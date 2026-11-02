import hashlib
import json

import pytest

from fakes import PIP_AUDIT_JSON, SARIF, Behaviour, FakeExecutor, fake_rules
from secaudit.core.scanners import (
    BanditAdapter,
    GitleaksAdapter,
    PipAuditAdapter,
    SemgrepAdapter,
    ToolPaths,
    build_adapters,
    run_adapter,
)
from secaudit.core.scanners.pip_audit import (
    STAGED_NAME,
    find_requirements_files,
    parse_requirements,
)

CONTAINER = ToolPaths(src="/src", out="/out", rules="/rules", sandboxed=True)
NATIVE = ToolPaths(src="C:/ws", out="C:/out", rules="C:/rules", sandboxed=False, sep="\\")


# ---------------------------------------------------------------- command builders


def test_bandit_command():
    cmd = BanditAdapter().build_command(CONTAINER)
    assert cmd == ["bandit", "-r", ".", "-f", "sarif", "-o", "/out/bandit.sarif", "--ignore-nosec"]


def test_semgrep_command_is_offline_and_scans_tests(tmp_path):
    adapter = SemgrepAdapter(fake_rules(tmp_path))
    cmd = adapter.build_command(CONTAINER)
    assert cmd[:2] == ["semgrep", "scan"]
    assert cmd.count("--config") == 2
    assert "/rules/p-python.yaml" in cmd and "/rules/p-flask.yaml" in cmd
    for flag in ("--metrics=off", "--disable-version-check", "--disable-nosem",
                 "--no-rewrite-rule-ids", "--sarif-output=/out/semgrep.sarif"):  # fmt: skip
        assert flag in cmd
    assert not any(a.startswith("p/") or a.startswith("http") for a in cmd), "no registry lookups"
    assert "--exclude" not in cmd and cmd[-1] == "."


def test_gitleaks_command_redacts_and_ignores_repo_config():
    cmd = GitleaksAdapter().build_command(CONTAINER)
    assert cmd[:3] == ["gitleaks", "dir", "."]
    assert "--redact" in cmd and "--ignore-gitleaks-allow" in cmd
    assert cmd[cmd.index("--config") + 1] == "/opt/gitleaks.toml"
    assert cmd[cmd.index("--gitleaks-ignore-path") + 1] == "/opt/no-ignore"
    assert "--log-opts" not in cmd and "git" not in cmd[1:3], "working tree only, no history"
    native = GitleaksAdapter().build_command(NATIVE)
    assert "--config" not in native and "--redact" in native


def test_pip_audit_command_never_resolves_dependencies():
    cmd = PipAuditAdapter().build_command(CONTAINER)
    assert "--no-deps" in cmd and "--disable-pip" in cmd
    assert cmd[cmd.index("-f") + 1] == "json"
    assert cmd[cmd.index("-r") + 1] == f"/src/{STAGED_NAME}"


def test_adapter_declarations():
    assert all(a.completed_exit_codes == frozenset({0, 1}) for a in build_adapters(
        ("bandit", "semgrep", "gitleaks", "pip-audit"), None))  # fmt: skip
    nets = {a.name: a.network_policy.value for a in build_adapters(
        ("bandit", "semgrep", "gitleaks", "pip-audit"), None)}  # fmt: skip
    assert nets == {"bandit": "none", "semgrep": "none", "gitleaks": "none", "pip-audit": "bridge"}
    assert BanditAdapter().image == "secaudit/bandit:1.9.4"
    with pytest.raises(ValueError):
        build_adapters(("nonsense",), None)


# ---------------------------------------------------------------- requirements parsing


def test_parse_requirements_pins_and_unresolved():
    text = "\n".join(
        [
            "# comment",
            "Flask==2.0.1  # inline comment",
            "requests[security]==2.19.0 ; python_version >= '3.8'",
            "pyyaml==5.3.1 \\",
            "    --hash=sha256:abc",
            "numpy>=1.20",
            "django~=4.2",
            "pandas",
            "pkg==1.*",
            "-r other.txt",
            "-c constraints.txt",
            "-e .",
            "--editable git+https://github.com/o/r.git#egg=x",
            "git+https://github.com/o/r.git",
            "mypkg @ https://example.com/mypkg.whl",
            "./local/path",
            "--index-url https://pypi.org/simple",
            "",
        ]
    )
    pinned, unresolved = parse_requirements({"requirements.txt": text})
    assert [(p["name"], p["version"], p["line"]) for p in pinned] == [
        ("Flask", "2.0.1", 2),
        ("requests", "2.19.0", 3),
        ("pyyaml", "5.3.1", 4),
    ]
    reasons = {u["requirement"].split()[0]: u["reason"] for u in unresolved}
    assert reasons["numpy>=1.20"] == "unpinned"
    assert reasons["django~=4.2"] == "unpinned"
    assert reasons["pandas"] == "unpinned"
    assert reasons["pkg==1.*"] == "unpinned"
    assert reasons["-r"] == "include_not_followed"
    assert reasons["-c"] == "include_not_followed"
    assert reasons["-e"] == "editable"
    assert reasons["git+https://github.com/o/r.git"] == "url_or_path"
    assert reasons["mypkg"] == "url_or_path"
    assert reasons["./local/path"] == "url_or_path"
    assert not any("index-url" in u["requirement"] for u in unresolved)


def test_find_requirements_files_skips_vendored_dirs(tmp_path):
    for rel in ("requirements.txt", "requirements-dev.txt", "sub/requirements.txt",
                ".venv/requirements.txt", "node_modules/x/requirements.txt", "notes.txt",
                "dev-requirements.txt", "requirements.in"):  # fmt: skip
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("flask==1.0\n")
    found = sorted(p.relative_to(tmp_path).as_posix() for p in find_requirements_files(tmp_path))
    assert found == ["dev-requirements.txt", "requirements-dev.txt", "requirements.txt",
                     "sub/requirements.txt"]  # fmt: skip


def test_pip_audit_prepare_stages_only_requirements_never_source(tmp_path):
    ws = tmp_path / "ws"
    (ws / "app").mkdir(parents=True)
    (ws / "app" / "secret_logic.py").write_text("PASSWORD = 'x'\n")
    (ws / "requirements.txt").write_text("flask==2.0.1\nrequests>=2\nflask==2.0.1\n")
    staging = tmp_path / "stage"
    staging.mkdir()
    prepared = PipAuditAdapter().prepare(ws, staging)
    assert prepared.src_dir == staging and prepared.src_dir != ws
    assert [p.name for p in staging.iterdir()] == [STAGED_NAME]
    assert (staging / STAGED_NAME).read_text() == "flask==2.0.1\n"  # deduplicated, pinned only
    assert prepared.extra["unresolved"][0]["reason"] == "unpinned"
    assert prepared.extra["pinned_requirements"][0] == {
        "name": "flask", "version": "2.0.1", "file": "requirements.txt", "line": 1,
    }  # fmt: skip


def test_pip_audit_without_pins_is_skipped(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "requirements.txt").write_text("flask>=2\n")
    staging = tmp_path / "stage"
    staging.mkdir()
    prepared = PipAuditAdapter().prepare(ws, staging)
    assert prepared.skip_reason and prepared.src_dir is None
    assert prepared.extra["unresolved"][0]["requirement"] == "flask>=2"


# ---------------------------------------------------------------- run_adapter outcomes


@pytest.fixture
def dirs(tmp_path):
    ws, work, raw = tmp_path / "ws", tmp_path / "work", tmp_path / "raw"
    ws.mkdir()
    work.mkdir()
    return ws, work, raw


def run(adapter, dirs, behaviour=None, label=None):
    ws, work, raw = dirs
    executor = FakeExecutor(behaviours={adapter.name: behaviour} if behaviour else {})
    result = run_adapter(
        adapter, ws, work_dir=work, raw_dir=raw, executor=executor, label=adapter.name
    )
    return result, executor, raw


def test_exit_code_1_with_valid_sarif_is_completed(dirs):
    result, _, raw = run(BanditAdapter(), dirs, Behaviour(exit_code=1, write=SARIF.encode()))
    assert result.status == "completed" and result.exit_code == 1
    assert result.raw_artifact_path == raw / "bandit.sarif"
    assert result.artifact_sha256 == hashlib.sha256(SARIF.encode()).hexdigest()
    assert result.version == "1.9.4" and result.command[0] == "bandit"


def test_exit_code_0_is_also_completed(dirs):
    assert (
        run(BanditAdapter(), dirs, Behaviour(exit_code=0, write=SARIF.encode()))[0].status
        == "completed"
    )


@pytest.mark.parametrize("code", [2, 3, 125, 126, 127, 137])
def test_unexpected_exit_codes_fail(dirs, code):
    result, _, raw = run(BanditAdapter(), dirs, Behaviour(exit_code=code, write=SARIF.encode()))
    assert result.status == "failed" and str(code) in result.detail
    assert result.raw_artifact_path is None and not raw.exists()
    assert "boom" in result.stderr_tail


def test_timeout_status(dirs):
    result, _, _ = run(BanditAdapter(), dirs, Behaviour(exit_code=None, timed_out=True))
    assert result.status == "timeout" and "killed" in result.detail


def test_output_flood_status(dirs):
    assert run(BanditAdapter(), dirs, Behaviour(exit_code=None, flood=True))[0].status == "failed"


def test_missing_result_file_fails_even_with_ok_exit(dirs):
    result, _, _ = run(BanditAdapter(), dirs, Behaviour(exit_code=1, write=None))
    assert result.status == "failed" and "no regular result file" in result.detail


@pytest.mark.parametrize(
    "payload", [b"", b"not json", b"[]", b'{"version": "2.1.0"}', b'{"runs": []}']
)
def test_malformed_sarif_fails(dirs, payload):
    result, _, raw = run(BanditAdapter(), dirs, Behaviour(exit_code=1, write=payload))
    assert result.status == "failed" and result.raw_artifact_path is None


def test_pip_audit_json_shape_validated(tmp_path):
    ws, work, raw = tmp_path / "ws", tmp_path / "work", tmp_path / "raw"
    ws.mkdir()
    work.mkdir()
    (ws / "requirements.txt").write_text("flask==2.0.1\n")
    ok = run_adapter(PipAuditAdapter(), ws, work_dir=work, raw_dir=raw,
                     executor=FakeExecutor(behaviours={"pip-audit": Behaviour(1, PIP_AUDIT_JSON.encode())}),
                     label="pip-audit")  # fmt: skip
    assert ok.status == "completed" and ok.extra["pinned_requirements"]
    work2 = tmp_path / "work2"
    work2.mkdir()
    bad = run_adapter(PipAuditAdapter(), ws, work_dir=work2, raw_dir=raw,
                      executor=FakeExecutor(behaviours={"pip-audit": Behaviour(1, b'{"x": 1}')}),
                      label="pip-audit")  # fmt: skip
    assert bad.status == "failed"


def test_artifact_must_be_a_regular_file(dirs):
    ws, work, raw = dirs

    class DirExecutor(FakeExecutor):
        def run(self, adapter, prepared, out_dir, command, label):
            if command != adapter.version_command():
                (out_dir / adapter.output_filename).mkdir()
            return super().run(adapter, prepared, out_dir, command, label)

    executor = DirExecutor(behaviours={"bandit": Behaviour(1, None)})
    result = run_adapter(
        BanditAdapter(), ws, work_dir=work, raw_dir=raw, executor=executor, label="bandit"
    )
    assert result.status == "failed" and "no regular result file" in result.detail


def test_version_mismatch_is_recorded_not_hidden(dirs):
    result, _, _ = run(
        BanditAdapter(), dirs, Behaviour(1, SARIF.encode(), reported_version="9.9.9")
    )
    assert result.status == "completed" and result.version == "9.9.9"
    assert "MISMATCH" in result.extra["version_check"]


def test_semgrep_without_rules_cache_is_unavailable(dirs):
    result, executor, _ = run(SemgrepAdapter(None), dirs)
    assert result.status == "failed" and result.detail.startswith("unavailable:")
    assert "rules update" in result.detail and executor.calls == []


def test_skipped_adapter_never_starts_a_container(dirs):
    ws, _, _ = dirs
    (ws / "requirements.txt").write_text("flask>=2\n")
    result, executor, _ = run(PipAuditAdapter(), dirs)
    assert result.status == "skipped" and executor.calls == []
    assert result.extra["unresolved"][0]["reason"] == "unpinned"


def test_executor_oserror_becomes_failed_status(dirs):
    result, _, _ = run(BanditAdapter(), dirs, Behaviour(raises=OSError("docker not found")))
    assert result.status == "failed" and "could not start tool" in result.detail


def test_raw_artifact_is_byte_identical_copy(dirs):
    payload = json.dumps({"version": "2.1.0", "runs": [{"results": [{"ruleId": "B1"}]}]}).encode()
    result, _, raw = run(BanditAdapter(), dirs, Behaviour(1, payload))
    assert (raw / "bandit.sarif").read_bytes() == payload
