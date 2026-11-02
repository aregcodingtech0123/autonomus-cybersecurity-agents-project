import json
from pathlib import Path

import pytest

from fakes import fake_rules
from secaudit import cli
from secaudit.core import scan as scan_mod
from secaudit.core.rules import MANIFEST_NAME, RulesError, load_rules_cache
from secaudit.core.scan import ScanOptions, ScanOutcome
from secaudit.core.scanners import RawScanResult

# ---------------------------------------------------------------- CLI


def run_cli(*argv):
    return cli.main(list(argv))


def fake_outcome(statuses: dict[str, str], tmp_path: Path) -> ScanOutcome:
    results = [
        RawScanResult(
            tool=t,
            version="1",
            pinned_version="1",
            command=(t,),
            exit_code=1,
            raw_artifact_path=None,
            duration_s=0.1,
            status=s,
        )  # fmt: skip
        for t, s in statuses.items()
    ]
    manifest = {
        "audit_id": "X", "tool_order": list(statuses),
        "tools": {t: {"status": s, "exit_code": 1, "duration_s": 0.1, "detail": ""} for t, s in statuses.items()},
    }  # fmt: skip
    return ScanOutcome(tmp_path, manifest, results)


def test_native_runner_refuses_without_trust_flag(monkeypatch, capsys, tmp_path):
    called = []
    monkeypatch.setattr(cli, "run_scan", lambda *a, **k: called.append(1))
    code = run_cli("scan", str(tmp_path), "--runner", "native")
    assert code == cli.EXIT_USAGE and not called
    assert "--i-trust-this-code" in capsys.readouterr().err


def test_native_runner_with_flag_warns_and_runs(monkeypatch, capsys, tmp_path):
    seen = {}

    def fake_run(source, options):
        seen["runner"] = options.runner
        return fake_outcome({"bandit": "completed"}, tmp_path)

    monkeypatch.setattr(cli, "run_scan", fake_run)
    code = run_cli("scan", str(tmp_path), "--runner", "native", "--i-trust-this-code")
    assert code == cli.EXIT_OK and seen["runner"] == "native"
    assert "NO sandbox" in capsys.readouterr().err


def test_exit_code_zero_when_scan_completes(monkeypatch, tmp_path):
    monkeypatch.setattr(
        cli,
        "run_scan",
        lambda s, o: fake_outcome({"bandit": "completed", "pip-audit": "skipped"}, tmp_path),
    )
    assert run_cli("scan", str(tmp_path)) == cli.EXIT_OK


@pytest.mark.parametrize("bad", ["failed", "timeout"])
def test_exit_code_nonzero_on_tool_failure(monkeypatch, tmp_path, bad):
    monkeypatch.setattr(
        cli,
        "run_scan",
        lambda s, o: fake_outcome({"bandit": "completed", "semgrep": bad}, tmp_path),
    )
    assert run_cli("scan", str(tmp_path)) == cli.EXIT_TOOLS


def test_exit_code_for_intake_rejection(tmp_path, capsys):
    bad = tmp_path / "bad.zip"
    bad.write_bytes(b"nope")
    # tools=bandit + monkeypatched preflight keeps this independent of Docker
    code = _with_no_preflight(
        lambda: run_cli("scan", str(bad), "--tools", "bandit", "--out", str(tmp_path / "o"))
    )
    assert code == cli.EXIT_INTAKE
    assert "invalid_archive" in capsys.readouterr().err


def test_exit_code_when_docker_is_down(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        scan_mod, "docker_available", lambda docker="docker": (False, "daemon not running")
    )
    code = run_cli("scan", str(tmp_path), "--tools", "bandit", "--out", str(tmp_path / "o"))
    assert code == cli.EXIT_ENV
    err = capsys.readouterr().err
    assert "Start Docker Desktop" in err and "daemon not running" in err


def test_exit_code_when_images_missing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(scan_mod, "docker_available", lambda docker="docker": (True, "29"))
    monkeypatch.setattr(scan_mod, "image_exists", lambda image, docker="docker": False)
    code = run_cli("scan", str(tmp_path), "--tools", "bandit", "--out", str(tmp_path / "o"))
    assert code == cli.EXIT_ENV and "build-images" in capsys.readouterr().err


def test_invalid_tool_name_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        run_cli("scan", ".", "--tools", "bandit,nonsense")
    assert exc.value.code == 2


def test_allow_git_host_extends_the_allowlist(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(
        cli,
        "run_scan",
        lambda s, o: seen.setdefault("o", o) and fake_outcome({"bandit": "completed"}, tmp_path),
    )
    run_cli("scan", "https://git.example.org/a/b", "--allow-git-host", "git.example.org")
    assert "git.example.org" in seen["o"].limits.git_allowed_hosts
    assert "github.com" in seen["o"].limits.git_allowed_hosts


def _with_no_preflight(fn):
    original = scan_mod.preflight
    scan_mod.preflight = lambda options, adapters: None
    try:
        return fn()
    finally:
        scan_mod.preflight = original


# ---------------------------------------------------------------- rules cache


def write_snapshot(cache: Path, fetch_id="20260101T000000Z", files=None, tamper=False):
    import hashlib

    base = cache / "semgrep"
    snap = base / fetch_id
    snap.mkdir(parents=True)
    files = files or {"p-python.yaml": b"rules: []\n"}
    entries = []
    for name, body in files.items():
        (snap / name).write_bytes(body)
        entries.append({"ruleset": "p/python", "url": "u", "file": name,
                        "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)})  # fmt: skip
    (snap / MANIFEST_NAME).write_text(json.dumps({"fetched_at": "t", "rulesets": entries}))
    (base / "CURRENT").write_text(fetch_id + "\n")
    if tamper:
        (snap / next(iter(files))).write_bytes(b"rules: [evil]\n")
    return snap


def test_rules_cache_loads_and_describes(tmp_path):
    write_snapshot(tmp_path)
    cache = load_rules_cache(tmp_path)
    assert cache.fetch_id == "20260101T000000Z" and cache.files == ("p-python.yaml",)
    assert cache.describe()["rulesets"][0]["name"] == "p/python"


def test_rules_cache_missing_is_a_clear_error(tmp_path):
    with pytest.raises(RulesError, match="rules update"):
        load_rules_cache(tmp_path)


def test_rules_cache_detects_tampering(tmp_path):
    write_snapshot(tmp_path, tamper=True)
    with pytest.raises(RulesError, match="integrity"):
        load_rules_cache(tmp_path)


@pytest.mark.parametrize("name", ["../evil.yaml", "p-x.yml", "evil.yaml", "p-/x.yaml"])
def test_rules_manifest_with_unsafe_file_names_rejected(tmp_path, name):
    snap = write_snapshot(tmp_path)
    manifest = json.loads((snap / MANIFEST_NAME).read_text())
    manifest["rulesets"][0]["file"] = name
    (snap / MANIFEST_NAME).write_text(json.dumps(manifest))
    with pytest.raises(RulesError):
        load_rules_cache(tmp_path)


def test_rules_current_pointer_must_be_well_formed(tmp_path):
    write_snapshot(tmp_path)
    (tmp_path / "semgrep" / "CURRENT").write_text("../../etc\n")
    with pytest.raises(RulesError, match="malformed"):
        load_rules_cache(tmp_path)


def test_fake_rules_helper_is_consistent(tmp_path):
    assert fake_rules(tmp_path).files == ("p-python.yaml", "p-flask.yaml")
    assert ScanOptions(out_root=tmp_path).tools


def test_version_flag_still_works(capsys):
    with pytest.raises(SystemExit) as exc:
        run_cli("--version")
    assert exc.value.code == 0 and capsys.readouterr().out.startswith("secaudit ")
