"""Real-container tests (marker `docker`). Needs Docker running and `secaudit build-images`.

Never skipped silently: see tests/conftest.py (explicit skip reason + loud summary banner).
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
import yaml

from hits import overlaps, tool_hits
from secaudit import cli
from secaudit.core.executors import list_managed_containers
from secaudit.core.rules import RulesError, load_rules_cache
from secaudit.core.sandbox import (
    ContainerSpec,
    Mount,
    NetworkPolicy,
    ResourceLimits,
    build_docker_command,
    container_user,
    kill_container,
    run_container,
)
from secaudit.core.scan import ScanOptions, run_scan
from secaudit.core.scanners import TOOL_NAMES

pytestmark = [pytest.mark.docker, pytest.mark.usefixtures("docker_images")]

REPO = Path(__file__).resolve().parent.parent
TARGET = REPO / "benchmarks" / "targets" / "vuln_python_app"
BASELINE_MANIFEST = REPO / "benchmarks" / "baseline" / "manifest.json"
PROBE_IMAGE = "secaudit/bandit:1.9.4"  # any pinned image with python works as a probe container

PROBE = r"""
import json, os, socket
r = {}
def attempt(label, fn):
    try:
        fn(); r[label] = "ok"
    except Exception as e:
        r[label] = type(e).__name__ + ":" + str(getattr(e, "errno", ""))
def write(path):
    def f():
        with open(path, "w") as h: h.write("x")
    return f
for label, path in (("src", "/src/x"), ("etc", "/etc/x"), ("root", "/x"), ("usr", "/usr/x"),
                    ("tmp", "/tmp/x"), ("out", "/out/x")):
    attempt("write_" + label, write(path))
def net():
    s = socket.socket(); s.settimeout(3); s.connect(("1.1.1.1", 443))
attempt("network", net)
attempt("dns", lambda: socket.gethostbyname("example.com"))
r["uid"], r["gid"] = os.getuid(), os.getgid()
status = dict(l.split(":\t", 1) for l in open("/proc/self/status").read().splitlines() if ":\t" in l)
r["NoNewPrivs"], r["CapEff"], r["CapBnd"] = (status.get(k, "").strip() for k in ("NoNewPrivs", "CapEff", "CapBnd"))
r["docker_sock"] = os.path.exists("/var/run/docker.sock")
r["host_secret_visible"] = "SECAUDIT_TEST_HOST_SECRET" in os.environ
mounts = open("/proc/mounts").read().splitlines()
r["tmp_mount"] = next((m for m in mounts if m.split()[1] == "/tmp"), "")
r["rootfs_mount"] = next((m for m in mounts if m.split()[1] == "/"), "")
print(json.dumps(r))
"""


@pytest.fixture
def spec_factory(tmp_path):
    src, out = tmp_path / "src", tmp_path / "out"
    src.mkdir()
    out.mkdir()

    def make(command, *, network=NetworkPolicy.NONE, limits=None, label="t"):
        return ContainerSpec(
            image=PROBE_IMAGE,
            command=tuple(command),
            output_dir=out,
            inputs=(Mount(src, "/src"),),
            network=network,
            env={"HOME": "/tmp"},
            limits=limits or ResourceLimits(timeout_s=60),
            workdir="/src",
        ).with_name(f"test-{label}")

    make.out = out
    return make


def wait_gone(name_part: str, seconds: float = 15.0) -> list[str]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        left = list_managed_containers(name_part)
        if not left:
            return []
        time.sleep(0.5)
    return list_managed_containers(name_part)


# --------------------------------------------------------------------------- sandbox properties


def test_sandbox_properties_in_a_real_container(spec_factory, monkeypatch):
    monkeypatch.setenv("SECAUDIT_TEST_HOST_SECRET", "must-not-leak")
    result = run_container(spec_factory(["python", "-c", PROBE], label="props"))
    assert result.exit_code == 0, result.stderr
    p = json.loads(result.stdout)
    assert p["network"].startswith("OSError"), "network must be unreachable"
    assert p["dns"].startswith("gaierror"), "DNS must not resolve"
    assert p["write_src"].startswith("OSError"), "/src is read-only"
    for forbidden in ("write_etc", "write_root", "write_usr"):
        assert p[forbidden].startswith("OSError"), f"{forbidden}: root filesystem must be read-only"
    assert p["write_tmp"] == "ok" and p["write_out"] == "ok"
    assert (spec_factory.out / "x").exists(), "the /out mount is the writable result channel"
    expected_uid, expected_gid = (int(x) for x in container_user().split(":"))
    assert expected_uid != 0, "the expected user is never root"
    assert (p["uid"], p["gid"]) == (expected_uid, expected_gid), (
        "must run as the selected non-root user"
    )
    assert p["NoNewPrivs"] == "1"
    assert int(p["CapEff"], 16) == 0 and int(p["CapBnd"], 16) == 0, "all capabilities dropped"
    assert p["docker_sock"] is False
    assert p["host_secret_visible"] is False, "host environment must not leak into the container"
    assert "noexec" in p["tmp_mount"] and "nosuid" in p["tmp_mount"]
    assert p["rootfs_mount"].split()[3].split(",")[0] == "ro"


def test_docker_inspect_matches_expected_hostconfig(spec_factory):
    spec = spec_factory(["python", "-c", "import time; time.sleep(120)"], label="inspect")
    argv = build_docker_command(spec)
    proc = subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )  # noqa: S603
    try:
        info = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and info is None:
            done = subprocess.run(
                ["docker", "inspect", spec.name], capture_output=True, text=True, check=False
            )  # noqa: S603
            if done.returncode == 0:
                info = json.loads(done.stdout)[0]
            else:
                time.sleep(0.3)
        assert info is not None, "container never appeared"
        host, cfg = info["HostConfig"], info["Config"]
        assert host["NetworkMode"] == "none"
        assert host["ReadonlyRootfs"] is True
        assert host["CapDrop"] == ["ALL"] and not host.get("CapAdd")
        assert any(o.startswith("no-new-privileges") for o in host["SecurityOpt"])
        assert not any("unconfined" in o for o in host["SecurityOpt"])
        assert host["Privileged"] is False
        assert host["PidsLimit"] == 256
        assert host["Memory"] == 1024**3 and host["MemorySwap"] == 1024**3
        assert host["NanoCpus"] == 2_000_000_000
        assert host["AutoRemove"] is True
        assert host["PidMode"] == "" and host["UsernsMode"] == ""
        assert host["IpcMode"] != "host" and not host.get("Devices")
        assert "/tmp" in host["Tmpfs"] and "noexec" in host["Tmpfs"]["/tmp"]
        assert not host.get("Binds"), "only explicit --mount entries, no -v binds"
        mounts = {m["Destination"]: m for m in info["Mounts"]}
        assert set(mounts) == {"/src", "/out"}
        assert mounts["/src"]["RW"] is False and mounts["/out"]["RW"] is True
        assert not any("docker.sock" in m["Source"] for m in info["Mounts"])
        assert cfg["User"] == container_user()
        assert cfg["Labels"]["org.secaudit.managed"] == "true"
        assert [e for e in cfg["Env"] if e.startswith("HOME=")] == ["HOME=/tmp"]
    finally:
        kill_container(spec.name)
        proc.kill()
        proc.wait(timeout=30)
    assert wait_gone(spec.name) == []


def test_timeout_really_kills_the_container(spec_factory):
    limits = ResourceLimits(timeout_s=3)
    spec = spec_factory(
        ["python", "-c", "import time; time.sleep(300)"], limits=limits, label="timeout"
    )
    started = time.monotonic()
    result = run_container(spec)
    assert result.timed_out and result.exit_code is None
    assert time.monotonic() - started < 40
    assert wait_gone(spec.name) == [], "container must not keep running after the timeout"


def test_output_flood_kills_the_container(spec_factory):
    limits = ResourceLimits(timeout_s=120, max_stream_bytes=300_000)
    spec = spec_factory(
        ["python", "-c", "import sys\nwhile True: sys.stdout.write('x'*65536); sys.stdout.flush()"],
        limits=limits, label="flood",
    )  # fmt: skip
    result = run_container(spec)
    assert result.output_limit_exceeded and len(result.stdout) <= limits.max_capture_bytes
    assert wait_gone(spec.name) == []


def test_pip_audit_container_never_sees_source(tmp_path):
    from secaudit.core.scanners import PipAuditAdapter

    ws, stage, out = tmp_path / "ws", tmp_path / "stage", tmp_path / "out"
    for d in (ws, stage, out):
        d.mkdir()
    (ws / "secret_source.py").write_text("PASSWORD = 'hunter2'\n")
    (ws / "requirements.txt").write_text("flask==2.0.1\n")
    prepared = PipAuditAdapter().prepare(ws, stage)
    spec = ContainerSpec(
        image=PipAuditAdapter().image,
        command=("python", "-c", "import os; print(sorted(os.listdir('/src')))"),
        output_dir=out,
        inputs=(Mount(prepared.src_dir, "/src"),),
        network=NetworkPolicy.EGRESS_ONLY,
        env={"HOME": "/tmp"},
    ).with_name("nosource")
    result = run_container(spec)
    assert result.stdout.strip() == "['requirements.audit.txt']"


# --------------------------------------------------------------------------- full scan + parity


@pytest.fixture(scope="module")
def rules_cache():
    try:
        return load_rules_cache()
    except RulesError as exc:
        pytest.fail(f"{exc}")


@pytest.fixture(scope="module")
def scan_outcome(tmp_path_factory, rules_cache):
    before = set(Path(tempfile.gettempdir()).glob("secaudit-*"))
    options = ScanOptions(
        out_root=tmp_path_factory.mktemp("audits"), resource_limits=ResourceLimits(timeout_s=300)
    )
    outcome = run_scan(str(TARGET), options, rules=rules_cache)
    outcome.leftover_temp = set(Path(tempfile.gettempdir()).glob("secaudit-*")) - before
    return outcome


def test_full_scan_via_docker_produces_four_raw_outputs(scan_outcome):
    audit, manifest = scan_outcome.audit_dir, scan_outcome.manifest
    assert scan_outcome.tools_ok, {
        t: (v["status"], v["detail"]) for t, v in manifest["tools"].items()
    }
    assert manifest["runner"] == "docker" and manifest["summary"]["completed"] == 4
    assert sorted(p.name for p in (audit / "raw").iterdir()) == [
        "bandit.sarif", "gitleaks.sarif", "pip-audit.json", "semgrep.json", "semgrep.sarif",
    ]  # fmt: skip
    for tool in TOOL_NAMES:
        entry = manifest["tools"][tool]
        assert entry["version"] == entry["pinned_version"], (
            f"{tool}: running version differs from pin"
        )
        assert entry["exit_code"] in (0, 1)
        assert "--network" in entry["sandbox_command"]
    assert manifest["tools"]["pip-audit"]["network"] == "bridge"
    assert all(manifest["tools"][t]["network"] == "none" for t in ("bandit", "semgrep", "gitleaks"))


def test_workspace_and_containers_are_cleaned_up(scan_outcome):
    short = scan_outcome.manifest["audit_id"].rsplit("-", 1)[1]
    assert list_managed_containers(f"secaudit-{short}") == [], "containers left behind"
    assert scan_outcome.leftover_temp == set(), (
        f"temp dirs left behind: {scan_outcome.leftover_temp}"
    )


SECRET_LITERALS = (
    "bench_n0" "VQRgmEuLNsKJ4a0ZkKpFxr11",
    "not-a-real-password-benchmark-fake",
    "placeholder-not-a-real-password",
    "benc" "h_uoSN55OKIJ9XKt",
    "bench_BvXX7C2JUsDNWW" "hy5PUSWscCmH1w2oxhud",
)
# Raw files that are DOCUMENTED to be secret-bearing (SECURITY_POLICY.md): Bandit embeds the
# source line verbatim. Everything else, and every derived artifact, must be free of the literals.
SECRET_BEARING_RAW = {"bandit.sarif", "semgrep.sarif"}


def test_secret_literals_appear_only_in_documented_raw_files(scan_outcome):
    audit = scan_outcome.audit_dir
    found = {
        p.name: {s for s in SECRET_LITERALS if s in p.read_text(encoding="utf-8")}
        for p in sorted((audit / "raw").iterdir())
    }
    leaking = {name for name, hits in found.items() if hits}
    assert leaking <= SECRET_BEARING_RAW, (
        f"undocumented secret-bearing outputs: {leaking - SECRET_BEARING_RAW}"
    )
    assert found["gitleaks.sarif"] == set() and "REDACTED" in (
        audit / "raw" / "gitleaks.sarif"
    ).read_text(encoding="utf-8")
    assert found["pip-audit.json"] == set()
    # The documented truth, pinned so a change in Bandit's behaviour is noticed:
    assert "not-a-real-password-benchmark-fake" in found["bandit.sarif"]
    manifest_text = (audit / "manifest.json").read_text(encoding="utf-8")
    assert not [s for s in SECRET_LITERALS if s in manifest_text], (
        "the manifest must be secret-free"
    )


def test_raw_files_are_byte_identical_to_what_the_manifest_hashes(scan_outcome):
    import hashlib

    for tool, entry in scan_outcome.manifest["tools"].items():
        data = (scan_outcome.audit_dir / entry["artifact"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["artifact_sha256"], tool


def test_semgrep_scanned_the_tests_directory(scan_outcome):
    manifest = scan_outcome.manifest
    assert manifest["tools"]["semgrep"]["ruleset_info"]["rulesets"], "rule snapshot recorded"
    assert manifest["workspace_policy_files"] == [".semgrepignore"]


def _parity(scan_outcome):
    truth = yaml.safe_load(
        (REPO / "benchmarks" / "expected_findings.yaml").read_text(encoding="utf-8")
    )
    requirements = (TARGET / "requirements.txt").read_text(encoding="utf-8")
    raw = scan_outcome.audit_dir / "raw"
    hits = {tool: tool_hits(tool, raw, requirements) for tool in TOOL_NAMES}
    return truth["cases"], hits


def test_parity_expected_detections_are_present_in_container_output(scan_outcome):
    """Every tool listed in expected_detecting_tools must hit the case's file and line range."""
    cases, hits = _parity(scan_outcome)
    missing = []
    for case in cases:
        if case["kind"] != "positive":
            continue
        for tool in case.get("expected_detecting_tools") or []:
            if not overlaps(hits[tool], case["file"], case["line_start"], case["line_end"]):
                missing.append((case["id"], tool))
    assert missing == [], f"container run lost detections the baseline expects: {missing}"


def _baseline_rules_match(scan_outcome) -> bool:
    if not BASELINE_MANIFEST.is_file():
        return False
    baseline = json.loads(BASELINE_MANIFEST.read_text(encoding="utf-8"))

    def pick(manifest):
        rulesets = manifest["tools"]["semgrep"]["ruleset_info"]["rulesets"]
        return sorted((r["name"], r["sha256"]) for r in rulesets)

    return pick(baseline) == pick(scan_outcome.manifest)


def test_parity_exact_match_with_recorded_baseline(scan_outcome):
    """Strict both ways (detections AND false alarms) when run against the baseline rule snapshot."""
    if not _baseline_rules_match(scan_outcome):
        pytest.skip(
            "local Semgrep rules snapshot differs from benchmarks/baseline/manifest.json; "
            "the lenient detection check above still ran. Re-baseline to compare exactly."
        )
    cases, hits = _parity(scan_outcome)
    wrong = []
    for case in cases:
        if case["kind"] == "injection_bait":
            expected = set()
        elif case["kind"] == "positive":
            expected = set(case.get("expected_detecting_tools") or [])
        else:
            expected = set(case.get("observed_false_alarms") or [])
        actual = {
            t
            for t in TOOL_NAMES
            if overlaps(hits[t], case["file"], case["line_start"], case["line_end"])
        }
        if actual != expected:
            wrong.append((case["id"], sorted(expected), sorted(actual)))
    assert wrong == [], f"(case, expected tools, actual tools) differ: {wrong}"


def test_cli_scan_end_to_end_exit_code_and_layout(tmp_path, rules_cache, capsys):
    code = cli.main(
        ["scan", str(TARGET), "--out", str(tmp_path / "o"), "--tools", "bandit,gitleaks"]
    )
    assert code == cli.EXIT_OK
    audit = next((tmp_path / "o").iterdir())
    manifest = json.loads((audit / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["tool_order"] == ["bandit", "gitleaks"]
    assert os.path.isfile(audit / "raw" / "bandit.sarif")
    captured = capsys.readouterr()
    assert "bandit" in captured.out
    assert not [s for s in SECRET_LITERALS if s in captured.out + captured.err], (
        "CLI summary leaks a secret"
    )


def test_zip_input_round_trips_through_the_sandbox(tmp_path, rules_cache):
    import shutil

    small = tmp_path / "target_without_generated"
    shutil.copytree(TARGET, small, ignore=shutil.ignore_patterns("generated_big_module.py"))
    archive = shutil.make_archive(str(tmp_path / "target"), "zip", small)
    options = ScanOptions(out_root=tmp_path / "audits", tools=("bandit", "gitleaks"))
    outcome = run_scan(archive, options, rules=rules_cache)
    manifest = outcome.manifest
    assert outcome.tools_ok and manifest["input"]["kind"] == "zip"
    assert manifest["input"]["sha256"] == hashlib.sha256(Path(archive).read_bytes()).hexdigest()
    assert manifest["input"]["file_count"] == 15, "every file of the benchmark target arrived"
    sarif = json.loads(
        (outcome.audit_dir / manifest["tools"]["bandit"]["artifact"]).read_text(encoding="utf-8")
    )
    analysed = {
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in sarif["runs"][0]["results"]
    }
    assert "webshop/db.py" in analysed, "the sandboxed Bandit analysed the extracted code"
