"""Review #9 (egress residual risk, honest tests) and #10 (declared Gitleaks allowlist gap)."""

from __future__ import annotations

import json
import textwrap

import pytest

from fakes import FakeExecutor, fake_rules
from secaudit.core import exe
from secaudit.core.sandbox import (
    ContainerSpec,
    Mount,
    NetworkPolicy,
    ResourceLimits,
    run_container,
)
from secaudit.core.scan import ScanOptions, run_scan

# ---------------------------------------------------------------- #10 limitations in the manifest


def test_manifest_declares_per_tool_limitations(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")
    (project / "requirements.txt").write_text("flask==2.0.1\n")
    outcome = run_scan(
        str(project),
        ScanOptions(out_root=tmp_path / "audits"),
        executor=FakeExecutor(),
        rules=fake_rules(tmp_path),
    )
    manifest = json.loads((outcome.audit_dir / "manifest.json").read_text(encoding="utf-8"))
    tools = manifest["tools"]
    for name in ("bandit", "semgrep", "gitleaks", "pip-audit"):
        assert tools[name]["limitations"], (
            f"{name}: limitations must be declared for Phase 2's coverage model"
        )
    gl = " ".join(tools["gitleaks"]["limitations"]).lower()
    assert (
        "allowlist" in gl and "node_modules" in gl and "lock" in gl and "svg" in gl and "pdf" in gl
    )
    assert "binary" in gl and "history" in gl
    assert "1,000,000" in " ".join(tools["semgrep"]["limitations"])
    assert "parse" in " ".join(tools["bandit"]["limitations"]).lower()
    assert "pinned" in " ".join(tools["pip-audit"]["limitations"]).lower()


def test_limitations_are_also_present_for_skipped_and_failed_tools(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "app.py").write_text("x = 1\n")  # no requirements: pip-audit is skipped
    outcome = run_scan(
        str(project),
        ScanOptions(out_root=tmp_path / "audits", tools=("pip-audit",)),
        executor=FakeExecutor(),
    )
    entry = outcome.manifest["tools"]["pip-audit"]
    assert entry["status"] == "skipped" and entry["limitations"]


# ---------------------------------------------------------------- #9 egress: what is and is not proven

PROBE = textwrap.dedent(
    """
    import json, socket
    out = {}
    def connect(host, port):
        s = socket.socket(); s.settimeout(4)
        try:
            s.connect((host, port)); return "open"
        except ConnectionRefusedError: return "refused"      # something answered: the address is routed
        except socket.timeout: return "timeout"
        except OSError as e: return f"error:{e.errno}"
        finally: s.close()
    out["internet"] = connect("pypi.org", 443)
    try: out["host_ip"] = socket.gethostbyname("host.docker.internal")
    except OSError: out["host_ip"] = None
    out["host_2375"] = connect(out["host_ip"], 2375) if out["host_ip"] else "no-name"
    out["metadata_80"] = connect("169.254.169.254", 80)
    print(json.dumps(out))
    """
)


def _probe(tmp_path, network, label):
    src, out = tmp_path / "s", tmp_path / "o"
    src.mkdir(exist_ok=True)
    out.mkdir(exist_ok=True)
    spec = ContainerSpec(
        image="secaudit/pip-audit:2.10.1",
        command=("python", "-c", PROBE),
        output_dir=out,
        inputs=(Mount(src, "/src"),),
        network=network,
        env={"HOME": "/tmp"},
        limits=ResourceLimits(timeout_s=60),
        workdir="/src",
    ).with_name(label)
    result = run_container(spec)
    assert result.exit_code == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def _is_docker_desktop() -> bool:
    done = exe.run(
        ["docker", "info", "--format", "{{.OperatingSystem}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return "docker desktop" in done.stdout.lower()


@pytest.mark.docker
@pytest.mark.usefixtures("docker_images")
def test_internet_is_reachable_only_for_adapters_that_declare_egress(tmp_path):
    """Proves ONLY this: egress-only reaches the internet, the default policy reaches nothing.
    It does NOT prove the egress network is isolated from the Docker host (see the next test)."""
    blocked = _probe(tmp_path, NetworkPolicy.NONE, "net-none")
    allowed = _probe(tmp_path, NetworkPolicy.EGRESS_ONLY, "net-egress")
    assert blocked["internet"].startswith("error") or blocked["internet"] == "timeout"
    assert allowed["internet"] == "open"


@pytest.mark.docker
@pytest.mark.usefixtures("docker_images")
def test_KNOWN_RESIDUAL_RISK_egress_network_can_reach_the_docker_host_side(tmp_path):
    """Review #9, documented rather than fixed. With the egress-only policy the container can still
    reach the Docker Desktop host-side addresses and the link-local metadata address. Experiments
    (docs/PHASE1_NOTES.md) showed --add-host, --dns and user-defined networks do NOT change this.
    When Phase 8 adds an egress allow-list proxy / private-range blocking, FLIP these assertions."""
    if not _is_docker_desktop():
        pytest.skip("residual-risk measurement is specific to Docker Desktop's host-side addresses")
    none = _probe(tmp_path, NetworkPolicy.NONE, "res-none")
    egress = _probe(tmp_path, NetworkPolicy.EGRESS_ONLY, "res-egress")
    assert none["host_2375"] in {"no-name"} or none["host_2375"].startswith("error")
    assert egress["host_2375"] in {"refused", "open"}, "host side is reachable (residual risk)"
    assert egress["metadata_80"] in {"refused", "open"}, (
        "link-local address is reachable (residual risk)"
    )
