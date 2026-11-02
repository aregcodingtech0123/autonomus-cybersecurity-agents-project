"""Shared fixtures and the Docker/network test gating.

Docker-marked tests are NEVER skipped silently: when the daemon is unreachable they are skipped
with an explicit reason AND a loud banner is printed in the pytest summary.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from secaudit.core.sandbox import docker_available

_docker_state: dict = {}


def _docker_status() -> tuple[bool, str]:
    if "status" not in _docker_state:
        _docker_state["status"] = docker_available()
    return _docker_state["status"]


def pytest_configure(config):
    config.addinivalue_line("markers", "docker: needs a reachable Docker daemon and built images")
    config.addinivalue_line(
        "markers", "network: needs outbound internet (set SECAUDIT_NETWORK_TESTS=1)"
    )


def pytest_collection_modifyitems(config, items):
    docker_items = [i for i in items if "docker" in i.keywords]
    if docker_items:
        ok, detail = _docker_status()
        if not ok:
            _docker_state["skipped"] = len(docker_items)
            reason = f"Docker daemon not reachable ({detail}); start Docker Desktop and rerun"
            for item in docker_items:
                item.add_marker(pytest.mark.skip(reason=reason))
    if os.environ.get("SECAUDIT_NETWORK_TESTS") != "1":
        reason = "network tests are opt-in: set SECAUDIT_NETWORK_TESTS=1"
        for item in items:
            if "network" in item.keywords:
                item.add_marker(pytest.mark.skip(reason=reason))


def pytest_terminal_summary(terminalreporter):
    if _docker_state.get("skipped"):
        terminalreporter.section("DOCKER TESTS DID NOT RUN", sep="!", red=True, bold=True)
        terminalreporter.write_line(
            f"{_docker_state['skipped']} docker-marked test(s) were skipped because the Docker "
            "daemon is unreachable. Start Docker Desktop, run `secaudit build-images`, rerun pytest."
        )


@pytest.fixture(scope="session")
def docker_images():
    """Fail loudly (not skip) if the scanner images have not been built."""
    from secaudit.core.executors import image_exists
    from secaudit.core.scanners import TOOL_NAMES, build_adapters

    missing = [a.image for a in build_adapters(TOOL_NAMES, None) if not image_exists(a.image)]
    if missing:
        pytest.fail(f"scanner images missing: {missing}. Run `secaudit build-images` first.")
    return True


# ---------------------------------------------------------------------------- helpers


def build_zip(path: Path, entries: list[dict], *, compress: bool = True) -> Path:
    """Write a ZIP with full control over raw entry names and attributes.

    Each entry: {name, data=b"", mode=None}. `name` is written verbatim (zipfile would
    otherwise normalize backslashes on Windows), `mode` sets a Unix st_mode (e.g. a symlink).
    """
    with zipfile.ZipFile(path, "w") as zf:
        for entry in entries:
            info = zipfile.ZipInfo("placeholder")
            info.filename = entry["name"]
            if entry.get("mode") is not None:
                info.create_system = 3
                info.external_attr = entry["mode"] << 16
            zf.writestr(
                info,
                entry.get("data", b""),
                compress_type=zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED,
            )
    return path


@pytest.fixture
def zip_factory(tmp_path):
    counter = {"n": 0}

    def make(entries: list[dict], *, compress: bool = True) -> Path:
        counter["n"] += 1
        return build_zip(tmp_path / f"in{counter['n']}.zip", entries, compress=compress)

    return make


@pytest.fixture
def ws_parent(tmp_path):
    """Parent directory for workspaces; tests assert nothing is left behind in it."""
    parent = tmp_path / "ws"
    parent.mkdir()
    return parent
