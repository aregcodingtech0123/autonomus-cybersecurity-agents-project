"""docker/semgrep/fetch_rules.py: the registry download, run inside the Semgrep image with network.

First CI run: `p/security-audit` once came back as something other than a rules file ("response
does not look like a Semgrep rules file") and the identical re-run passed. A transient bad response
must be retried a bounded number of times, a deterministic failure must stay a failure, and the
final message must say what the server actually returned. Content validation is unchanged: nothing
that does not start with `rules:` is ever written.
"""

from __future__ import annotations

import importlib.util
import urllib.error
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "docker" / "semgrep" / "fetch_rules.py"
GOOD = b"rules:\n- id: demo.rule\n  message: demo\n"
HTML = b"<!DOCTYPE html><html><body>Just a moment...</body></html>"


@pytest.fixture
def fetch_rules(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("fetch_rules_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(module, "OUT_DIR", out)
    sleeps: list[float] = []
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    module.sleeps = sleeps
    module.out = out
    return module


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, content_type: str = "text/yaml"):
        self._body = body
        self.status = status
        self.headers = {"content-type": content_type}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]


def serve(monkeypatch, module, *steps):
    """Each step is a FakeResponse or an exception to raise; returns the list of requested URLs."""
    queue = list(steps)
    seen: list[str] = []

    def fake_urlopen(request, timeout=None):
        seen.append(request.full_url)
        step = queue.pop(0)
        if isinstance(step, Exception):
            raise step
        return step

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    return seen


def test_a_transient_bad_response_is_retried_and_then_accepted(fetch_rules, monkeypatch):
    seen = serve(
        monkeypatch,
        fetch_rules,
        FakeResponse(HTML, content_type="text/html"),
        FakeResponse(GOOD),
    )
    entry = fetch_rules.fetch("p/security-audit")
    assert len(seen) == 2 and len(fetch_rules.sleeps) == 1, "one retry, after a pause"
    assert (fetch_rules.out / "p-security-audit.yaml").read_bytes() == GOOD
    assert entry["bytes"] == len(GOOD)


def test_a_persistent_bad_response_fails_after_a_bounded_number_of_attempts(
    fetch_rules, monkeypatch
):
    seen = serve(monkeypatch, fetch_rules, *[FakeResponse(HTML, content_type="text/html")] * 5)
    with pytest.raises(SystemExit) as exc:
        fetch_rules.fetch("p/security-audit")
    message = str(exc.value)
    assert len(seen) == 3, "three attempts, not an endless loop"
    assert "does not look like a Semgrep rules file" in message
    assert "3 attempts" in message and "text/html" in message and "Just a moment" in message
    assert list(fetch_rules.out.iterdir()) == [], "unvalidated content is never written"


def test_a_client_error_is_not_retried(fetch_rules, monkeypatch):
    error = urllib.error.HTTPError("https://semgrep.dev/c/p/nope", 404, "Not Found", {}, None)
    seen = serve(monkeypatch, fetch_rules, error)
    with pytest.raises(SystemExit, match="404"):
        fetch_rules.fetch("p/nope")
    assert len(seen) == 1 and fetch_rules.sleeps == []


def test_a_server_error_is_retried(fetch_rules, monkeypatch):
    error = urllib.error.HTTPError("https://semgrep.dev/c/p/python", 503, "Unavailable", {}, None)
    seen = serve(monkeypatch, fetch_rules, error, FakeResponse(GOOD))
    fetch_rules.fetch("p/python")
    assert len(seen) == 2


def test_an_oversized_response_fails_at_once(fetch_rules, monkeypatch):
    monkeypatch.setattr(fetch_rules, "MAX_BYTES", 10)
    seen = serve(monkeypatch, fetch_rules, FakeResponse(GOOD))
    with pytest.raises(SystemExit, match="larger than"):
        fetch_rules.fetch("p/python")
    assert len(seen) == 1


def test_rejects_a_ruleset_name_that_is_not_a_registry_pack(fetch_rules):
    with pytest.raises(SystemExit, match="refusing ruleset name"):
        fetch_rules.fetch("../etc/passwd")
