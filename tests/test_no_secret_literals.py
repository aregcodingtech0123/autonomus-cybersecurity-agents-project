"""Regression guard: no provider-shaped credential in any tracked file. NO allowlist.

GitHub push protection scans every commit of a push and blocks provider-shaped tokens even when they
are fake. Since ADR-003 (docs/DECISIONS.md) nothing in the repository is provider-shaped: not the
tests, not the benchmark target, not the raw scanner outputs, not the frozen fixtures.

* Test canaries that must look like real provider tokens (to prove masking catches them) are
  assembled at RUNTIME from fragments in tests/canaries.py.
* The benchmark's planted secrets are hardcoded on purpose, but GENERIC-shaped (a `bench_` prefix
  and a random body). They match none of the patterns below by design, and Gitleaks still finds the
  positive ones with its generic rule.

This test scans the content of every file in `git ls-files` and fails with the path, line and length
of each hit (never the value). A positive control builds one sample per pattern at runtime and
proves the scanner flags it, so an empty result means something; a negative control proves it does
not flag everything.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from canaries import (
    ini_example_key_id,
    ini_example_secret,
    ini_key_id,
    ini_secret,
    pem_block,
    planted_api_key,
    planted_api_key_prefix,
    planted_secrets,
    single_line_canaries,
)

REPO = Path(__file__).resolve().parent.parent

_B64 = r"A-Za-z0-9/+="
PATTERNS = {
    "stripe_key": re.compile(r"\b[spr]k_(?:test|live)_[0-9A-Za-z]{8,}"),
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{12,16}\b"),
    "aws_secret_key_40": re.compile(rf"(?<![{_B64}\-_.\\])[{_B64}]{{40}}(?![{_B64}\-_.])"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"),
    "github_fine_grained_pat": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    "slack_token": re.compile(r"\bxox[abprse]-[A-Za-z0-9-]{10,}"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"),
    "gitlab_pat": re.compile(r"\bglpat-[0-9A-Za-z_-]{16,}"),
    "sendgrid_key": re.compile(r"\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}"),
    "shopify_token": re.compile(r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{20,}"),
    "npm_token": re.compile(r"\bnpm_[0-9A-Za-z]{30,}"),
    "pypi_token": re.compile(r"\bpypi-[0-9A-Za-z_-]{30,}"),
    "huggingface_token": re.compile(r"\bhf_[0-9A-Za-z]{30,}"),
    "digitalocean_token": re.compile(r"\bdo[por]_v1_[0-9a-f]{20,}"),
    "pem_private_key_block": re.compile(
        r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:(?:\\n|\s)*[A-Za-z0-9+/=]{16,}){2,}"
        r"|-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:\\n|\s)*[A-Za-z0-9+/=]{40,}"
    ),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}"),
    "url_with_credentials": re.compile(
        r"\b[a-z][a-z0-9+.-]*://([^/\s:@'\"{}$<>\\]+):([^/\s@'\"{}$<>\\]+)@[^\s'\"]+", re.I
    ),
}
# `scheme://user:pass@host` in docs and parser tests is a placeholder, not a credential.
PLACEHOLDER_PASSWORDS = {"pass", "password", "pwd", "secret", "token", "xxx", "xxxx", "redacted"}


def scan_text(text: str) -> list[tuple[str, int, int]]:
    """Return (kind, line number, length) for every provider-shaped literal in `text`."""
    views = [text]
    if "\\/" in text:
        views.append(text.replace("\\/", "/"))  # JSON may escape "/"; do not let that hide a key
    found = set()
    for view in views:
        for kind, rx in PATTERNS.items():
            for m in rx.finditer(view):
                value = m.group(0)
                if kind == "aws_secret_key_40" and not (
                    re.search(r"[A-Z]", value)
                    and re.search(r"[a-z]", value)
                    and re.search(r"\d", value)
                ):
                    continue  # a hex digest or an identifier, not a key
                if kind == "url_with_credentials" and m.group(2).lower() in PLACEHOLDER_PASSWORDS:
                    continue
                found.add((kind, view.count("\n", 0, m.start()) + 1, len(value)))
    return sorted(found)


def tracked_files() -> list[str]:
    if not (REPO / ".git").exists():
        pytest.skip("not a git checkout (source archive): nothing to enumerate")
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True
    ).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def test_no_tracked_file_holds_a_provider_shaped_literal():
    """Everything is scanned: benchmarks/**, raw outputs and frozen fixtures included."""
    problems = []
    for rel in tracked_files():
        if not (REPO / rel).is_file():
            continue
        data = (REPO / rel).read_bytes()
        if b"\0" in data[:8192]:
            continue  # binary
        for kind, line, length in scan_text(data.decode("utf-8", errors="replace")):
            problems.append(f"{rel}:{line}  {kind}  (length {length})")
    assert not problems, (
        "provider-shaped literal(s) in tracked files. Build test canaries at runtime from "
        "fragments (tests/canaries.py); benchmark secrets must be generic-shaped (ADR-003):\n  "
        + "\n  ".join(problems)
    )


# ---------------------------------------------------------------- positive and negative controls


def _kinds(text: str) -> set[str]:
    return {kind for kind, _line, _length in scan_text(text)}


def test_positive_control_a_runtime_built_sample_is_flagged():
    by_name = {c.name: c.line for c in single_line_canaries()}
    body = "Zk3Rt9Qm" * 5
    samples = {
        "stripe_key": "pk" + "_live_" + body[:24],
        "aws_access_key_id": "AK" + "IA" + "QWERTYUIOPASDFGH",
        "aws_secret_key_40": "aws_secret_access_key = " + "Xq7" + "Lm2Vb9Tr" * 4 + "Pz3E0",
        "github_token": by_name["github_classic"],
        "github_fine_grained_pat": by_name["github_fine_grained"],
        "slack_token": by_name["slack_bot"],
        "google_api_key": by_name["google_api_key"],
        "gitlab_pat": "gl" + "pat-" + body[:20],
        "sendgrid_key": "S" + "G." + body[:22] + "." + body[:43],
        "shopify_token": "sh" + "pat_" + "0a1b2c3d4e5f" * 3,
        "npm_token": "np" + "m_" + body[:36],
        "pypi_token": "py" + "pi-" + body[:40],
        "huggingface_token": "h" + "f_" + body[:34],
        "digitalocean_token": "do" + "p_v1_" + "0a1b2c3d4e5f" * 4,
        "jwt": by_name["jwt"],
        "url_with_credentials": by_name["url_password"],
        "pem_private_key_block": "\n".join(pem_block()),
    }
    assert set(samples) == set(PATTERNS), "every pattern needs its own positive control"
    missed = {kind for kind, text in samples.items() if kind not in _kinds(text)}
    assert not missed, f"scanner failed to flag its own samples: {sorted(missed)}"
    escaped = '{"key": "' + "Xq7" + "Lm2Vb9T/" * 4 + "Pz3E0" + '"}'
    assert "aws_secret_key_40" in _kinds(escaped.replace("/", "\\/")), "JSON escaping hid a key"


def test_negative_control_benign_text_is_not_flagged():
    benign = "\n".join(
        [
            "sha = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4'",  # 40 hex characters, a git digest
            "url = 'https://user:pass@github.com/org/repo.git'",  # documentation placeholder
            "dsn = f'postgres://svc:{password}@db.internal/app'",  # template, not a credential
            "prefix = 'sk_test_'  # the prefix alone",
            "-----BEGIN PRIVATE KEY-----",  # header without a body
            "x = 'AKIA'  # the prefix alone",
            "class VeryLongCamelCaseIdentifierWithoutAnyDigitsAtAllXx: ...",
        ]
    )
    assert scan_text(benign) == []


# ---------------------------------------------------------------- the planted fakes


def test_planted_benchmark_secrets_are_generic_shaped():
    """ADR-003: hardcoded on purpose, fake, and matching no provider format."""
    for value in planted_secrets():
        assert scan_text(f'value = "{value}"') == [], "a planted fake looks like a provider token"
    for value in (planted_api_key(), ini_key_id(), ini_secret()):
        assert value.startswith("bench_")


def test_runtime_builders_equal_what_the_benchmark_target_plants():
    """The tests' view of the planted fakes must be the real thing, or they prove nothing."""
    target = REPO / "benchmarks" / "targets" / "vuln_python_app"
    corpus = "\n".join(
        p.read_text("utf-8", errors="replace") for p in sorted(target.rglob("*")) if p.is_file()
    )
    for name, value in {
        "planted_api_key": planted_api_key(),
        "ini_key_id": ini_key_id(),
        "ini_secret": ini_secret(),
        "ini_example_key_id": ini_example_key_id(),
        "ini_example_secret": ini_example_secret(),
    }.items():
        assert value in corpus, f"{name} no longer matches the benchmark target"
    assert planted_api_key().startswith(planted_api_key_prefix())
    assert len(planted_secrets()) == 7
