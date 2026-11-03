"""Regression guard: no token-shaped literal in any tracked file.

GitHub push protection scans every commit of a push, and any secret scanner flags a realistic token
that sits in a test. Test canaries are therefore assembled at RUNTIME from fragments
(tests/canaries.py). This test scans the content of every file in `git ls-files` with a pattern
set that approximates what the scanners look for, and fails with the path, line and a MASKED value
(first four characters and the length; never the value).

ALLOWLIST: the only paths allowed to hold token-shaped literals.

* benchmarks/targets/**, benchmarks/baseline/**, tests/fixtures/phase1_baseline/**: the benchmark
  target plants fake secrets ON PURPOSE (they are the vulnerability under test) and the baseline
  holds the scanners' raw output about them, frozen byte for byte.
* benchmarks/expected_findings.yaml: the ground truth that names the planted lines. The frozen
  baseline pins its SHA-256 (`ground_truth_sha256` in metrics_tool_only.json), so editing it would
  invalidate the baseline.

A positive control builds a token-shaped sample at runtime and proves the scanner flags it, so an
empty result means something. A negative control proves it does not flag everything.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from canaries import (
    aws_docs_key_id,
    aws_docs_secret_key,
    aws_key_id,
    aws_secret_key,
    pem_block,
    planted_secrets,
    single_line_canaries,
    stripe_test_key,
    stripe_test_key_short,
)

REPO = Path(__file__).resolve().parent.parent

ALLOWLIST_PREFIXES = (
    "benchmarks/targets/",
    "benchmarks/baseline/",
    "tests/fixtures/phase1_baseline/",
)
ALLOWLIST_FILES = ("benchmarks/expected_findings.yaml",)

_B64 = r"A-Za-z0-9/+="
PATTERNS = {
    "stripe_key": re.compile(r"\b[sr]k_(?:test|live)_[0-9A-Za-z]{8,}"),
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "aws_secret_key_40": re.compile(rf"(?<![{_B64}\-_.])[{_B64}]{{40}}(?![{_B64}\-_.])"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    "github_fine_grained_pat": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    "pem_private_key_block": re.compile(
        r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:\s*[A-Za-z0-9+/=]{16,}){2,}|-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{40,}"
    ),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}"),
    "url_with_credentials": re.compile(
        r"\b[a-z][a-z0-9+.-]*://([^/\s:@'\"{}$<>]+):([^/\s@'\"{}$<>]+)@[^\s'\"]+", re.I
    ),
}
# `scheme://user:pass@host` in docs and parser tests is a placeholder, not a credential.
PLACEHOLDER_PASSWORDS = {"pass", "password", "pwd", "secret", "token", "xxx", "xxxx", "redacted"}


def scan_text(text: str) -> list[tuple[str, int, int]]:
    """Return (kind, line number, length) for every token-shaped literal in `text`."""
    found = []
    for kind, rx in PATTERNS.items():
        for m in rx.finditer(text):
            value = m.group(0)
            if kind == "aws_secret_key_40" and not (
                re.search(r"[A-Z]", value)
                and re.search(r"[a-z]", value)
                and re.search(r"\d", value)
            ):
                continue  # a hex digest or an identifier, not a key
            if kind == "url_with_credentials" and m.group(2).lower() in PLACEHOLDER_PASSWORDS:
                continue
            found.append((kind, text.count("\n", 0, m.start()) + 1, len(value)))
    return found


def is_allowlisted(path: str) -> bool:
    return path.startswith(ALLOWLIST_PREFIXES) or path in ALLOWLIST_FILES


def tracked_files() -> list[str]:
    if not (REPO / ".git").exists():
        pytest.skip("not a git checkout (source archive): nothing to enumerate")
    out = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, check=True
    ).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def test_no_tracked_file_holds_a_token_shaped_literal():
    problems = []
    for rel in tracked_files():
        if is_allowlisted(rel) or not (REPO / rel).is_file():
            continue
        data = (REPO / rel).read_bytes()
        if b"\0" in data[:8192]:
            continue  # binary
        for kind, line, length in scan_text(data.decode("utf-8", errors="replace")):
            problems.append(f"{rel}:{line}  {kind}  (length {length})")
    assert not problems, (
        "token-shaped literal(s) in tracked files. Build the value at runtime from fragments "
        "(tests/canaries.py) instead of committing it:\n  " + "\n  ".join(problems)
    )


def test_allowlist_entries_exist():
    """A stale allowlist entry would silently exempt a path that comes back later."""
    for prefix in ALLOWLIST_PREFIXES:
        assert (REPO / prefix).is_dir(), prefix
    for rel in ALLOWLIST_FILES:
        assert (REPO / rel).is_file(), rel


# ---------------------------------------------------------------- positive and negative controls


def _kinds(text: str) -> set[str]:
    return {kind for kind, _line, _length in scan_text(text)}


def test_positive_control_a_runtime_built_sample_is_flagged():
    by_name = {c.name: c.line for c in single_line_canaries()}
    samples = {
        "stripe_key": f'KEY = "{stripe_test_key()}"',
        "aws_access_key_id": f"id = {aws_key_id()}",
        "aws_secret_key_40": f"aws_secret_access_key = {aws_secret_key()}",
        "github_token": by_name["github_classic"],
        "github_fine_grained_pat": by_name["github_fine_grained"],
        "slack_token": by_name["slack_bot"],
        "google_api_key": by_name["google_api_key"],
        "jwt": by_name["jwt"],
        "url_with_credentials": by_name["url_password"],
        "pem_private_key_block": "\n".join(pem_block()),
    }
    assert set(samples) == set(PATTERNS), "every pattern needs its own positive control"
    missed = {kind for kind, text in samples.items() if kind not in _kinds(text)}
    assert not missed, f"scanner failed to flag its own samples: {sorted(missed)}"


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


# ---------------------------------------------------------------- the allowlisted fakes stay in sync


def test_runtime_builders_equal_what_the_benchmark_target_plants():
    """The tests' view of the planted fakes must be the real thing, or they prove nothing."""
    target = REPO / "benchmarks" / "targets" / "vuln_python_app"
    corpus = "\n".join(
        p.read_text("utf-8", errors="replace") for p in sorted(target.rglob("*")) if p.is_file()
    )
    for name, value in {
        "stripe_test_key": stripe_test_key(),
        "aws_key_id": aws_key_id(),
        "aws_secret_key": aws_secret_key(),
        "aws_docs_key_id": aws_docs_key_id(),
        "aws_docs_secret_key": aws_docs_secret_key(),
    }.items():
        assert value in corpus, f"{name} no longer matches the benchmark target"
    assert stripe_test_key().startswith(stripe_test_key_short())
    assert len(planted_secrets()) == 7
