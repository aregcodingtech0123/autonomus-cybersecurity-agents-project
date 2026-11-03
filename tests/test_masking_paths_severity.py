import pytest

from secaudit.core.models import Confidence, Severity
from secaudit.core.normalize.masking import REDACTED, mask_lines, mask_message, mask_text, sanitize
from secaudit.core.normalize.paths import normalize_source_path
from secaudit.core.normalize.severity_map import map_confidence, map_severity

# ---------------------------------------------------------------- masking

PLANTED = [
    "bench_n0" "VQRgmEuLNsKJ4a0ZkKpFxr11",
    "not-a-real-password-benchmark-fake",
    "placeholder-not-a-real-password",
    "benc" "h_uoSN55OKIJ9XKt",
    "bench_BvXX7C2JUsDNWW" "hy5PUSWscCmH1w2oxhud",
    "benc" "h_eEA2vGLEXAMPLE",
    "bench_482czv7pDcEQR8" "dwYWxBZZH4EXAMPLEKEY",
]


@pytest.mark.parametrize(
    "line",
    [
        'PAYMENT_API_KEY = "bench_n0' 'VQRgmEuLNsKJ4a0ZkKpFxr11"',
        'ADMIN_PASSWORD = "not-a-real-password-benchmark-fake"',
        'return {"user": "test_user", "password": "placeholder-not-a-real-password"}',
        "aws_access_key_id = benc" "h_uoSN55OKIJ9XKt",
        "aws_secret_access_key = bench_BvXX7C2JUsDNWW" "hy5PUSWscCmH1w2oxhud",
        "aws_access_key_id = benc" "h_eEA2vGLEXAMPLE",
        "aws_secret_access_key = bench_482czv7pDcEQR8" "dwYWxBZZH4EXAMPLEKEY",
        "Possible hardcoded password: 'not-a-real-password-benchmark-fake'",
        "Possible hardcoded password: 'placeholder-not-a-real-password'",
    ],
)
def test_every_planted_secret_is_masked(line):
    masked = mask_text(line)
    assert REDACTED in masked
    for secret in PLANTED:
        assert secret not in masked


def test_masking_keeps_the_key_and_structure_readable():
    assert mask_text('ADMIN_PASSWORD = "hunter2"') == f'ADMIN_PASSWORD = "{REDACTED}"'
    assert mask_text("password: 'x'") == f"password: '{REDACTED}'"
    assert mask_text("token=abc123") == f"token={REDACTED}"
    assert mask_text(
        "Authorization: Bearer abcdef"
    ) == f"Authorization: {REDACTED} abcdef" or REDACTED in mask_text(
        "Authorization: Bearer abcdef"
    )


@pytest.mark.parametrize(
    "text",
    [
        ".".join(
            ["ey" + "JhbGciOiJIUzI1NiJ9", "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0", "dBjftJeZ4CVPmB92K"]
        ),
        "ghp_" + "a" * 36,
        "xo" + "xb-1234567890-abcdefghij",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_token_shapes_are_masked_without_a_keyword(text):
    assert REDACTED in mask_text(f"value is {text} here")


def test_ordinary_code_is_not_mangled():
    code = "return hashlib.md5(password.encode()).hexdigest()"
    assert mask_text(code) == code, "a password VARIABLE without an assigned literal is kept"
    assert (
        mask_text("def hash_password(password: str) -> str:")
        == "def hash_password(password: str) -> str:"
    )


def test_messages_are_masked_sanitized_and_bounded():
    msg = "Possible hardcoded password: 'not-a-real-password-benchmark-fake'\x1b[31m red\x00"
    out = mask_message(msg)
    assert "not-a-real-password" not in out and "\x1b" not in out and "\x00" not in out
    assert len(mask_message("x" * 5000)) == 500


def test_sanitize_strips_ansi_and_controls_but_keeps_newlines_tabs():
    assert sanitize("a\x1b[1;31mb\x07c\td\ne", 100) == "abc\td\ne"


def test_flagged_gitleaks_lines_are_replaced_wholesale():
    lines = [(5, "x = 1"), (6, "KEY = 'zzzzzzzz-unmatched-by-any-regex'"), (7, "y = 2")]
    out = dict(mask_lines(lines, flagged={6}))
    assert out[5] == "x = 1" and out[7] == "y = 2"
    assert "zzzz" not in out[6] and "redacted" in out[6]


def test_long_lines_are_truncated():
    assert len(mask_lines([(1, "a" * 5000)], set())[0][1]) <= 200


# ---------------------------------------------------------------- paths


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("webshop/db.py", "webshop/db.py"),
        ("./webshop/db.py", "webshop/db.py"),
        ("webshop\\db.py", "webshop/db.py"),
        ("/src/webshop/db.py", "webshop/db.py"),
        ("file:///src/webshop/db.py", "webshop/db.py"),
        ("webshop%2Fdb%20x.py", "webshop/db x.py"),
        ("a/b/../c.py", "a/c.py"),
    ],
)
def test_paths_are_normalized(raw, expected):
    assert normalize_source_path(raw) == (expected, None)


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("../../etc/passwd", "path_escapes_source_root"),
        ("a/../../b", "path_escapes_source_root"),
        ("..\\..\\evil.py", "path_escapes_source_root"),
        ("/etc/passwd", "absolute_path_outside_source_root"),
        ("C:\\Windows\\x.py", "absolute_path"),
        ("c:/x.py", "absolute_path"),
        ("file:///C:/x.py", "absolute_path"),
        ("//server/share/x", "absolute_path"),
        ("a\x00b.py", "control_character"),
        ("%00evil", "control_character"),
        ("", "empty_path"),
        ("   ", "empty_path"),
        (None, "empty_path"),
        (123, "empty_path"),
        (".", "is_source_root"),
        ("/src", "is_source_root"),
        ("x/" * 2000, "path_too_long"),
    ],
)
def test_hostile_or_invalid_paths_are_refused(raw, reason):
    assert normalize_source_path(raw) == (None, reason)


# ---------------------------------------------------------------- severity policy


def test_bandit_tool_severity_is_mapped_as_emitted():
    assert map_severity("bandit", raw="HIGH") == (Severity.HIGH, "tool:bandit", None)
    assert map_severity("bandit", raw="medium")[0] is Severity.MEDIUM
    assert map_severity("bandit", raw="LOW")[0] is Severity.LOW


@pytest.mark.parametrize("raw", [None, "", "SEVERE", "critical"])
def test_unknown_bandit_severity_is_unknown_with_a_warning(raw):
    severity, _basis, warning = map_severity("bandit", raw=raw)
    assert severity is Severity.UNKNOWN and warning


def test_semgrep_levels_are_a_stated_policy():
    assert map_severity("semgrep", raw=None, level="error")[:2] == (
        Severity.HIGH,
        "policy:semgrep-level",
    )
    assert map_severity("semgrep", raw=None, level="warning")[0] is Severity.MEDIUM
    assert map_severity("semgrep", raw=None, level="note")[0] is Severity.LOW
    severity, _b, warning = map_severity("semgrep", raw=None, level="catastrophic")
    assert severity is Severity.UNKNOWN and warning


def test_gitleaks_and_pip_audit_policies_are_explicit():
    assert map_severity("gitleaks", raw=None)[:2] == (Severity.HIGH, "policy:gitleaks-secret")
    assert map_severity("pip-audit", raw=None) == (
        Severity.UNKNOWN,
        "pip-audit:emits-no-severity",
        None,
    )


def test_unknown_tool_is_unknown_with_a_warning():
    severity, basis, warning = map_severity("newtool", raw=None, level=None)
    assert severity is Severity.UNKNOWN and "newtool" in basis and warning


def test_confidence_sources():
    assert map_confidence("bandit", raw="MEDIUM") is Confidence.MEDIUM
    assert map_confidence("semgrep", tags=("security", "HIGH CONFIDENCE")) is Confidence.HIGH
    assert map_confidence("semgrep", tags=(), precision="very-high") is Confidence.HIGH
    assert map_confidence("semgrep", tags=(), precision=None) is Confidence.UNKNOWN
    assert map_confidence("gitleaks") is Confidence.UNKNOWN


# ---------------------------------------------------------------- ReDoS: hostile text must mask in linear time

ADVERSARIAL = {
    "one long token": "a" * 20000,
    "keyword soup": "password" * 2500,
    "dotted run": "a." * 10000,
    "many assignments": "token=" * 3000,
    "unterminated quote": "password = '" + "x" * 19000,
    "many private key headers": "-----BEGIN PRIVATE KEY-----" * 700,
}


@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_masking_adversarial_text_stays_fast(name):
    import time

    text = ADVERSARIAL[name]
    started = time.perf_counter()
    mask_message(text)
    mask_lines([(1, text)], set())
    assert time.perf_counter() - started < 1.5, (
        f"{name}: masking took {time.perf_counter() - started:.1f}s"
    )
