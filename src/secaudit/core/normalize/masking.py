"""Secret masking for DERIVED text (messages, snippets). Raw scanner output is never touched.

Layers, applied in this order:
  1. line ranges flagged by Gitleaks and private-key blocks are replaced wholesale (`mask_lines`);
  2. well-known secret SHAPES (AWS / Stripe / GitHub / Slack / Google / `sk-` keys, JWTs, private
     keys, credentials inside URLs, Authorization / Bearer / Basic values);
  3. a high-entropy fallback: any long random-looking token is redacted, whatever it is assigned to;
  4. sensitive `key = value` assignments (also `key: type = value`) and the Bandit message form
     `... password: 'value'`.
Masking fails closed on purpose: a false redaction costs context, a leak costs a credential. Text is
also stripped of control characters, ANSI escapes and invisible formatting characters (a zero-width
space inside a token must not defeat a shape) and bounded in length.

Hostile text must not stall the pipeline: every pattern is anchored on a literal or a character
class that cannot overlap its neighbour, and layer 4 is a single left-to-right pass over word
tokens, so cost is linear in the input size (tests/test_masking_hardening.py feeds megabyte-long
adversarial runs).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Collection

REDACTED = "<REDACTED>"
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]")
# ASCII controls except tab and newline, DEL and C1 controls, then invisible formatting characters
# (soft hyphen, zero-width, bidi marks, BOM). Built with chr() so this file stays plain ASCII.
_INVISIBLE = "".join(
    map(chr, [0xAD, *range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2070), 0xFEFF])
)
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f" + _INVISIBLE + "]")

_AUTH_HEADER = re.compile(
    r"(authorization[\"']?[ \t]*[:=][ \t]*[\"']?)(?:[A-Za-z]+[ \t]+)?[^\s\"',;]+", re.IGNORECASE
)
_SHAPES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"), REDACTED),  # AWS key id
    (re.compile(r"\b(?:sk|rk|pk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b"), REDACTED),  # Stripe
    (re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_\-]{19,}"), REDACTED),  # sk-... (OpenAI / Anthropic)
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), REDACTED),  # GitHub tokens
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),  # Slack
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        REDACTED,
    ),  # JWT
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), REDACTED),  # Google API key
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?"
            r"(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)",
            re.DOTALL,
        ),
        REDACTED,
    ),
    # scheme://user:password@host and scheme://token@host: the whole userinfo goes
    (re.compile(r"(?<=://)[^\s/@\"'<>]+@"), f"{REDACTED}@"),
    (_AUTH_HEADER, rf"\1{REDACTED}"),
    (
        re.compile(r"\b(Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=\-]{8,}", re.IGNORECASE),
        rf"\1 {REDACTED}",
    ),
]

_LONG_RUN = re.compile(r"[A-Za-z0-9+/_\-=]{32,}")
ENTROPY_BITS = 4.2  # random base64 scores ~4.7; hex digests max out at 4.0 and are left alone

_TOKEN = re.compile(r"[A-Za-z0-9_.\-]+")
_KEYWORD = re.compile(
    r"pass(?:word|wd|phrase)?|pwd|secret|token|api[_\-]?key|apikey|auth(?:orization)?"
    r"|credential|private[_\-]?key|access[_\-]?key|client[_\-]?secret|signing[_\-]?key",
    re.IGNORECASE,
)
_SEPARATOR = re.compile(r"[\"']?[ \t]*(?:=>|=|:)[ \t]*")
# `password: str = "x"`, `secret: Optional[str] = "x"`: the type sits between the key and the value
_ANNOTATED_ASSIGN = re.compile(r"[ \t]*\]*[ \t]*=(?!=)[ \t]*")
_VALUE = re.compile(
    r"(?:(?P<q>[\"'])(?P<quoted>[^\n]*?)(?P=q)"  # quoted, single line
    r"|(?P<q2>[\"'])[^\n]*"  # quote never closed: redact to the end of the line
    r"|(?P<bare>[^\s,;#\"')\]}=:]+))"  # bare token
)
_TYPE_WORDS = frozenset(
    {
        "str",
        "int",
        "bytes",
        "bool",
        "float",
        "none",
        "true",
        "false",
        "optional",
        "any",
        "list",
        "dict",
    }
)
_DOTTED_NAME = re.compile(r"^[A-Za-z_]+(\.[A-Za-z_]+)+$")


def entropy(token: str) -> float:
    """Shannon entropy in bits per character."""
    if not token:
        return 0.0
    n = len(token)
    return -sum(c / n * math.log2(c / n) for c in Counter(token).values())


def _is_code_reference(value: str) -> bool:
    """Unquoted type words (`password: str`, `Optional[str`) and short dotted names are code."""
    if value.split("[", 1)[0].lower() in _TYPE_WORDS:
        return True
    return bool(_DOTTED_NAME.match(value)) and len(value) <= 40 and entropy(value) < 4.0


def _mask_assignments(text: str) -> str:
    out: list[str] = []
    pos = 0
    for token in _TOKEN.finditer(text):
        if token.start() < pos or not _KEYWORD.search(token.group()):
            continue
        separator = _SEPARATOR.match(text, token.end())
        if not separator:
            continue
        value = _VALUE.match(text, separator.end())
        if not value:
            continue
        bare = value.group("bare")
        if bare is not None and _KEYWORD.search(bare) and _SEPARATOR.match(text, value.end()):
            continue  # `secret: secret_key = "x"`: the "value" is itself a key; handle it next
        if bare is not None and _is_code_reference(bare):
            annotated = _ANNOTATED_ASSIGN.match(text, value.end())
            if not annotated:
                continue
            separator = annotated
            value = _VALUE.match(text, annotated.end())
            if not value:
                continue
            bare = value.group("bare")
            if bare is not None and _is_code_reference(bare):
                continue
        out.append(text[pos : separator.end()])
        if value.group("q2"):
            out.append(f"{value.group('q2')}{REDACTED}")
        elif value.group("q"):
            out.append(f"{value.group('q')}{REDACTED}{value.group('q')}")
        else:
            out.append(REDACTED)
        pos = value.end()
    out.append(text[pos:])
    return "".join(out)


def _mask_random_tokens(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group()
        has_digit = any(c.isdigit() for c in token)
        has_alpha = any(c.isalpha() for c in token)
        return REDACTED if has_digit and has_alpha and entropy(token) >= ENTROPY_BITS else token

    return _LONG_RUN.sub(replace, text)


def sanitize(text: str, max_chars: int) -> str:
    """Strip ANSI escapes, control and invisible characters, then bound the length."""
    text = CONTROL.sub("", ANSI.sub("", text))
    if len(text) <= max_chars:
        return text
    return text[:max_chars] if max_chars <= 3 else text[: max_chars - 3] + "..."


def mask_text(text: str) -> str:
    """Layers 2 to 4 on arbitrary text."""
    for shape, replacement in _SHAPES:
        text = shape.sub(replacement, text)
    return _mask_assignments(_mask_random_tokens(text))


def mask_message(text: str, max_chars: int = 500) -> str:
    """Tool messages can quote code (Bandit B105 embeds the literal), so they are masked too."""
    return sanitize(mask_text(sanitize(text, 20000)), max_chars)


GITLEAKS_LINE = "<line redacted: secret detected by gitleaks>"
PEM_LINE = "<line redacted: private key block>"


def mask_lines(
    lines: list[tuple[int, str]],
    flagged: Collection[int],
    max_line_chars: int = 200,
    pem: Collection[int] = (),
) -> list[tuple[int, str]]:
    """Mask numbered source lines.

    Lines in `flagged` (Gitleaks ranges) and in `pem` (inside a private-key block, found from the
    whole file) are replaced entirely: unknown secret shapes there are masked because the line is.
    """
    out: list[tuple[int, str]] = []
    for number, text in lines:
        if number in flagged:
            out.append((number, sanitize(GITLEAKS_LINE, max_line_chars)))
        elif number in pem:
            out.append((number, sanitize(PEM_LINE, max_line_chars)))
        else:
            out.append((number, sanitize(mask_text(sanitize(text, 20000)), max_line_chars)))
    return out
