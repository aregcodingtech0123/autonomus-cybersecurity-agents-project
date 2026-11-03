"""Secret masking for DERIVED text (messages, snippets). Raw scanner output is never touched.

Three layers, applied in this order:
  1. line ranges flagged by Gitleaks are replaced wholesale (handled by `mask_lines`);
  2. well-known secret SHAPES (AWS / Stripe / GitHub / Slack tokens, JWTs, private-key blocks);
  3. sensitive `key = value` assignments and the Bandit message form `... password: 'value'`.
Masking is conservative on purpose: a false redaction costs context, a leak costs a credential.
Text is also stripped of control characters / ANSI escapes and bounded in length.

Hostile text must not stall the pipeline: layer 3 is a single left-to-right pass that looks at each
word-token once (no regex backtracking over long runs), so cost is linear in the input size.
"""

from __future__ import annotations

import re

REDACTED = "<REDACTED>"
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

_SHAPES = [
    re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"),  # AWS access key id
    re.compile(r"\b(?:sk|rk|pk)_(?:test|live|prod)_[A-Za-z0-9]{10,99}\b"),  # Stripe
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),  # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),  # Slack
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),  # JWT
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),  # Google API key
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.DOTALL
    ),
]

_TOKEN = re.compile(r"[A-Za-z0-9_.\-]+")
_KEYWORD = re.compile(
    r"pass(?:word|wd|phrase)?|pwd|secret|token|api[_\-]?key|apikey|auth(?:orization)?"
    r"|credential|private[_\-]?key|access[_\-]?key|client[_\-]?secret|signing[_\-]?key",
    re.IGNORECASE,
)
_SEPARATOR = re.compile(r"[\"']?[ \t]*(?:=>|=|:)[ \t]*")
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


def _is_code_reference(value: str) -> bool:
    """Unquoted type words (`password: str`) and dotted names (`pw = request.form`) are code."""
    return value.lower() in _TYPE_WORDS or bool(_DOTTED_NAME.match(value))


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


def sanitize(text: str, max_chars: int) -> str:
    """Strip ANSI escapes and control characters, then bound the length."""
    text = CONTROL.sub("", ANSI.sub("", text))
    return text if len(text) <= max_chars else text[: max_chars - 3] + "..."


def mask_text(text: str) -> str:
    """Layers 2 and 3 on arbitrary text."""
    for shape in _SHAPES:
        text = shape.sub(REDACTED, text)
    return _mask_assignments(text)


def mask_message(text: str, max_chars: int = 500) -> str:
    """Tool messages can quote code (Bandit B105 embeds the literal), so they are masked too."""
    return sanitize(mask_text(sanitize(text, 20000)), max_chars)


def mask_lines(
    lines: list[tuple[int, str]], flagged: set[int], max_line_chars: int = 200
) -> list[tuple[int, str]]:
    """Mask numbered source lines. Lines in `flagged` (Gitleaks ranges) are replaced entirely."""
    out: list[tuple[int, str]] = []
    for number, text in lines:
        if number in flagged:
            out.append((number, "<line redacted: secret detected by gitleaks>"))
        else:
            out.append((number, sanitize(mask_text(sanitize(text, 20000)), max_line_chars)))
    return out
