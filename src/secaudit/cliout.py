"""Terminal-safe text for anything that came from scanned content.

File names, rule titles, input names and manifest fields must pass through `safe()` before they
are printed: a file name carrying ESC sequences must not clear the screen or retitle the
terminal, and a bidi override must not make a path read differently from what it is.
"""

from __future__ import annotations

import re
import unicodedata

from secaudit.core.normalize.masking import ANSI

# OSC (title, hyperlinks, clipboard) and DCS/PM/APC/SOS strings run until BEL or ST (ESC \).
_STRING_SEQUENCE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[PX^_][^\x1b]*(?:\x1b\\)?")
_DROPPED = frozenset(
    {"Cc", "Cf", "Cs"}
)  # controls (incl. C1), format (bidi, zero-width), surrogates
_AS_SPACE = frozenset({"Zl", "Zp"})


def safe(value: object, max_chars: int = 300) -> str:
    """One printable line: no escape sequences, no control or invisible characters, bounded."""
    text = ANSI.sub("", _STRING_SEQUENCE.sub("", str(value)))
    out: list[str] = []
    for char in text:
        if char in "\n\r\t":
            out.append(" ")
            continue
        category = unicodedata.category(char)
        if category in _AS_SPACE:
            out.append(" ")
        elif category not in _DROPPED:
            out.append(char)
    line = "".join(out)
    return line if len(line) <= max_chars else line[: max_chars - 3] + "..."
