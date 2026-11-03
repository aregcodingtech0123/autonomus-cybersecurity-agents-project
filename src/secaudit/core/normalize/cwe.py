"""CWE extraction, issue-class equivalence and the Gitleaks rule table."""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import cache
from importlib import resources

import yaml

_CWE_RE = re.compile(r"cwe[-_ :/]*?(\d{1,5})(?!\d)", re.IGNORECASE)

# Reviewed equivalences: two CWE ids that name the same issue class for merge/fingerprint purposes.
# Keep this short; every entry needs a reason. Different classes are NEVER merged.
CLASS_EQUIVALENCE: dict[str, str] = {
    "CWE-328": "CWE-327",  # reversible one-way hash ~ broken/risky algorithm (md5 uses both)
    "CWE-259": "CWE-798",  # hard-coded password is the password case of hard-coded credentials
}


def normalize_cwe(text: str) -> str | None:
    """`external/cwe/cwe-94`, `CWE-489: Active Debug Code`, `cwe_79` -> `CWE-94`, `CWE-489`, `CWE-79`."""
    match = _CWE_RE.search(text or "")
    return f"CWE-{int(match.group(1))}" if match else None


def extract_cwes(values: Iterable[str]) -> tuple[str, ...]:
    """Unique CWE ids from free-form tag strings, numerically sorted (deterministic)."""
    found = {c for v in values if isinstance(v, str) and (c := normalize_cwe(v))}
    return tuple(sorted(found, key=lambda c: int(c.split("-")[1])))


def issue_class_for_cwe(cwe: str) -> str:
    return CLASS_EQUIVALENCE.get(cwe, cwe)


@cache
def _gitleaks_table() -> tuple[str, frozenset[str]]:
    text = (resources.files("secaudit") / "data" / "gitleaks_rule_cwe.yaml").read_text("utf-8")
    doc = yaml.safe_load(text)
    return doc["default_cwe"], frozenset(doc["rules"])


def gitleaks_cwe(rule_id: str) -> tuple[str, bool]:
    """(CWE, reviewed). Unknown rules still map to the default CWE but are flagged unreviewed."""
    default, rules = _gitleaks_table()
    return default, rule_id in rules
