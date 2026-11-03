"""THE severity/confidence policy. One file, reviewed as a unit; every table is explicit.

Read this before trusting a mapped severity:
  * Bandit emits HIGH/MEDIUM/LOW itself: mapped 1:1 (basis "tool").
  * Semgrep emits a rule LEVEL (error/warning/note), which is not a risk rating. Mapping it to
    HIGH/MEDIUM/LOW is OUR policy (basis "policy:semgrep-level").
  * Gitleaks emits no severity at all. Our reviewed policy is that a detected hard-coded secret is
    HIGH (basis "policy:gitleaks-secret"). This is a policy choice, not tool output.
  * pip-audit emits none either; CVSS enrichment is Phase 4, so the severity stays UNKNOWN.
Anything not in a table maps to UNKNOWN and produces a warning. Nothing is guessed.
"""

from __future__ import annotations

from secaudit.core.models import Confidence, Severity

BANDIT_SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
BANDIT_CONFIDENCE = {"HIGH": Confidence.HIGH, "MEDIUM": Confidence.MEDIUM, "LOW": Confidence.LOW}

SEMGREP_LEVEL = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}
# Semgrep rules carry a confidence tag ("HIGH CONFIDENCE") and a SARIF `precision` property.
SEMGREP_CONFIDENCE_TAG = {
    "HIGH CONFIDENCE": Confidence.HIGH,
    "MEDIUM CONFIDENCE": Confidence.MEDIUM,
    "LOW CONFIDENCE": Confidence.LOW,
}
SEMGREP_PRECISION = {
    "very-high": Confidence.HIGH,
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
}

GITLEAKS_SECRET_SEVERITY = Severity.HIGH  # policy: every detected hard-coded secret

# Generic SARIF `level`, used only for tools without a dedicated table.
GENERIC_LEVEL = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "note": Severity.LOW}


def map_severity(
    tool: str, *, raw: str | None, level: str | None = None
) -> tuple[Severity, str, str | None]:
    """Return (severity, basis, warning); `raw` = tool severity word, `level` = SARIF level."""
    if tool == "bandit":
        if raw is None:
            return (
                Severity.UNKNOWN,
                "bandit:missing-issue_severity",
                "bandit result has no issue_severity",
            )
        mapped = BANDIT_SEVERITY.get(raw.upper())
        if mapped is None:
            return (
                Severity.UNKNOWN,
                f"bandit:unmapped:{raw[:20]}",
                f"unknown bandit severity {raw[:20]!r}",
            )
        return mapped, "tool:bandit", None
    if tool == "semgrep":
        key = (level or raw or "").lower()
        mapped = SEMGREP_LEVEL.get(key)
        if mapped is None:
            return (
                Severity.UNKNOWN,
                "semgrep:no-level",
                f"semgrep rule level {key[:20]!r} is not in the table",
            )
        return mapped, "policy:semgrep-level", None
    if tool == "gitleaks":
        return GITLEAKS_SECRET_SEVERITY, "policy:gitleaks-secret", None
    if tool == "pip-audit":
        return Severity.UNKNOWN, "pip-audit:emits-no-severity", None
    mapped = GENERIC_LEVEL.get((level or "").lower())
    if mapped is None:
        return (
            Severity.UNKNOWN,
            f"{tool[:30]}:unknown-tool",
            f"no severity table for tool {tool[:30]!r}",
        )
    return (
        mapped,
        f"policy:{tool[:30]}-sarif-level",
        f"no dedicated severity table for tool {tool[:30]!r}",
    )


def map_confidence(
    tool: str, *, raw: str | None = None, tags: tuple[str, ...] = (), precision: str | None = None
) -> Confidence:
    if tool == "bandit":
        return BANDIT_CONFIDENCE.get((raw or "").upper(), Confidence.UNKNOWN)
    if tool == "semgrep":
        for tag in tags:
            if tag.upper() in SEMGREP_CONFIDENCE_TAG:
                return SEMGREP_CONFIDENCE_TAG[tag.upper()]
        return SEMGREP_PRECISION.get((precision or "").lower(), Confidence.UNKNOWN)
    return Confidence.UNKNOWN
