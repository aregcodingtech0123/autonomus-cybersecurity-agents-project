import pytest
from pydantic import ValidationError

from secaudit.core.models import (
    SCHEMA_VERSION,
    Audit,
    Confidence,
    RawRef,
    SecurityFinding,
    Severity,
    ToolHit,
)

REF = RawRef(artifact="raw/bandit.sarif", artifact_sha256="a" * 64, pointer="/runs/0/results/0")


def hit(**kw):
    base = dict(
        tool="bandit",
        rule_id="B608",
        message="m",
        file_path="app/db.py",
        line_start=3,
        line_end=3,
        raw_ref=REF,
    )
    return ToolHit(**{**base, **kw})


def finding(hits=None, **kw):
    base = dict(
        id="f1",
        fingerprint="x",
        fingerprint_basis="content",
        title="t",
        issue_class="CWE-89",
        file_path="app/db.py",
        line_start=3,
        line_end=3,
        hits=(hit(),) if hits is None else hits,
        severity=Severity.HIGH,
        severity_basis="bandit:B608",
    )
    return SecurityFinding(**{**base, **kw})


def test_a_finding_without_tool_evidence_cannot_be_constructed():
    with pytest.raises(ValidationError):
        finding(hits=())
    with pytest.raises(ValidationError):
        SecurityFinding.model_validate(
            {k: v for k, v in finding().model_dump().items() if k != "hits"}
        )


def test_valid_finding_and_reserved_fields_are_empty():
    f = finding()
    assert f.status == "open" and f.triage is None and f.risk is None and f.remediation is None
    assert f.tools == ("bandit",) and f.confidence is Confidence.UNKNOWN


@pytest.mark.parametrize("field", ["triage", "risk", "remediation"])
def test_reserved_fields_cannot_be_filled_yet(field):
    with pytest.raises(ValidationError):
        finding(**{field: {"anything": 1}})


@pytest.mark.parametrize(
    "path",
    [
        "../etc/passwd",
        "/etc/passwd",
        "a\\b.py",
        "C:/x.py",
        "a/../b.py",
        "a//b.py",
        "",
        "x" * 2000,
        "a\x00b",
    ],
)
def test_hostile_paths_are_unrepresentable(path):
    with pytest.raises(ValidationError):
        hit(file_path=path)
    with pytest.raises(ValidationError):
        finding(file_path=path)


def test_line_range_and_message_bounds():
    with pytest.raises(ValidationError):
        hit(line_start=5, line_end=4)
    with pytest.raises(ValidationError):
        hit(line_start=0)
    with pytest.raises(ValidationError):
        hit(message="x" * 501)


def test_models_are_frozen_and_reject_unknown_fields():
    f = finding()
    with pytest.raises(ValidationError):
        f.title = "other"
    with pytest.raises(ValidationError):
        ToolHit(**{**hit().model_dump(), "snippet": "secret"})  # no snippet field exists on a hit


def test_raw_ref_needs_a_real_sha256():
    with pytest.raises(ValidationError):
        RawRef(artifact="raw/x", artifact_sha256="nothex", pointer="/")


def test_severity_ordering_and_schema_version():
    assert (
        Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank > Severity.UNKNOWN.rank
    )
    assert Audit().schema_version == SCHEMA_VERSION == "1"
