import json
from collections import Counter
from pathlib import Path

import pytest

from secaudit.core.normalize.cwe import (
    extract_cwes,
    gitleaks_cwe,
    issue_class_for_cwe,
    normalize_cwe,
)
from secaudit.core.normalize.owasp import load_owasp_map, owasp_category

RAW = Path(__file__).resolve().parent / "fixtures" / "phase1_baseline" / "raw"


def test_every_category_lists_exactly_the_count_the_official_page_states():
    owasp = load_owasp_map()
    listed = Counter(owasp.by_cwe.values())
    assert set(owasp.names) == {f"A{i:02d}" for i in range(1, 11)}
    assert dict(listed) == owasp.stated_counts
    assert sum(listed.values()) == 249 == len(owasp.by_cwe), "no CWE appears in two categories"


def test_official_names_and_provenance():
    owasp = load_owasp_map()
    assert owasp.names["A03"] == "Software Supply Chain Failures"
    assert owasp.names["A10"] == "Mishandling of Exceptional Conditions"
    assert owasp.retrieved == "2026-11-03"
    header = (
        Path(__file__).resolve().parent.parent / "src/secaudit/data/owasp_top10_2025_cwe_map.yaml"
    ).read_text("utf-8")
    assert "top10.owasp.org/2025" in header and "Retrieved" in header


@pytest.mark.parametrize(
    ("cwe", "category"),
    [
        ("CWE-89", "A05"), ("CWE-78", "A05"), ("CWE-94", "A05"), ("CWE-22", "A01"),
        ("CWE-798", "A07"), ("CWE-259", "A07"), ("CWE-327", "A04"), ("CWE-328", "A04"),
        ("CWE-502", "A08"), ("CWE-489", "A02"), ("CWE-1395", "A03"), ("CWE-703", "A10"),
    ],
)  # fmt: skip
def test_lookups_for_the_cwes_the_benchmark_uses(cwe, category):
    assert load_owasp_map().category(cwe) == category


@pytest.mark.parametrize("cwe", ["CWE-999999", "CWE-1", "nonsense", "CWE-"])
def test_unmapped_cwes_are_none_not_guesses(cwe):
    assert load_owasp_map().category(cwe) is None


def test_primary_cwe_wins_then_first_mapped():
    assert owasp_category(("CWE-1", "CWE-89"), primary=None) == "A05"
    assert owasp_category(("CWE-89", "CWE-798"), primary="CWE-798") == "A07"
    assert owasp_category(("CWE-1",)) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("external/cwe/cwe-94", "CWE-94"),
        ("CWE-489: Active Debug Code", "CWE-489"),
        ("cwe_79", "CWE-79"),
        ("CWE-0089", "CWE-89"),
        ("OWASP-A06:2017 - Security Misconfiguration", None),
        ("security", None),
        ("", None),
    ],
)
def test_normalize_cwe(text, expected):
    assert normalize_cwe(text) == expected


def test_extract_cwes_is_unique_and_numerically_sorted():
    tags = ["security", "CWE-327: x", "external/cwe/cwe-78", "cwe-327", "CWE-1004", 5, None]
    assert extract_cwes(tags) == ("CWE-78", "CWE-327", "CWE-1004")


def test_reviewed_class_equivalences_only():
    assert issue_class_for_cwe("CWE-328") == "CWE-327"
    assert issue_class_for_cwe("CWE-259") == "CWE-798"
    assert issue_class_for_cwe("CWE-89") == "CWE-89"
    assert issue_class_for_cwe("CWE-78") != issue_class_for_cwe("CWE-89")


def test_gitleaks_table_covers_every_rule_in_the_real_sarif():
    rules = json.loads((RAW / "gitleaks.sarif").read_text("utf-8"))["runs"][0]["tool"]["driver"][
        "rules"
    ]
    assert len(rules) == 222
    for rule in rules:
        assert gitleaks_cwe(rule["id"]) == ("CWE-798", True)
    assert gitleaks_cwe("brand-new-rule") == ("CWE-798", False), "unreviewed rules are flagged"
