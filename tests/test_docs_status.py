"""The POSIX verification table must never claim more than its Run column proves."""

from __future__ import annotations

import re
from pathlib import Path

NOTES = Path(__file__).resolve().parent.parent / "docs" / "PHASE1_NOTES.md"


def claims_verified(status: str) -> bool:
    """Whole word only: 'unverified' must not count as verified."""
    return re.search(r"\bverified\b", status, re.IGNORECASE) is not None


def table_rows() -> list[list[str]]:
    text = NOTES.read_text("utf-8")
    section = text.split("## POSIX / Linux verification status", 1)[1].split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if re.match(r"^\|\s*\d+\s*\|", line)]
    return [[cell.strip() for cell in row.strip().strip("|").split("|")] for row in rows]


def test_the_status_table_exists_and_covers_every_claim():
    rows = table_rows()
    assert [r[0] for r in rows] == [str(n) for n in range(1, 11)]
    assert all(len(r) == 6 for r in rows), "number, claim, evidence, runner test, status, run"


def test_nothing_is_marked_verified_without_a_run_id():
    for number, _claim, _evidence, _runner, status, run in table_rows():
        if claims_verified(status):
            assert re.search(r"\d{6,}|https://github\.com/\S+/actions/runs/\d+", run), (
                f"row {number} says VERIFIED but names no CI run"
            )
        else:
            assert run in ("-", "") or re.search(r"\d", run), f"row {number}: unexpected Run value"


def test_the_never_run_state_is_stated_while_no_row_has_a_run():
    rows = table_rows()
    if all(r[5] in ("-", "") for r in rows):
        assert not any(claims_verified(r[4]) for r in rows)
