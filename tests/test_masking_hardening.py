"""Phase 2B Task 0c: masking fails closed. Canaries are built at runtime (tests/canaries.py)."""

import json
import time

import pytest

from canaries import PEM_BODY, pem_block, single_line_canaries
from secaudit.core.normalize.masking import REDACTED, mask_lines, mask_message, mask_text
from secaudit.core.normalize.pipeline import export_json, normalize_audit
from secaudit.core.normalize.snippets import flagged_text, make_snippet

CANARIES = single_line_canaries()
IDS = [c.name for c in CANARIES]


# ---------------------------------------------------------------- every shape, messages and snippets


@pytest.mark.parametrize("canary", CANARIES, ids=IDS)
def test_canary_is_masked_in_text_and_in_tool_messages(canary):
    assert canary.core not in mask_text(canary.line)
    message = f"Possible secret found: {canary.line} (line 5)"
    masked = mask_message(message)
    assert canary.core not in masked and REDACTED in masked


@pytest.mark.parametrize("canary", CANARIES, ids=IDS)
def test_canary_is_masked_in_source_snippets_and_fingerprint_text(canary, tmp_path):
    (tmp_path / "a.py").write_text(f"x = 1\ny = 2\n{canary.line}\nz = 3\n", encoding="utf-8")
    snippet = make_snippet(tmp_path, "a.py", 3, 3, set())
    assert snippet is not None and canary.core not in snippet
    text = flagged_text(tmp_path, "a.py", 3, 3, set())
    assert text is not None and canary.core not in text


@pytest.mark.parametrize("canary", CANARIES, ids=IDS)
def test_masking_is_idempotent(canary):
    once = mask_text(canary.line)
    assert mask_text(once) == once
    message = mask_message(f"found {canary.line}")
    assert mask_message(message) == message


def test_masking_never_reveals_more_than_the_text_it_was_given():
    for canary in CANARIES:
        assert mask_text(canary.line).count(canary.core) == 0
    plain = "def add(a, b):\n    return a + b  # a long_identifier_without_digits_is_not_a_secret"
    assert mask_text(plain) == plain


# ---------------------------------------------------------------- PEM blocks across lines


def _write_key_file(tmp_path):
    lines = ["import os", "", *pem_block(), "", "print('done')"]
    (tmp_path / "key.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return lines


def test_pem_block_is_masked_when_the_header_is_in_the_text():
    text = "\n".join(pem_block())
    masked = mask_text(text)
    assert all(part not in masked for part in PEM_BODY)


def test_pem_body_lines_are_masked_even_when_the_snippet_window_holds_no_header(tmp_path):
    lines = _write_key_file(tmp_path)
    middle = next(i for i, line in enumerate(lines, 1) if line == PEM_BODY[3])
    for center in range(middle - 1, middle + 2):
        snippet = make_snippet(tmp_path, "key.py", center, center, set())
        assert snippet is not None
        assert all(part not in snippet for part in PEM_BODY), snippet
    assert all(
        part not in (flagged_text(tmp_path, "key.py", middle, middle, set()) or "")
        for part in PEM_BODY
    )


def test_an_unterminated_pem_block_masks_to_the_end_of_the_file(tmp_path):
    lines = ["a = 1", pem_block()[0], *PEM_BODY, "tail = 2"]
    (tmp_path / "k.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
    snippet = make_snippet(tmp_path, "k.py", 6, 6, set())
    assert all(part not in snippet for part in PEM_BODY)


def test_code_around_a_pem_block_stays_readable(tmp_path):
    _write_key_file(tmp_path)
    snippet = make_snippet(tmp_path, "key.py", 1, 1, set())
    assert "import os" in snippet


# ---------------------------------------------------------------- flagged Gitleaks lines


def test_unknown_shape_in_a_flagged_line_is_masked_because_the_whole_range_is():
    odd = "~~weird-format-" + "Nq5Ws8Ed2Rf6" + "~~"  # no regex knows this shape
    lines = [(4, "a = 1"), (5, f"vault = '{odd}'"), (6, "b = 2")]
    out = dict(mask_lines(lines, {5}))
    assert odd not in out[5] and out[4] == "a = 1" and out[6] == "b = 2"


def test_flagged_range_also_protects_the_snippet_end_to_end(tmp_path):
    odd = "~~weird-format-" + "Nq5Ws8Ed2Rf6" + "~~"
    (tmp_path / "a.py").write_text(f"a = 1\nvault = '{odd}'\nb = 2\n", encoding="utf-8")
    assert odd in (tmp_path / "a.py").read_text(), "the unflagged line would have leaked"
    assert odd not in make_snippet(tmp_path, "a.py", 2, 2, {2})
    assert odd not in flagged_text(tmp_path, "a.py", 2, 2, {2})


# ---------------------------------------------------------------- bounds and speed


@pytest.mark.parametrize("cap", [10, 40, 200, 500])
def test_output_never_exceeds_the_cap(cap):
    hostile = " ".join(c.line for c in CANARIES) * 50
    assert len(mask_message(hostile, cap)) <= cap
    for _number, text in mask_lines([(1, hostile), (2, "x")], {2}, cap):
        assert len(text) <= cap


ADVERSARIAL = {
    "bearer flood": "Bearer " * 60_000,
    "scheme flood": "http://" * 60_000,
    "userinfo without at": "https://" + "a" * 400_000,
    "long token run": "Ab1" * 200_000,
    "long base64 run": ("Pq8Zx3Cv7Bn1" * 40_000) + "=",
    "assignment flood": "token=" * 60_000,
    "quote flood": "password = '" * 40_000,
    "begin flood": "-----BEGIN PRIVATE KEY-----" * 2_000,
    "zero width flood": "ab​" * 150_000,
}


@pytest.mark.parametrize("name", ADVERSARIAL)
def test_hostile_text_is_masked_in_linear_time(name):
    started = time.perf_counter()
    mask_message(ADVERSARIAL[name], 500)
    mask_lines([(1, ADVERSARIAL[name])], set(), 200)
    assert time.perf_counter() - started < 5, name


# ---------------------------------------------------------------- end to end: nothing survives in findings.json


def _bandit_sarif(message, source_line, line=3):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit", "version": "1.9.4", "rules": []}},
                "results": [
                    {
                        "ruleId": "B105",
                        "message": {"text": message},
                        "properties": {"issue_severity": "LOW", "issue_confidence": "MEDIUM"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {
                                        "startLine": line,
                                        "endLine": line,
                                        "snippet": {"text": source_line},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_no_canary_survives_the_normalized_export(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    raw = tmp_path / "raw"
    raw.mkdir()
    exported = []
    for canary in CANARIES:
        (source / "a.py").write_text(f"x = 1\ny = 2\n{canary.line}\nz = 3\n", encoding="utf-8")
        message = f"Possible hardcoded secret: {canary.line}"
        (raw / "bandit.sarif").write_text(json.dumps(_bandit_sarif(message, canary.line)))
        audit = normalize_audit(raw, manifest=None, source_root=source)
        assert len(audit.findings) == 1, canary.name
        exported.append((canary, export_json(audit)))
    for canary, text in exported:
        assert canary.core not in text, canary.name
