"""Phase 2C-A: benchmarks/CASES.md is exactly what its generator produces from the ground truth."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

BENCH = Path(__file__).resolve().parent.parent / "benchmarks"
EXPANSION = BENCH / "expected_findings_expansion.yaml"
CATALOGUE = BENCH / "CASES.md"


@pytest.fixture(scope="module")
def generator():
    spec = importlib.util.spec_from_file_location("gen_cases_md", BENCH / "gen_cases_md.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def doc():
    return yaml.safe_load(EXPANSION.read_text(encoding="utf-8"))


def test_committed_catalogue_equals_generated_output(generator):
    assert CATALOGUE.read_bytes() == generator.generate().encode("utf-8")


def test_catalogue_uses_lf_newlines():
    assert b"\r" not in CATALOGUE.read_bytes()


def test_catalogue_lists_every_case_and_no_canary(generator, doc):
    text = generator.generate()
    for case in doc["cases"]:
        assert f"| {case['id']} |" in text
        if case.get("canary"):
            assert case["canary"] not in text


def test_catalogue_output_does_not_depend_on_case_order(generator, doc):
    copy = json.loads(json.dumps(doc))
    copy["cases"].reverse()
    assert generator.render(copy) == generator.render(doc)
