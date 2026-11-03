"""Phase 2B Task 2: schema export and the self-contained, inert HTML report."""

from __future__ import annotations

import base64
import hashlib
import html as htmllib
import re
from pathlib import Path

import pytest

from secaudit.core import evaluation, schema_export
from secaudit.core.models import (
    Audit,
    RawRef,
    SecurityFinding,
    Severity,
    SkippedFile,
    ToolCoverage,
    ToolHit,
    ToolRun,
)
from secaudit.core.normalize.pipeline import normalize_audit_dir
from secaudit.report import render as render_module
from secaudit.report import render_html
from secaudit.report.render import related_informational_items
from store_helpers import make_audit_dir

ROOT = Path(__file__).resolve().parent.parent
TRUTH = ROOT / "benchmarks" / "expected_findings.yaml"
TEMPLATE = ROOT / "src" / "secaudit" / "report" / "templates" / "report.html.j2"


@pytest.fixture(scope="module")
def baseline_audit(tmp_path_factory) -> Audit:
    return normalize_audit_dir(make_audit_dir(tmp_path_factory.mktemp("audits")))


def hostile_audit(
    path='dir/<script>alert("p")</script>.py',
    title="<img src=x onerror=alert(1)>",
    snippet="&amp; <script>alert('s')</script> &lt;b&gt; </pre><h1>x</h1>",
    finding_id='F-"><script>alert(2)</script>',
) -> Audit:
    ref = RawRef(artifact="raw/bandit.sarif", artifact_sha256="a" * 64, pointer="/runs/0/results/0")
    hit = ToolHit(
        tool="bandit", rule_id="B<b>1", message="<script>alert(3)</script> &copy;",
        file_path=path, line_start=3, line_end=3, raw_ref=ref, rule_name="<i>name</i>",
    )  # fmt: skip
    finding = SecurityFinding(
        id=finding_id, fingerprint="f" * 8, fingerprint_basis="content", title=title,
        issue_class="rule:bandit:B<b>1", file_path=path, line_start=3, line_end=3, hits=(hit,),
        severity=Severity.HIGH, severity_basis="bandit as emitted", snippet=snippet,
    )  # fmt: skip
    return Audit(
        audit_id="20261103T000000Z-deadbeef",
        input={"kind": "directory", "source": "<script>alert(4)</script>"},
        neutralized_files=(".bandit", 'x/<script>alert(5)</script>/.semgrepignore'),
        warnings=("<script>alert(6)</script>",),
        tool_runs=(ToolRun(tool="bandit", status="completed", version="<b>1</b>"),),
        coverage=(
            ToolCoverage(
                tool="semgrep", status="known", analyzed_files=("a.py",),
                skipped_files=(SkippedFile(path="<script>alert(7)</script>.py", reason="<b>big</b>"),),
                limitations=("<script>alert(8)</script>",), note="<script>alert(9)</script>",
            ),
        ),
        findings=(finding,),
    )  # fmt: skip


# ---------------------------------------------------------------- schema export


def test_the_committed_json_schema_matches_the_models():
    committed = (schema_export.DEFAULT_DIR / schema_export.SCHEMA_FILENAME).read_text("utf-8")
    assert committed == schema_export.render_schema(), (
        "models changed: run `uv run python -m secaudit.core.schema_export` and commit docs/schema/"
    )


def test_schema_describes_the_real_export_and_forbids_extra_fields():
    schema = schema_export.audit_schema()
    assert schema["additionalProperties"] is False and "findings" in schema["properties"]
    assert schema["$defs"]["SecurityFinding"]["properties"]["hits"]["minItems"] == 1
    assert schema["$defs"]["ToolHit"]["additionalProperties"] is False
    assert "snippet" not in schema["$defs"]["ToolHit"]["properties"], "hits never carry code text"


def test_schema_export_is_deterministic(tmp_path):
    first = schema_export.write_schema(tmp_path).read_text("utf-8")
    assert schema_export.write_schema(tmp_path).read_text("utf-8") == first


# ---------------------------------------------------------------- the report itself


def test_report_has_every_required_section_for_the_baseline(baseline_audit):
    html = render_html(baseline_audit)
    for heading in (
        "<h2>Summary</h2>", "<h2>Scan coverage &amp; limitations</h2>", "<h2>Findings</h2>",
        "<h2>Evidence</h2>", "<h2>Related informational</h2>", "<h2>Warnings and skipped results</h2>",
        "<h2>Notices</h2>", "OWASP Top 10:2025",
    ):  # fmt: skip
        assert heading in html, heading
    assert html.count('<details id="finding-') == len(baseline_audit.findings) == 25
    assert "Gitleaks' built-in default config has a path allowlist" in html.replace("&#39;", "'")
    assert "semgrep: coverage known" in html and "bandit: coverage unknown" in html


def test_report_is_deterministic_and_plain_ascii_safe(baseline_audit):
    assert render_html(baseline_audit) == render_html(baseline_audit)


def test_report_is_fully_self_contained(baseline_audit):
    html = render_html(baseline_audit)
    for forbidden in (
        "<script",
        "<link",
        "<img",
        "<iframe",
        "<object",
        "<embed",
        "@import",
        "url(",
    ):
        assert forbidden not in html, forbidden
    assert not re.search(r'(?:src|href|action|poster)="(?:https?:)?//', html)
    assert not re.search(r"\son[a-z]+=", html), "no inline event handlers"
    assert " style=" not in html, "inline style attributes would need a CSP relaxation"


def test_csp_meta_is_present_and_pins_the_exact_stylesheet(baseline_audit):
    html = render_html(baseline_audit)
    meta = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', html)
    assert meta, "CSP meta tag missing"
    policy = htmllib.unescape(meta.group(1))  # what the browser sees after parsing
    assert "default-src 'none'" in policy and "script-src" not in policy
    assert "unsafe-inline" not in policy and "unsafe-eval" not in policy
    css = re.search(r"<style>(.*?)</style>", html, re.DOTALL).group(1)
    digest = base64.b64encode(hashlib.sha256(css.encode()).digest()).decode()
    assert f"style-src 'sha256-{digest}'" in policy
    assert render_module.style_hash() == f"sha256-{digest}"
    assert "base-uri 'none'" in policy and "form-action 'none'" in policy


def test_hostile_file_names_snippets_and_rule_text_render_inert():
    html = render_html(hostile_audit())
    assert "<script" not in html.lower().replace("&lt;script", "")
    assert "<img" not in html and "onerror=alert" not in html.replace(
        "&lt;img src=x onerror=alert", ""
    )
    assert "&lt;script&gt;alert(&#34;p&#34;)&lt;/script&gt;" in html, "file name escaped"
    assert "&amp;amp; &lt;script&gt;" in html, "an entity in the snippet is escaped, not decoded"
    assert "&lt;/pre&gt;&lt;h1&gt;x&lt;/h1&gt;" in html, "cannot break out of <pre>"
    assert '"><script>' not in html and "&#34;&gt;&lt;script&gt;alert(2)" in html, (
        "id escaped in attributes"
    )
    for n in range(3, 10):
        assert f"<script>alert({n})" not in html
    assert html.count("<h1>") == 1, "snippet text must not add real elements"


def test_one_info_notice_per_neutralized_scanner_config_file():
    html = render_html(hostile_audit())
    notices = re.findall(r"scanner configuration found in repository and neutralized", html)
    assert len(notices) == 2 and 'class="info"' in html
    clean = render_html(Audit(audit_id="20261103T000000Z-deadbeef"))
    assert "scanner configuration found in repository and neutralized" not in clean
    assert "No scanner configuration files were found" in clean


def test_skipped_files_are_listed_in_the_coverage_section(baseline_audit):
    html = render_html(hostile_audit())
    assert "1 file(s) NOT analysed" in html and "&lt;b&gt;big&lt;/b&gt;" in html
    assert "limitations" in html.lower()


def test_empty_audit_renders(baseline_audit):
    html = render_html(Audit())
    assert "no findings" in html and "(no audit id)" in html


def test_related_informational_section_needs_the_ground_truth(baseline_audit):
    without = render_html(baseline_audit)
    assert "No ground-truth labeling was supplied" in without
    items = related_informational_items(baseline_audit, evaluation.load_truth(TRUTH))
    assert {i["case"]: i["related_to"] for i in items} == {"R01": "P06", "R02": "P05"}
    html = render_html(baseline_audit, related=items)
    assert "Not detections and not false positives" in html and "R01" in html and "R02" in html
    assert "No ground-truth labeling was supplied" not in html


def test_template_never_disables_escaping_or_marks_input_safe():
    source = TEMPLATE.read_text("utf-8")
    assert not re.search(r"\|\s*safe|autoescape|Markup|\|\s*raw", source)
    assert render_module._environment().autoescape is True
    module_source = Path(render_module.__file__).read_text("utf-8")
    assert module_source.count("Markup(") == 1, "only the constant stylesheet is passed as markup"
