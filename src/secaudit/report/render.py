"""HTML report: Jinja2 with autoescape ON, no JavaScript, no external resources, CSP via <meta>.

Everything shown comes from the normalized Audit (findings.json / manifest.json fields); raw
scanner files are never read here. Fields marked [UNTRUSTED] in core/models.py (paths, titles,
snippets, rule text) are scanned content: they are only ever interpolated by `{{ ... }}`
(escaped), never marked safe. The one piece of markup passed as-is is the stylesheet, a constant
of this module; its sha256 goes into the CSP, so the page needs neither 'unsafe-inline' nor a
script allowance.
"""

from __future__ import annotations

import base64
import hashlib
from collections import Counter
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined
from markupsafe import Markup

from secaudit.core.models import Audit, Severity
from secaudit.core.normalize.masking import ANSI, CONTROL
from secaudit.core.normalize.owasp import load_owasp_map

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
MAX_LISTED = 50

CSS = """
body { font: 14px/1.45 system-ui, sans-serif; margin: 2rem auto; max-width: 70rem;
  padding: 0 1rem; color: #1b1f24; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.15rem; margin-top: 2rem; border-bottom: 1px solid #d0d7de; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; }
th, td { border: 1px solid #d0d7de; padding: .25rem .5rem; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
code, pre { font: 12px/1.4 ui-monospace, monospace; }
pre { background: #f6f8fa; padding: .5rem; overflow-x: auto; white-space: pre-wrap;
  word-break: break-all; }
.sev { font-weight: 600; padding: 0 .35rem; border-radius: .25rem; }
.sev-critical, .sev-high { background: #ffd8d3; }
.sev-medium { background: #fff1c2; }
.sev-low { background: #dcefff; }
.sev-info, .sev-unknown { background: #eaeef2; }
.note { color: #57606a; }
.info { color: #0550ae; }
details { margin: .75rem 0; border: 1px solid #d0d7de; border-radius: .35rem;
  padding: .35rem .6rem; }
summary { cursor: pointer; font-weight: 600; }
""".strip()


def style_hash() -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode()


def csp() -> str:
    return (
        f"default-src 'none'; style-src '{style_hash()}'; img-src data:; "
        "base-uri 'none'; form-action 'none'"
    )


def _strip_controls(value: object) -> object:
    """Applied to every `{{ ... }}` before escaping: no ESC / control / invisible characters.

    HTML escaping does not neutralize them, and `secaudit report` may print the page to a terminal.
    """
    if isinstance(value, Markup) or not isinstance(value, str):
        return value
    return CONTROL.sub("", ANSI.sub("", value))


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=True,  # on for every template, whatever its extension
        undefined=StrictUndefined,
        finalize=_strip_controls,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def related_informational_items(audit: Audit, truth: dict) -> list[dict]:
    """Findings the benchmark ground truth labels `related_informational` (benchmark audits)."""
    from secaudit.core import evaluation

    metrics = evaluation.evaluate(audit, truth)
    by_id = {f.id: f for f in audit.findings}
    items = []
    for row in metrics["related_informational"]:
        if not row["reported"]:
            continue
        items.append(
            {
                "case": row["id"],
                "related_to": row["related_to"],
                "rules": row["rules"],
                "findings": [
                    {"id": fid, "file": by_id[fid].file_path, "line": by_id[fid].line_start}
                    for fid in row["findings"]
                ],
            }
        )
    return items


def build_context(audit: Audit, related: list[dict] | None) -> dict:
    owasp = load_owasp_map()
    findings = sorted(
        audit.findings, key=lambda f: (-f.severity.rank, f.file_path, f.line_start, f.id)
    )
    severity_counts = Counter(f.severity for f in audit.findings)
    tool_counts = Counter(t for f in audit.findings for t in f.tools)
    owasp_counts = Counter(f.owasp_2025 or "unmapped" for f in audit.findings)
    skipped = Counter((s.tool, s.reason) for s in audit.skipped_results)
    return {
        "css": Markup(CSS),  # noqa: S704 - a constant of this module, hashed into the CSP
        "csp": csp(),
        "audit": audit,
        "findings": findings,
        "total": len(audit.findings),
        "severities": [
            (sev.value, severity_counts[sev])
            for sev in sorted(Severity, key=lambda s: -s.rank)
            if severity_counts[sev]
        ],
        "tools": sorted(tool_counts.items()),
        "owasp": [
            (cid, owasp.names.get(cid, ""), n)
            for cid, n in sorted(owasp_counts.items(), key=lambda kv: (kv[0] == "unmapped", kv[0]))
        ],
        "skipped_counts": sorted((tool, reason, n) for (tool, reason), n in skipped.items()),
        "max_listed": MAX_LISTED,
        "related": related,
    }


def render_html(audit: Audit, *, related: list[dict] | None = None) -> str:
    """`related`: output of `related_informational_items` (None = no ground truth was supplied)."""
    template = _environment().get_template("report.html.j2")
    return template.render(**build_context(audit, related))
