"""Semgrep adapter: SARIF, rules from a local read-only cache, no network during the scan."""

from pathlib import Path

from secaudit.core.rules import RulesCache
from secaudit.core.scanners.base import (
    AdapterUnavailable,
    Prepared,
    ScannerAdapter,
    ToolPaths,
)

# Semgrep skips tests/ and similar paths via a built-in default ignore list UNLESS the project
# root contains a .semgrepignore file. The workspace gets a neutral one (see orchestrator), which
# also stops scanned code from shipping an ignore file that hides its own findings.
SEMGREPIGNORE_NAME = ".semgrepignore"
SEMGREPIGNORE_BODY = "# secaudit: scanned content must not control the scan scope\n"


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    version = "1.183.0"
    output_filename = "semgrep.sarif"
    artifact_kind = "sarif"
    # The JSON copy lists `paths.scanned`; it is the cheap source of Semgrep coverage data.
    extra_outputs = ("semgrep.json",)
    limitations = (
        "Files larger than 1,000,000 bytes (--max-target-bytes default) are skipped without "
        "any notification in the SARIF (verified 2026-11-03); parse errors, in contrast, are "
        "reported as notifications.",
        "Results depend on the pinned rules snapshot (names + SHA-256 in ruleset_info); "
        "coverage is only as broad as those rulesets.",
    )
    env = {"HOME": "/tmp", "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}  # noqa: RUF012

    def __init__(self, rules: RulesCache | None) -> None:
        self.rules = rules

    def prepare(self, workspace: Path, staging: Path) -> Prepared:
        if self.rules is None:
            raise AdapterUnavailable("no Semgrep rules cache; run `secaudit rules update` first")
        return Prepared(
            src_dir=workspace,
            rules_dir=self.rules.path,
            extra={"rules": self.rules.describe()},
        )

    def build_command(self, paths: ToolPaths) -> list[str]:
        assert self.rules is not None  # noqa: S101 - guaranteed by prepare()
        command = ["semgrep", "scan"]
        for filename in self.rules.files:
            command += ["--config", paths.rules_file(filename)]
        command += [
            "--metrics=off",
            "--disable-version-check",
            "--disable-nosem",  # '# nosemgrep' comments must not hide findings
            "--no-rewrite-rule-ids",
            "--quiet",
            f"--sarif-output={paths.out_file(self.output_filename)}",
            f"--json-output={paths.out_file(self.extra_outputs[0])}",
            ".",
        ]
        return command
