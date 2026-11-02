"""Bandit adapter: SARIF output."""

from secaudit.core.scanners.base import ScannerAdapter, ToolPaths


class BanditAdapter(ScannerAdapter):
    name = "bandit"
    version = "1.9.4"
    output_filename = "bandit.sarif"
    artifact_kind = "sarif"

    def build_command(self, paths: ToolPaths) -> list[str]:
        return [
            "bandit", "-r", ".", "-f", "sarif", "-o", paths.out_file(self.output_filename),
            "--ignore-nosec",  # '# nosec' comments in scanned code must not hide findings
        ]  # fmt: skip
