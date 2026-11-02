"""Gitleaks adapter: working tree only (no git history), SARIF, secrets redacted on disk."""

from secaudit.core.scanners.base import ScannerAdapter, ToolPaths


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    version = "8.30.1"
    output_filename = "gitleaks.sarif"
    artifact_kind = "sarif"
    limitations = (
        "Gitleaks' built-in default config has a path allowlist: secrets under node_modules/, "
        "in lock files (go.sum, package-lock.json, poetry.lock), and in .svg and .pdf files "
        "were NOT reported (verified in the Phase 1 review, 2026-11-03). The config was "
        "deliberately not rewritten in Phase 1.",
        "Binary files are not scanned (verified 2026-11-03).",
        "Working tree only: git history is never scanned (.git is excluded from the workspace).",
    )

    def version_command(self) -> list[str]:
        return ["gitleaks", "version"]

    def build_command(self, paths: ToolPaths) -> list[str]:
        command = [
            "gitleaks", "dir", ".",
            "--report-format", "sarif",
            "--report-path", paths.out_file(self.output_filename),
            "--redact",  # raw secrets are never written to disk
            "--no-banner",
            "--ignore-gitleaks-allow",  # 'gitleaks:allow' comments must not hide findings
        ]  # fmt: skip
        if paths.sandboxed:
            # Scanned content must not supply its own config or ignore file.
            command += [
                "--config",
                "/opt/gitleaks.toml",
                "--gitleaks-ignore-path",
                "/opt/no-ignore",
            ]
        return command
