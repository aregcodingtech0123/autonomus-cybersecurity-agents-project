"""Command-line entry point (stub: only `--version` for now)."""

import argparse
from collections.abc import Sequence

from secaudit import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secaudit", description="Multi-agent security audit.")
    parser.add_argument("--version", action="version", version=f"secaudit {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    return 0
