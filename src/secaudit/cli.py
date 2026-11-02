"""Command-line entry point: scan, build-images, rules update.

Exit codes: 0 scan completed (findings do NOT change the code); 2 usage error or refused native
run; 3 input rejected by intake; 4 one or more tools failed/timed out; 5 environment problem
(Docker unreachable, image or rules missing); 6 temporary files could not be removed;
1 unexpected internal error.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from secaudit import __version__
from secaudit.core import exe
from secaudit.core.intake import DEFAULT_LIMITS, CleanupError, IntakeError
from secaudit.core.rules import DEFAULT_RULESETS, RulesError, update_rules
from secaudit.core.sandbox import ResourceLimits, docker_available
from secaudit.core.scan import ScanEnvironmentError, ScanOptions, run_scan
from secaudit.core.scanners import TOOL_NAMES, SemgrepAdapter, build_adapters

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_INTAKE, EXIT_TOOLS, EXIT_ENV, EXIT_CLEANUP = (
    0,
    1,
    2,
    3,
    4,
    5,
    6,
)
NATIVE_WARNING = (
    "WARNING: --runner native executes scanner tools directly on this machine with NO sandbox. "
    "Scanned content is untrusted; only use this for code you trust."
)


def _tool_list(value: str) -> tuple[str, ...]:
    names = tuple(v.strip() for v in value.split(",") if v.strip())
    unknown = [n for n in names if n not in TOOL_NAMES]
    if unknown or not names:
        raise argparse.ArgumentTypeError(f"choose from: {', '.join(TOOL_NAMES)}")
    return names


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secaudit", description="Multi-agent security audit.")
    parser.add_argument("--version", action="version", version=f"secaudit {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="run the scanners against a directory, ZIP or https Git URL")
    scan.add_argument("input", help="directory, .zip file, or https:// Git URL")
    scan.add_argument("--tools", type=_tool_list, default=TOOL_NAMES, metavar="LIST",
                      help=f"comma-separated subset of: {','.join(TOOL_NAMES)}")  # fmt: skip
    scan.add_argument(
        "--out", type=Path, default=Path("audits"), help="output root (default: ./audits)"
    )
    scan.add_argument("--runner", choices=("docker", "native"), default="docker")
    scan.add_argument("--i-trust-this-code", action="store_true",
                      help="required for --runner native (no isolation)")  # fmt: skip
    scan.add_argument("--include-git", action="store_true", help="copy .git from a local directory")
    scan.add_argument("--rules-dir", type=Path, default=None, help="Semgrep rules cache directory")
    scan.add_argument("--allow-git-host", action="append", default=[], metavar="HOST",
                      help="additional Git host to allow (repeatable)")  # fmt: skip
    scan.add_argument("--timeout", type=float, default=ResourceLimits().timeout_s,
                      help="per-tool wall-clock timeout in seconds")  # fmt: skip

    build = sub.add_parser("build-images", help="build the pinned scanner Docker images")
    build.add_argument("--tools", type=_tool_list, default=TOOL_NAMES, metavar="LIST")
    build.add_argument(
        "--docker-dir", type=Path, default=Path(__file__).resolve().parents[2] / "docker"
    )

    rules = sub.add_parser("rules", help="manage the Semgrep rules cache")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    update = rules_sub.add_parser("update", help="download rulesets (network on, no code present)")
    update.add_argument("--rules-dir", type=Path, default=None)
    update.add_argument(
        "--ruleset",
        action="append",
        default=None,
        metavar="p/NAME",
        help="ruleset to fetch (repeatable; default: " + " ".join(DEFAULT_RULESETS) + ")",
    )
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    if args.runner == "native":
        if not args.i_trust_this_code:
            print(
                "error: --runner native runs scanners with no isolation and requires "
                "--i-trust-this-code.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        print(NATIVE_WARNING, file=sys.stderr)
    limits = DEFAULT_LIMITS
    if args.allow_git_host:
        limits = replace(
            limits, git_allowed_hosts=limits.git_allowed_hosts | frozenset(args.allow_git_host)
        )
    options = ScanOptions(
        out_root=args.out,
        tools=args.tools,
        runner=args.runner,
        limits=limits,
        include_git=args.include_git,
        rules_dir=args.rules_dir,
        resource_limits=ResourceLimits(timeout_s=args.timeout),
    )
    try:
        outcome = run_scan(args.input, options)
    except IntakeError as exc:
        print(f"input rejected [{exc.reason.value}]: {exc.detail}", file=sys.stderr)
        return EXIT_INTAKE
    except ScanEnvironmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ENV
    except CleanupError as exc:
        print(f"cleanup failed, delete these leftovers manually: {exc}", file=sys.stderr)
        return EXIT_CLEANUP
    manifest = outcome.manifest
    print(f"audit {manifest['audit_id']} -> {outcome.audit_dir.as_posix()}")
    for name in manifest["tool_order"]:
        tool = manifest["tools"][name]
        extra = f" ({tool['detail']})" if tool["detail"] else ""
        print(
            f"  {name:10} {tool['status']:9} exit={tool['exit_code']}  {tool['duration_s']}s{extra}"
        )
    return EXIT_OK if outcome.tools_ok else EXIT_TOOLS


def _cmd_build_images(args: argparse.Namespace) -> int:
    ok, detail = docker_available()
    if not ok:
        print(
            f"error: Docker daemon is not reachable ({detail}). Start Docker Desktop.",
            file=sys.stderr,
        )
        return EXIT_ENV
    status = EXIT_OK
    for adapter in build_adapters(args.tools, None):
        context = args.docker_dir / adapter.name
        if not (context / "Dockerfile").is_file():
            print(f"error: no Dockerfile in {context}", file=sys.stderr)
            return EXIT_ENV
        print(f"building {adapter.image} ...", flush=True)
        done = exe.run(
            ["docker", "build", "--quiet", "-t", adapter.image, str(context)],
            capture_output=True, text=True, check=False, stdin=subprocess.DEVNULL,
        )  # fmt: skip
        if done.returncode != 0:
            print(done.stderr[-1500:], file=sys.stderr)
            print(f"error: build of {adapter.image} failed", file=sys.stderr)
            status = EXIT_ENV
        else:
            print(f"  built {adapter.image}")
    return status


def _cmd_rules_update(args: argparse.Namespace) -> int:
    ok, detail = docker_available()
    if not ok:
        print(
            f"error: Docker daemon is not reachable ({detail}). Start Docker Desktop.",
            file=sys.stderr,
        )
        return EXIT_ENV
    semgrep = SemgrepAdapter(None)
    try:
        cache = update_rules(
            image=semgrep.image,
            cache_dir=args.rules_dir,
            rulesets=tuple(args.ruleset or DEFAULT_RULESETS),
            semgrep_version=semgrep.version,
        )
    except RulesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ENV
    print(f"rules snapshot {cache.fetch_id} at {cache.path.as_posix()}")
    for r in cache.rulesets:
        print(f"  {r['ruleset']:20} {r['bytes']:>9} bytes  sha256 {r['sha256'][:16]}...")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    # Defence in depth (review #1): ask Windows not to search the cwd for programs. The real
    # protection is core.exe, which resolves every program to a trusted absolute path.
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "build-images":
            return _cmd_build_images(args)
        if args.command == "rules":
            return _cmd_rules_update(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR
    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
