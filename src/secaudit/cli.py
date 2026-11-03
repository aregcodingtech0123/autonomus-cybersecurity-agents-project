"""Command-line entry point: scan, build-images, rules update.

Exit codes: 0 scan completed (findings do NOT change the code); 2 usage error or refused native
run; 3 input rejected by intake; 4 one or more tools failed/timed out; 5 environment problem
(Docker unreachable, image or rules missing); 6 temporary files could not be removed;
1 unexpected internal error.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import traceback
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from secaudit import __version__
from secaudit.core import evaluation, exe
from secaudit.core.executors import reap_stale_containers
from secaudit.core.intake import DEFAULT_LIMITS, CleanupError, IntakeError
from secaudit.core.normalize.pipeline import export_json, normalize_audit, normalize_audit_dir
from secaudit.core.rules import DEFAULT_RULESETS, RulesError, update_rules
from secaudit.core.sandbox import ResourceLimits, docker_available
from secaudit.core.scan import ScanEnvironmentError, ScanOptions, run_scan
from secaudit.core.scanners import TOOL_NAMES, SemgrepAdapter, build_adapters

REPO_ROOT = Path(__file__).resolve().parents[2]
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


def log_directory() -> Path:
    """Where tracebacks of unexpected errors are written (git-ignored state directory)."""
    return Path(os.environ.get("SECAUDIT_LOG_DIR") or Path(".secaudit") / "logs")


def _internal_error(exc: BaseException, debug: bool) -> int:
    """Print one sanitized line (type only; messages can hold host paths) and log the traceback."""
    trace = "".join(traceback.format_exception(exc))
    shown = "the log could not be written"
    try:
        directory = log_directory()
        directory.mkdir(parents=True, exist_ok=True)
        log = directory / f"secaudit-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}.log"
        log.write_text(trace, encoding="utf-8", newline="\n")
        # Only a relative directory is shown: an absolute one would put host paths on the terminal.
        where = "" if directory.is_absolute() else f" in {directory.as_posix()}"
        shown = f"details in {log.name}{where}"
    except OSError:
        pass
    print(
        f"error: internal error ({type(exc).__name__}); {shown}. "
        "Re-run with --debug to print the traceback.",
        file=sys.stderr,
    )
    if debug:
        print(trace, file=sys.stderr)
    return EXIT_ERROR


def _tool_list(value: str) -> tuple[str, ...]:
    names = tuple(v.strip() for v in value.split(",") if v.strip())
    unknown = [n for n in names if n not in TOOL_NAMES]
    if unknown or not names:
        raise argparse.ArgumentTypeError(f"choose from: {', '.join(TOOL_NAMES)}")
    return names


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secaudit", description="Multi-agent security audit.")
    parser.add_argument("--version", action="version", version=f"secaudit {__version__}")
    parser.add_argument(
        "--debug", action="store_true", help="print tracebacks of unexpected errors"
    )
    sub = parser.add_subparsers(dest="command")
    # Accept --debug after the subcommand too, without overriding a value given before it.
    debug_parent = argparse.ArgumentParser(add_help=False)
    debug_parent.add_argument(
        "--debug", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )

    scan = sub.add_parser(
        "scan",
        parents=[debug_parent],
        help="run the scanners against a directory, ZIP or https Git URL",
    )
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

    build = sub.add_parser(
        "build-images", parents=[debug_parent], help="build the pinned scanner Docker images"
    )
    build.add_argument("--tools", type=_tool_list, default=TOOL_NAMES, metavar="LIST")
    build.add_argument(
        "--docker-dir", type=Path, default=Path(__file__).resolve().parents[2] / "docker"
    )

    rules = sub.add_parser("rules", parents=[debug_parent], help="manage the Semgrep rules cache")
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
    norm = sub.add_parser(
        "normalize",
        parents=[debug_parent],
        help="turn an audit directory's raw outputs into de-duplicated, secret-free findings.json",
    )
    norm.add_argument("audit_dir", type=Path, help="directory written by `secaudit scan`")
    norm.add_argument("--out", type=Path, default=None, help="default: <audit_dir>/findings.json")

    ev = sub.add_parser(
        "eval",
        parents=[debug_parent],
        help="tool-only detection metrics from committed raw outputs (no Docker needed)",
    )
    ev.add_argument("--from-raw", type=Path, required=True, help="directory with the raw outputs")
    ev.add_argument("--source", type=Path, required=True, help="the scanned source tree")
    ev.add_argument(
        "--ground-truth", type=Path, default=REPO_ROOT / "benchmarks" / "expected_findings.yaml"
    )
    ev.add_argument(
        "--exclude", action="append", default=[], metavar="ID", help="drop a case (repeatable)"
    )
    ev.add_argument("--out-dir", type=Path, default=None, help="default: the parent of --from-raw")
    return parser


def _cmd_normalize(args: argparse.Namespace) -> int:
    audit_dir = args.audit_dir
    if not (audit_dir / "raw").is_dir():
        print("error: not an audit directory (no raw/ inside)", file=sys.stderr)
        return EXIT_USAGE
    audit = normalize_audit_dir(audit_dir)
    out = args.out or audit_dir / "findings.json"
    out.write_text(export_json(audit), encoding="utf-8", newline="\n")
    raw_total = sum(r.raw_results for r in audit.tool_runs)
    print(f"{len(audit.findings)} findings from {raw_total} raw results -> {out.name}")
    for run in audit.tool_runs:
        counts = f"raw={run.raw_results} unique={run.unique_hits} skipped={run.skipped_results}"
        print(f"  {run.tool:10} {run.status:10} {counts}")
    for warning in audit.warnings:
        print(f"  warning: {warning}", file=sys.stderr)
    return EXIT_OK


def _cmd_eval(args: argparse.Namespace) -> int:
    raw, source = args.from_raw, args.source
    for label, path in (
        ("--from-raw", raw),
        ("--source", source),
        ("--ground-truth", args.ground_truth),
    ):
        if not path.exists():
            print(f"error: {label} path does not exist", file=sys.stderr)
            return EXIT_USAGE
    truth = evaluation.load_truth(args.ground_truth)
    for case_id in evaluation.ensure_generated(truth, REPO_ROOT, source):
        print(f"generated the benchmark file for {case_id}")
    manifest_path = raw.parent / "manifest.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else None
    )
    audit = normalize_audit(raw, manifest=manifest, source_root=source)
    metrics = evaluation.evaluate(
        audit,
        truth,
        manifest=manifest,
        exclude=tuple(args.exclude),
        inputs={"ground_truth_sha256": evaluation.sha256_file(args.ground_truth)},
    )
    out_dir = args.out_dir or raw.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics_tool_only.json").write_text(
        evaluation.metrics_json(metrics), encoding="utf-8", newline="\n"
    )
    (out_dir / "metrics_tool_only.md").write_text(
        evaluation.render_markdown(metrics), encoding="utf-8", newline="\n"
    )
    s = metrics["summary"]
    pos, neg, fnd = s["positives"], s["negatives"], s["findings"]
    missed = ", ".join(pos["missed"]) or "none"
    print(f"positives detected {pos['detected']}/{pos['total']} (missed: {missed})")
    flagged = ", ".join(neg["flagged"]) or "none"
    print(f"negatives flagged  {len(neg['flagged'])}/{neg['total']} ({flagged})")
    print(f"findings {fnd['total']} from {fnd['raw_results']} raw; {fnd['unlabeled']} unlabeled")
    print(f"wrote metrics_tool_only.json/.md to {out_dir.name}")
    return EXIT_OK


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
    reap_stale_containers()
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
        if args.command == "normalize":
            return _cmd_normalize(args)
        if args.command == "eval":
            return _cmd_eval(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - last line of defence: no traceback, no host paths
        return _internal_error(exc, bool(getattr(args, "debug", False)))
    parser.print_help()
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
