"""One full agent run.  Needs model credentials.

    python examples/run_check.py https://example.com
    python examples/run_check.py https://example.com --check headers --trace full
    python examples/run_check.py https://example.com --json report.json --sarif report.sarif

The whole turn diagram end to end: the public API validates the scope, the
runner builds an agent from the `Check`, the MCP server comes up, the policy
hooks ride along, and a typed `CheckResult` comes back - for a caller who
wrote no prompt and imported no agent framework.

Reads `.env` for `OPENAI_API_KEY` so the demo is one command.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from websecuritycheck import SecurityChecker
from websecuritycheck.results.export import summary_line, write_json, write_sarif

REPO_ROOT = Path(__file__).resolve().parent.parent

SEVERITY_MARK = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def load_env(path: Path = REPO_ROOT / ".env") -> None:
    """Read `KEY=value` lines into the environment, without overwriting it.

    Deliberately not a dependency: the file has one key in it, and a
    library to parse that is a library to keep up to date.
    """
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="the http(s) URL to check")
    parser.add_argument(
        "--check",
        default="all",
        help="which check to run, or 'all' for every registered one (default: all)",
    )
    parser.add_argument(
        "--scope",
        action="append",
        help="scope entry; repeatable. Defaults to the target itself.",
    )
    parser.add_argument("--subdomains", action="store_true", help="allow subdomains of the scope")
    parser.add_argument("--model", default="openai:gpt-4o-mini", help="provider:model-id")
    parser.add_argument(
        "--trace", default="summary", choices=["off", "summary", "full"], help="trace detail"
    )
    parser.add_argument("--json", dest="json_path", help="write the result as JSON")
    parser.add_argument("--sarif", dest="sarif_path", help="write the result as SARIF 2.1.0")
    return parser.parse_args()


def main() -> int:
    load_env()
    args = parse_args()

    try:
        checker = SecurityChecker(
            model=args.model,
            scope=args.scope or [args.target],
            allow_subdomains=args.subdomains,
            trace_level=args.trace,
        )
    except ValueError as exc:  # a bad scope is the caller's mistake, not a crash
        print(f"error: {exc}", file=sys.stderr)
        return 2

    wanted = list(checker.checks) if args.check == "all" else [args.check]
    unknown = [name for name in wanted if name not in checker.checks]
    if unknown:
        known = ", ".join(checker.checks)
        print(f"error: unknown check {unknown[0]!r}; available: {known}, all", file=sys.stderr)
        return 2

    print(f"check   {', '.join(wanted)}")
    print(f"target  {args.target}")
    print(f"model   {args.model}")
    print(f"scope   {args.scope or [args.target]}\n")
    print(f"running {len(wanted)} check(s), a few seconds each...\n")

    results = []
    for name in wanted:
        result = checker.run(name, args.target)
        results.append(result)
        report(result, trace=args.trace != "off")

    if len(results) > 1:
        overview(results)

    if args.json_path:
        print(f"\nJSON  -> {write_json(results, args.json_path)}")
    if args.sarif_path:
        print(f"SARIF -> {write_sarif(results, args.sarif_path)}")

    # `failed` is the only outcome that means the SDK could not do its job.
    # `issues_found` is a working run that found problems, which is a
    # success for this tool and a failure for the target.
    return 1 if any(r.status == "failed" for r in results) else 0


def report(result, *, trace: bool) -> None:
    """One check, in full."""
    print(f"{'=' * 78}\n{summary_line(result)}\n{'=' * 78}")

    for finding in result.findings:
        print(f"  {SEVERITY_MARK[finding.severity]}  {finding.title}")
        print(f"        where      {finding.location}")
        print(f"        evidence   {finding.evidence[:300]}")
        print(f"        rests on   {', '.join(finding.tool_refs) or '-'}")

    if result.errors:
        print("  ERRORS")
        for error in result.errors:
            code = f" [{error.code}]" if error.code else ""
            where = f" ({error.tool})" if error.tool else ""
            print(f"    {error.kind}{code}{where}: {error.message}")

    if trace and result.trace:
        print("  TRACE")
        for step in result.trace:
            took = f"  {step.duration_ms} ms" if step.duration_ms is not None else ""
            print(f"    {step.id:4} {step.kind:13} {step.name:22} {step.status:9}{took}")
    print()


def overview(results) -> None:
    """The scan as one thing.

    `check_all` returns a list today, so this is the merge done in the
    example rather than in the SDK. The status line is the honest one: a
    scan where a check failed has not covered the site, however clean the
    checks that did run came back.
    """
    counts: dict[str, int] = {}
    for result in results:
        for finding in result.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

    failed = [r.check for r in results if r.status == "failed"]
    partial = [r.check for r in results if r.status == "partial"]
    total = sum(counts.values())

    print(f"{'=' * 78}\nSCAN SUMMARY\n{'=' * 78}")
    for check in results:
        print(f"  {check.check:10} {check.status:13} {len(check.findings)} finding(s)")
    print()
    if total:
        order = ["critical", "high", "medium", "low", "info"]
        print("  " + " | ".join(f"{counts[s]} {s}" for s in order if s in counts))
    else:
        print("  no findings")

    if failed:
        print(f"\n  INCOMPLETE: {', '.join(failed)} could not run. The site is not fully checked.")
    elif partial:
        print(f"\n  PARTIAL: {', '.join(partial)} hit an error while running.")


if __name__ == "__main__":
    sys.exit(main())
