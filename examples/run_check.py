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
    parser.add_argument("--check", default="headers", help="which check to run (default: headers)")
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

    if args.check not in checker.checks:
        known = ", ".join(checker.checks)
        print(f"error: unknown check {args.check!r}; available: {known}", file=sys.stderr)
        return 2

    print(f"check   {args.check}")
    print(f"target  {args.target}")
    print(f"model   {args.model}")
    print(f"scope   {args.scope or [args.target]}\n")
    print("running (one model call per turn, a few seconds)...\n")

    result = checker.run(args.check, args.target)

    print(summary_line(result), "\n")

    if result.findings:
        print("FINDINGS")
        for finding in result.findings:
            print(f"  {SEVERITY_MARK[finding.severity]}  {finding.title}")
            print(f"        where      {finding.location}")
            print(f"        evidence   {finding.evidence}")
            print(f"        fix        {finding.remediation}")
            print(f"        rests on   {', '.join(finding.tool_refs) or '-'}")

    if result.errors:
        print("\nERRORS")
        for error in result.errors:
            code = f" [{error.code}]" if error.code else ""
            where = f" ({error.tool})" if error.tool else ""
            print(f"  {error.kind}{code}{where}: {error.message}")

    if result.trace:
        print("\nTRACE")
        for step in result.trace:
            took = f"  {step.duration_ms} ms" if step.duration_ms is not None else ""
            print(
                f"  {step.id:4} {step.kind:13} {step.name:24} {step.status:9} {step.summary}{took}"
            )

    if args.json_path:
        print(f"\nJSON  -> {write_json(result, args.json_path)}")
    if args.sarif_path:
        print(f"SARIF -> {write_sarif(result, args.sarif_path)}")

    # `failed` is the only outcome that means the SDK could not do its job.
    # `issues_found` is a working run that found problems, which is a
    # success for this tool and a failure for the target.
    return 1 if result.status == "failed" else 0


if __name__ == "__main__":
    sys.exit(main())
