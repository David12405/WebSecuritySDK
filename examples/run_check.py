"""One full agent run.  Needs model credentials.

    python examples/run_check.py https://example.com
    python examples/run_check.py https://example.com --check headers --trace full
    python examples/run_check.py https://example.com --json report.json --sarif report.sarif
    python examples/run_check.py https://example.com --history h.db        # run twice to diff
    python examples/run_check.py https://example.com --check surface --target-store recon.db

The whole turn diagram end to end: the public API validates the scope, the
runner builds an agent from the `Check`, the MCP server comes up, the policy
hooks ride along, and a typed `CheckResult` comes back - for a caller who
wrote no prompt and imported no agent framework.

Reads `.env` for the provider key so the demo is one command.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import textwrap
from pathlib import Path

from websecuritycheck import SecurityChecker
from websecuritycheck.memory.target_store import SQLiteTargetStore
from websecuritycheck.results.export import summary_line, write_json, write_sarif

REPO_ROOT = Path(__file__).resolve().parent.parent


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
    parser.add_argument(
        "--judge",
        action="store_true",
        help="add the model-judged steering rule (costs a model call per round)",
    )
    parser.add_argument("--json", dest="json_path", help="write the result as JSON")
    parser.add_argument("--sarif", dest="sarif_path", help="write the result as SARIF 2.1.0")
    parser.add_argument(
        "--history",
        dest="history_db",
        help="SQLite path to record runs in and diff against; run twice to see the diff",
    )
    parser.add_argument(
        "--target-store",
        dest="target_store",
        help="SQLite path for the recon store: each tool call is journalled and the "
        "TargetModel (endpoints, technologies) is accumulated across runs",
    )
    parser.add_argument(
        "--assessment-id",
        dest="assessment_id",
        help="assessment id the recon store is keyed by, like 'ASMT-001' (default: ASMT-001)",
    )
    return parser.parse_args()


def main() -> int:
    load_env()
    args = parse_args()

    # The recon store turns on the ToolResultAdapter: every tool call is
    # journalled and fed to the recon pipeline, which accumulates a
    # TargetModel. It needs an assessment id to key by; default one so
    # `--target-store x.db` alone is enough. The id is a canonical domain id
    # (`^[A-Z]{2,}-[0-9]{3,}$`, e.g. ASMT-001), validated here rather than
    # deep in the adapter where it would fail every tool call mid-run.
    target_store = SQLiteTargetStore(args.target_store) if args.target_store else None
    assessment_id = args.assessment_id or ("ASMT-001" if target_store else None)
    if assessment_id is not None and not re.fullmatch(r"[A-Z]{2,}-[0-9]{3,}", assessment_id):
        print(
            f"error: --assessment-id {assessment_id!r} must look like 'ASMT-001' "
            "(two+ uppercase letters, a dash, three+ digits)",
            file=sys.stderr,
        )
        return 2

    try:
        checker = SecurityChecker(
            model=args.model,
            scope=args.scope or [args.target],
            allow_subdomains=args.subdomains,
            trace_level=args.trace,
            use_judge=args.judge,
            history_db=args.history_db,
            assessment_id=assessment_id,
            target_store=target_store,
        )
    except ValueError as exc:  # a bad scope is the caller's mistake, not a crash
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # "all" is the default scan, not every registered check: a parked check
    # runs only when someone asks for it by name.
    wanted = list(checker.scan_checks) if args.check == "all" else [args.check]
    unknown = [name for name in wanted if name not in checker.checks]
    if unknown:
        known = ", ".join(checker.checks)
        print(f"error: unknown check {unknown[0]!r}; available: {known}, all", file=sys.stderr)
        return 2

    parked = [name for name in checker.checks if name not in checker.scan_checks]
    if args.check == "all" and parked:
        print(f"note    not in a scan: {', '.join(parked)} (run by name to try one)\n")

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

    # What the recon pipeline accumulated into the TargetModel this run - the
    # half that is more than "run the tools": a map of the target that grows
    # across runs, keyed by assessment and target.
    if target_store is not None:
        recon_summary(target_store, assessment_id, args.target)
        target_store.close()

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
        print(f"  * {finding.title}")
        print(f"        where      {finding.location}")
        print(f"        evidence   {finding.evidence[:300]}")
        print(f"        rests on   {', '.join(finding.tool_refs) or '-'}")

    # After the findings, because it is context for them rather than a
    # headline - but printed always, including on a clean run. A check that
    # found nothing has still said what it looked at, and leaving that out
    # is what makes `passed` read as "did nothing".
    if result.notes:
        print("  NOTES")
        for line in textwrap.wrap(result.notes, width=72):
            print(f"    {line}")

    if result.errors:
        print("  ERRORS")
        for error in result.errors:
            code = f" [{error.code}]" if error.code else ""
            where = f" ({error.tool})" if error.tool else ""
            print(f"    {error.kind}{code}{where}: {error.message}")

    # Only present with --history, and only from the second run on - the first
    # run of a target and check has nothing to compare against.
    if result.diff is not None:
        diff = result.diff
        print(f"  DIFF (vs run {diff.previous_run_id})")
        for label, ids in (
            ("new", diff.new),
            ("fixed", diff.fixed),
            ("unchanged", diff.unchanged),
            ("unverified", diff.unverified),
        ):
            for finding_id in ids:
                # The title, not the id: "new 1a9bd79b152f" tells a reader
                # nothing, "new Missing CSP header" tells them what changed.
                print(f"    {label:11} {diff.label(finding_id)}")

    if trace and result.trace:
        print("  TRACE")
        for step in result.trace:
            took = f"  {step.duration_ms} ms" if step.duration_ms is not None else ""
            # The summary is the reason: which topic steering wanted, why a
            # call was refused. A trace that shows a step fired without
            # saying what over is a trace nobody can act on.
            why = f"  {step.summary}" if step.summary and step.summary != step.name else ""
            print(f"    {step.id:4} {step.kind:13} {step.name:22} {step.status:9}{took}{why}")
    print()


def recon_summary(store, assessment_id: str, target: str) -> None:
    """What the recon pipeline accumulated into the TargetModel.

    Reads the store back the same way the next run will: `load_target` by
    assessment and target. The key is the target as the tools received it,
    which for one URL is the URL itself; we try that, then fall back to
    whatever targets the assessment recorded, so a canonicalized key still
    shows.
    """
    model = store.load_target(assessment_id, target)
    if model is None:
        # The tools may have stored the target under a canonicalized key.
        rows = store._connection.execute(
            "SELECT canonical_target FROM targets WHERE assessment_id = ?", (assessment_id,)
        ).fetchall()
        for row in rows:
            model = store.load_target(assessment_id, row[0])
            if model is not None:
                target = row[0]
                break

    revision = model.revision if model else 0
    print(f"\n{'=' * 78}\nRECON (TargetModel, revision {revision})\n{'=' * 78}")
    if model is None:
        print("  nothing accumulated — no tool call produced recon data this run")
        return

    print(f"  target      {target}")
    print(f"  technologies {len(model.technologies)}")
    for tech in model.technologies:
        version = f" {tech.version}" if getattr(tech, "version", "") else ""
        print(f"    - {tech.name}{version}  ({tech.category})")
    print(f"  endpoints    {len(model.endpoints)}")
    for ep in model.endpoints[:20]:
        print(f"    - {ep.method} {ep.origin}{ep.path}")
    if len(model.endpoints) > 20:
        print(f"    ... and {len(model.endpoints) - 20} more")


def overview(results) -> None:
    """The scan as one thing.

    `check_all` returns a list today, so this is the merge done in the
    example rather than in the SDK. The status line is the honest one: a
    scan where a check failed has not covered the site, however clean the
    checks that did run came back.
    """
    failed = [r.check for r in results if r.status == "failed"]
    partial = [r.check for r in results if r.status == "partial"]
    total = sum(len(r.findings) for r in results)

    print(f"{'=' * 78}\nSCAN SUMMARY\n{'=' * 78}")
    for check in results:
        print(f"  {check.check:10} {check.status:13} {len(check.findings)} finding(s)")
    print()
    # A count, not a severity breakdown. Findings carry no rating, so the
    # only honest headline is how many there are - and ranking them is the
    # reader's job, since they know what the target is for.
    print(f"  {total} finding(s) in total" if total else "  no findings")

    if failed:
        print(f"\n  INCOMPLETE: {', '.join(failed)} could not run. The site is not fully checked.")
    elif partial:
        print(f"\n  PARTIAL: {', '.join(partial)} hit an error while running.")


if __name__ == "__main__":
    sys.exit(main())
