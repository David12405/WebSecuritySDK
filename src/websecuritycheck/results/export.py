"""Report export - JSON and SARIF.

Two readers, two formats.

**JSON** is the result verbatim: every field of `CheckResult`, nothing
reshaped. Written for a human reading the file and for a script that wants
the SDK's own vocabulary.

**SARIF 2.1.0** is for CI. GitHub code scanning, Azure DevOps and most
quality gates read it, which is how a check becomes a pull-request comment
instead of a log line nobody opens.

Two things about the SARIF mapping are worth knowing before reading it.

*SARIF is file-oriented and we are not.* Its locations want a path and a line
number; ours are a URL and a header name. The target URL goes in
`artifactLocation.uri` and the header or cookie name becomes a
`logicalLocation`. Nothing is invented to fill the line-number slots.

*The trace is the point of `invocations`.* A CI gate that reads only
`results` cannot tell "we checked and found nothing" from "every probe timed
out", and would wave the second one through. So `executionSuccessful`
follows the run status, every `ErrorInfo` becomes a
`toolExecutionNotification`, and the trace rides along in the invocation's
property bag. A failed run is visible without opening a single result.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from .models import CheckResult, ErrorInfo, Finding, Severity, TraceStep

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

TOOL_NAME = "WebSecurityCheck"
TOOL_URI = "https://github.com/David12405/WebSecuritySDK"

#: SARIF has four levels and we have five severities, so `critical` and
#: `high` share `error`. The distinction survives in `security-severity`.
SARIF_LEVEL: dict[Severity, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

#: GitHub code scanning buckets this number: >=9.0 critical, >=7.0 high,
#: >=4.0 medium, >0 low. There is no informational bucket, so `info` lands at
#: the bottom of low rather than disappearing.
SECURITY_SEVERITY: dict[Severity, str] = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "5.0",
    "low": "3.0",
    "info": "1.0",
}

#: Namespaced so GitHub can tell our fingerprints from another tool's, and
#: versioned so changing how `stable_id` is derived does not silently merge
#: two different alert histories.
FINGERPRINT_KEY = "websecuritycheck/finding/v1"


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def to_json(result: CheckResult | Sequence[CheckResult], *, indent: int | None = 2) -> str:
    """The result as JSON, in the SDK's own vocabulary.

    A sequence is written as a JSON array, so `check_all()` output is one
    file rather than four.
    """
    if isinstance(result, CheckResult):
        return result.model_dump_json(indent=indent)
    payload = [json.loads(r.model_dump_json()) for r in result]
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def write_json(
    result: CheckResult | Sequence[CheckResult],
    path: str | Path,
    *,
    indent: int | None = 2,
) -> Path:
    destination = Path(path)
    destination.write_text(to_json(result, indent=indent), encoding="utf-8")
    return destination


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------


def to_sarif(result: CheckResult | Sequence[CheckResult]) -> dict[str, Any]:
    """A SARIF 2.1.0 log.

    One SARIF `run` per `CheckResult`: each check has its own invocation, its
    own trace and its own success, and flattening four checks into one run
    would lose which of them failed.
    """
    results = [result] if isinstance(result, CheckResult) else list(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [_run(r) for r in results],
    }


def write_sarif(result: CheckResult | Sequence[CheckResult], path: str | Path) -> Path:
    destination = Path(path)
    destination.write_text(
        json.dumps(to_sarif(result), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return destination


def _run(result: CheckResult) -> dict[str, Any]:
    return {
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": __version__,
                "informationUri": TOOL_URI,
                "rules": _rules(result.findings, result.check),
                "notifications": _notification_descriptors(result.errors),
            }
        },
        "automationDetails": {
            "id": f"{TOOL_NAME}/{result.check}/{result.run_id or 'unversioned'}",
            "description": {"text": f"{result.check} check of {result.target}"},
        },
        "invocations": [_invocation(result)],
        "results": [_result(f, result.target) for f in result.findings],
        "properties": {
            "check": result.check,
            "target": result.target,
            "status": result.status,
        },
    }


def _rules(findings: Sequence[Finding], check: str) -> list[dict[str, Any]]:
    """One `reportingDescriptor` per distinct finding id.

    Today a finding *is* its own rule: the checks have no rule catalog yet,
    so there is nothing more stable to key on than `Finding.id`. When the
    catalog lands this becomes one descriptor per rule, written once, and a
    run with three CSP findings stops declaring three rules.
    """
    seen: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.id in seen:
            continue
        seen[finding.id] = {
            "id": finding.id,
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": f"{finding.title} ({finding.location})"},
            # No `help`. SARIF viewers render it as the recommendation panel,
            # and this SDK reports what a target does without advising how to
            # change it. An empty panel is better than a guessed one.
            "defaultConfiguration": {"level": SARIF_LEVEL[finding.severity]},
            "properties": {
                "security-severity": SECURITY_SEVERITY[finding.severity],
                "tags": ["security", f"web/{check}"],
            },
        }
    return list(seen.values())


def _result(finding: Finding, target: str) -> dict[str, Any]:
    return {
        "ruleId": finding.id,
        "level": SARIF_LEVEL[finding.severity],
        "message": {"text": f"{finding.title} — {finding.evidence}"},
        "locations": [
            {
                "physicalLocation": {"artifactLocation": {"uri": target}},
                "logicalLocations": [
                    {
                        "name": finding.location,
                        "fullyQualifiedName": f"{target}#{finding.location}",
                    }
                ],
            }
        ],
        # What lets a CI gate follow one alert across runs instead of
        # reporting it as new every time. The same job `Finding.id` does in
        # `RunDiff`, handed to a tool that keeps its own history.
        "partialFingerprints": {FINGERPRINT_KEY: finding.id},
        "properties": {
            "severity": finding.severity,
            "evidence": finding.evidence,
            "toolRefs": finding.tool_refs,
        },
    }


def _invocation(result: CheckResult) -> dict[str, Any]:
    """The part a CI gate must read before trusting an empty `results` list.

    `executionSuccessful` is false for a `failed` run - no tool measured
    anything, or every error was fatal. A `partial` run did produce findings,
    so it stays true and carries its notifications; the status in the
    property bag is what distinguishes it from a clean pass.
    """
    invocation: dict[str, Any] = {
        "executionSuccessful": result.status != "failed",
        "toolExecutionNotifications": [_notification(e) for e in result.errors],
        "properties": {
            "status": result.status,
            "toolsRan": result.tools_ran,
            "trace": [_step(s) for s in result.trace],
        },
    }
    if result.started_at:
        invocation["startTimeUtc"] = _utc(result.started_at)
    if result.finished_at:
        invocation["endTimeUtc"] = _utc(result.finished_at)
    return invocation


def _notification_descriptors(errors: Sequence[ErrorInfo]) -> list[dict[str, Any]]:
    """Declare every `E_*` code this run actually emitted.

    A notification's `descriptor` is a reference, and a reference to
    something the driver never declared is dangling - valid-looking JSON that
    a strict SARIF validator rejects. The codes are declared here, from the
    run itself, so the reference always resolves.
    """
    codes = sorted({e.code for e in errors if e.code})
    return [{"id": code} for code in codes]


def _notification(error: ErrorInfo) -> dict[str, Any]:
    """An `ErrorInfo` as SARIF sees it.

    Every one is `level: "error"`. A scope block or a timed-out probe is not
    a milder kind of problem than a crash - it is the same statement, that
    the SDK did not find out - and demoting any of them to a warning is how
    a report ends up looking cleaner than the run was.

    The tool name goes in the property bag rather than in `associatedRule`:
    that field references a *rule* in `driver.rules`, and a tool is not one
    of our rules.
    """
    notification: dict[str, Any] = {
        "level": "error",
        "message": {"text": error.message},
        "properties": {"kind": error.kind},
    }
    if error.code:
        notification["descriptor"] = {"id": error.code}
    if error.tool:
        notification["properties"]["tool"] = error.tool
    if error.step_ref:
        notification["properties"]["stepRef"] = error.step_ref
    return notification


def _step(step: TraceStep) -> dict[str, Any]:
    """A trace step in the invocation property bag.

    SARIF has no native slot for "what the agent did, in order" - its
    `threadFlows` describe a data path through code, not an agent loop - so
    the trace goes in `properties` rather than being bent into a shape that
    means something else.
    """
    entry = {
        "id": step.id,
        "kind": step.kind,
        "name": step.name,
        "status": step.status,
        "summary": step.summary,
    }
    if step.code:
        entry["code"] = step.code
    if step.duration_ms is not None:
        entry["durationMs"] = step.duration_ms
    return entry


def _utc(moment: datetime) -> str:
    """SARIF wants ISO 8601 in UTC, ending in Z.

    A naive datetime is read as UTC rather than as local time: a report is
    read in a timezone that has nothing to do with where it was produced.
    """
    aware = moment if moment.tzinfo else moment.replace(tzinfo=UTC)
    return aware.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# Convenience
# --------------------------------------------------------------------------


def summary_line(result: CheckResult) -> str:
    """One line for a terminal or a CI log.

    Errors are named before findings. A run that half worked must not read
    like a clean one, and the first thing on the line is what the reader
    needs to know about how far to trust the rest of it.
    """
    parts = [f"{result.check:8} {result.status:12} {result.target}"]
    if result.errors:
        parts.append(f"{len(result.errors)} error(s)")
    parts.append(f"{len(result.findings)} finding(s)")
    parts.append(f"{result.tools_ran} tool call(s)")
    return " | ".join(parts)


def summary_lines(results: Iterable[CheckResult]) -> str:
    return "\n".join(summary_line(r) for r in results)
