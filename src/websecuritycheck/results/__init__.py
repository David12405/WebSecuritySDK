"""The public result types. With `checker.py`, the only public surface.

Everything a developer reads after a check, plus the two internal pieces the
runner needs to assemble it: `CheckOutput` (what the model fills) and
`decide_status` (the one place a status is decided).
"""

from .export import summary_line, summary_lines, to_json, to_sarif, write_json, write_sarif
from .models import (
    MAX_SUMMARY_CHARS,
    NO_TOOL_RAN,
    CheckOutput,
    CheckResult,
    ErrorInfo,
    ErrorKind,
    Finding,
    FindingDraft,
    RunDiff,
    Status,
    StepKind,
    StepStatus,
    TraceStep,
    decide_status,
    stable_id,
)

__all__ = [
    "MAX_SUMMARY_CHARS",
    "NO_TOOL_RAN",
    "CheckOutput",
    "CheckResult",
    "ErrorInfo",
    "ErrorKind",
    "Finding",
    "FindingDraft",
    "RunDiff",
    "Status",
    "StepKind",
    "StepStatus",
    "TraceStep",
    "decide_status",
    "stable_id",
    "summary_line",
    "summary_lines",
    "to_json",
    "to_sarif",
    "write_json",
    "write_sarif",
]
