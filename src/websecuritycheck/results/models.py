"""Finding, ErrorInfo, TraceStep, RunDiff, CheckOutput, CheckResult.

Two audiences, and keeping them apart is the whole point of this module.

**The model, inside the loop.** It fills `CheckOutput` - drafts of findings
and nothing else. It cannot set a status, cannot write a trace, and cannot
invent a finding id. Everything it is not allowed to decide is simply absent
from the schema it is shown, so "the model never sets status" stops being a
rule somebody has to remember and becomes a thing that cannot be expressed.

**The developer, after the run.** They get `CheckResult`: the findings, the
errors, the trace of what actually happened, and the diff against the last
run. The harness fills in everything the model was not allowed to touch.

The trace is what makes the other three readable. The output of this SDK is a
report, not a conversation - nobody asks the agent afterwards what it did, so
the report has to answer on its own: which tools ran, which calls were
blocked, which failed, which answers were sent back. Without it
`status="partial"` is a word with no content.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --------------------------------------------------------------------------
# Vocabularies
# --------------------------------------------------------------------------

#: **There is no severity.** A finding says what the target does and where;
#: how much it matters is not something one response can settle, and a model
#: asked to rate it will answer anyway. Measured on this project: severities
#: moved between identical runs, a reviewing model argued them on every
#: finding and invented a premise to justify itself, and the pressure to
#: defend a rating pushed four specific findings into one vague one.
#:
#: Dropping the field removes the question rather than forbidding it - the
#: same move `CheckOutput` makes with `status`. Whoever reads the report
#: knows their own system and can rank what it says; the SDK knows one
#: response.

ErrorKind = Literal["scope", "tool", "model", "validation", "timeout", "injection"]

Status = Literal["passed", "issues_found", "failed", "partial"]

StepKind = Literal[
    "model_call",  # one turn of the agent loop
    "tool_call",  # a tool ran, with its outcome
    "cancelled",  # a hook refused the call before it ran
    "retry",  # a transient failure, tried again
    "skill_loaded",  # the SKILL.md for this check entered the prompt
    "steering",  # an answer was sent back, with the reason
    "output",  # the final structured answer
]

StepStatus = Literal["ok", "error", "cancelled"]

#: No raw target content in a trace. A summary is written by our code, and is
#: cut here rather than at the call site, so there is one place to check.
MAX_SUMMARY_CHARS = 300

_SLUG = re.compile(r"[^a-z0-9]+")


# --------------------------------------------------------------------------
# What the model produces
# --------------------------------------------------------------------------


class FindingDraft(BaseModel):
    """One problem in the target, as the model reports it.

    This is the model-facing half, and it is deliberately missing two fields
    the public `Finding` has:

    `id` - it has to be stable across runs or the diff is meaningless, and a
    model asked for an identifier produces a different one every time.
    `stable_id()` derives it instead.

    `tool_refs` - these are trace step ids, which the harness assigns. The
    model never sees them, so asking for them would only invite invention.

    There is also no `remediation`, and that is a scope decision rather than
    an omission. This SDK reports what a target does; it does not advise how
    to change it. The two jobs need different warrants - a finding is backed
    by a tool result from this run, while a fix is backed by knowledge of a
    stack the SDK never looked at - and a model asked for both will produce
    them in the same confident voice. The cost of guessing was measured:
    asked to remediate `X-XSS-Protection: 0`, the model advised turning the
    header back on, which reintroduces the vulnerability it was removed for.
    A report that stays silent on fixes is one a reader cannot be misled by.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1)
    location: str = Field(min_length=1, description="URL, header name, cookie name ...")
    evidence: str = Field(
        min_length=1,
        description="Quoted from a tool result in THIS run. Not a restatement of the title.",
    )
    source_tool: str = Field(
        default="",
        description="Name of the tool the evidence was quoted from, if it came from one tool.",
    )


class CheckOutput(BaseModel):
    """The model's entire contribution - the structured-output schema.

    `extra="forbid"` is load-bearing. Without it a model that has seen enough
    security reports will helpfully add `"status": "passed"`, and a later
    refactor that trusts the field would hand the model a way to declare a
    target clean. There is no status here and there is no room for one.
    """

    model_config = ConfigDict(extra="forbid")

    findings: list[FindingDraft] = Field(default_factory=list)
    notes: str = Field(
        default="",
        description="What was checked and what could not be. Never a substitute for a finding.",
    )


# --------------------------------------------------------------------------
# What the harness produces
# --------------------------------------------------------------------------


def slug(text: str) -> str:
    """Lowercase, alphanumerics and single dashes. Used for ids."""
    return _SLUG.sub("-", text.lower()).strip("-")


def stable_id(check: str, location: str, title: str) -> str:
    """A finding id that survives between runs, so two runs can be diffed.

    Derived from what the finding is *about* rather than from how it was
    worded this time: the check, the location, and a slug of the title.

    Known limit: a model that rewords a title between runs - "CSP header
    missing" then "no Content-Security-Policy" - produces a different id, and
    the diff reads it as one finding fixed and another appeared. Location is
    the stable part, title is not, and the pair is still the best key
    available without a curated rule catalog. When the checks grow their own
    rule ids, this becomes `check:rule:location` and the problem disappears.
    """
    key = f"{slug(check)}|{location.strip().lower()}|{slug(title)}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


class Finding(FindingDraft):
    """A finding as the developer receives it: a draft plus its identity."""

    id: str
    tool_refs: list[str] = Field(
        default_factory=list,
        description="Trace step ids this finding rests on.",
    )

    @classmethod
    def from_draft(cls, draft: FindingDraft, check: str, tool_refs: Sequence[str]) -> Finding:
        return cls(
            **draft.model_dump(),
            id=stable_id(check, draft.location, draft.title),
            tool_refs=list(tool_refs),
        )


class ErrorInfo(BaseModel):
    """A failure of the SDK, a tool, or the model - never a property of the target.

    A finding says something about the site. An error says the SDK could not
    find out. They never mix: that is what keeps `passed` honest.
    """

    kind: ErrorKind
    message: str
    tool: str | None = None
    code: str | None = Field(default=None, description="E_TIMEOUT, E_SERVER_UNAVAILABLE, ...")
    step_ref: str | None = Field(
        default=None,
        description="Trace step this error came from, when it came from one.",
    )


class TraceStep(BaseModel):
    """One thing that happened, in order. The tool-use log.

    `summary` and `detail` are written by our code. Nothing derived from the
    target's bytes is ever put here - a trace is read by people and shipped to
    CI, and a header value echoed into it would carry target content straight
    past the injection guard.
    """

    id: str = Field(description="s1, s2, ... monotonic within a run, so tool_refs read plainly.")
    kind: StepKind
    name: str = Field(default="", description="Tool name, model id, skill name, or rule name.")
    status: StepStatus = "ok"
    summary: str = ""
    detail: str = ""
    code: str | None = None
    duration_ms: int | None = None

    @field_validator("summary", "detail")
    @classmethod
    def _cap(cls, value: str) -> str:
        if len(value) <= MAX_SUMMARY_CHARS:
            return value
        return value[: MAX_SUMMARY_CHARS - 1] + "…"

    @property
    def measured(self) -> bool:
        """Did this step actually obtain evidence about the target?"""
        return self.kind == "tool_call" and self.status == "ok"


class RunDiff(BaseModel):
    """What changed since the previous run of this check on this target."""

    previous_run_id: str | None = None
    new: list[str] = Field(default_factory=list, description="Finding ids seen for the first time.")
    fixed: list[str] = Field(
        default_factory=list,
        description="Gone, and the tool that would have found them ran successfully this time.",
    )
    unchanged: list[str] = Field(default_factory=list)
    unverified: list[str] = Field(
        default_factory=list,
        description="Previously found; this run could not re-check them because a tool failed.",
    )

    @property
    def is_empty(self) -> bool:
        return not (self.new or self.fixed or self.unverified)


# --------------------------------------------------------------------------
# Status
# --------------------------------------------------------------------------


#: Raised as an error by the runner when the loop ended without measuring.
NO_TOOL_RAN = ErrorInfo(
    kind="model",
    message="The check completed without calling a tool, so nothing about the target was measured.",
)


def decide_status(
    findings: Sequence[Finding] | Sequence[FindingDraft],
    errors: Sequence[ErrorInfo],
    tools_ran: int,
) -> Status:
    """The one place a `CheckResult` status is decided.

    | findings | errors | status         |
    |----------|--------|----------------|
    | none     | none   | `passed`       |
    | some     | none   | `issues_found` |
    | some     | some   | `partial`      |
    | none     | some   | `failed`       |

    With one rule above the table: **a run that called no tool is never
    `passed`**. It measured nothing, so an empty findings list is the absence
    of evidence, not evidence of absence - and a report that calls an
    unmeasured target clean is the worst output this SDK can produce.

    The same rule disposes of findings produced without a tool: they were
    remembered, not observed, so the run is `failed` rather than `partial`.
    """
    if tools_ran == 0:
        return "failed"
    if findings and errors:
        return "partial"
    if findings:
        return "issues_found"
    if errors:
        return "failed"
    return "passed"


# --------------------------------------------------------------------------
# The public result
# --------------------------------------------------------------------------


class CheckResult(BaseModel):
    """What one check returns. The only thing most developers ever read."""

    check: str
    target: str
    status: Status
    findings: list[Finding] = Field(default_factory=list)
    notes: str = ""
    """What the check looked at, in the model's words. Carried through from
    `CheckOutput.notes`.

    It is the only place an inventory can land. A finding says something is
    wrong; a check like `fingerprint` spends most of its evidence
    establishing what is *there*, and "nginx, no version" is an answer worth
    reading and not a defect worth reporting. Drop this field and a run that
    examined nine technologies reports two unrelated findings and looks like
    it never did the work.

    Not a substitute for a finding, and nothing here is scored.
    """
    errors: list[ErrorInfo] = Field(default_factory=list)
    diff: RunDiff | None = None
    trace: list[TraceStep] = Field(default_factory=list)

    run_id: str = ""
    started_at: datetime | None = None
    finished_at: datetime | None = None

    tools_ran: int = 0
    """How many tool calls measured something.

    Stored rather than counted from `trace`, because the trace is filtered
    by `trace_level` and the count is not. A result whose trace was turned
    off still knows it measured the target; deriving the number from a
    filtered view would report zero and contradict its own status.
    """

    @classmethod
    def build(
        cls,
        *,
        check: str,
        target: str,
        output: CheckOutput,
        errors: Sequence[ErrorInfo],
        trace: Sequence[TraceStep],
        diff: RunDiff | None = None,
        run_id: str = "",
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        tools_ran: int | None = None,
    ) -> CheckResult:
        """Assemble a result from the model's output and the run's own record.

        The runner calls this instead of constructing a `CheckResult` by hand,
        so `status` is computed from what happened every time rather than
        passed in by whoever is assembling the result.

        `tools_ran` is counted from the trace when it is not given. Pass it
        when the trace is filtered - `trace_level="off"` produces no steps
        at all, and counting those would turn "do not print a trace" into
        "every run failed".
        """
        errors = list(errors)
        trace = list(trace)
        tool_steps = [step for step in trace if step.measured]
        measured = len(tool_steps) if tools_ran is None else tools_ran

        findings = [
            Finding.from_draft(draft, check, _refs_for(draft, tool_steps))
            for draft in output.findings
        ]
        # By location, then title. With no severity to rank by, the useful
        # order is the one that puts a target's findings about the same
        # header or cookie next to each other.
        findings.sort(key=lambda f: (f.location, f.title))

        if measured == 0 and NO_TOOL_RAN not in errors:
            errors.append(NO_TOOL_RAN)

        return cls(
            check=check,
            target=target,
            status=decide_status(findings, errors, measured),
            findings=findings,
            notes=output.notes,
            errors=errors,
            diff=diff,
            trace=trace,
            run_id=run_id,
            started_at=started_at,
            finished_at=finished_at,
            tools_ran=measured,
        )

    def by_location(self) -> dict[str, list[Finding]]:
        """Findings grouped for a report, by what they are about."""
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.location, []).append(finding)
        return grouped


def _refs_for(draft: FindingDraft, tool_steps: Sequence[TraceStep]) -> list[str]:
    """Trace steps a finding rests on.

    Matched by the tool the model says it quoted. When it named no tool - or
    named one that never ran - the finding falls back to every tool step of
    the run: it rests on this run's evidence, just not on an identified part
    of it. Whether that evidence actually supports the finding is the
    grounding rule's job, not this function's.
    """
    if draft.source_tool:
        named = [step.id for step in tool_steps if step.name == draft.source_tool]
        if named:
            return named
    return [step.id for step in tool_steps]
