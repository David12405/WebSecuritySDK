"""The trace: which tools ran, which calls were blocked, which failed.

The output of this SDK is a report, not a conversation - nobody asks the
agent afterwards what it did, so the report has to answer on its own.

The trace is also load-bearing, not decoration. `decide_status` counts the
steps that actually measured something, and the rule that a run calling no
tool is never `passed` is enforced from that count. A collector that records
nothing turns every successful run into `failed`.

Two constraints are enforced here rather than left to whoever writes a step:

* `level` decides which kinds reach the report - `off`, `summary` (the
  default), or `full`, which adds a step per model call.
* No target content in a step. A summary is a sentence our code wrote about
  what happened; it never carries bytes the target chose. The one thing that
  does cross over is a refusal reason like `host 'evil.com' is not in scope`,
  which quotes a single identifier, already capped at 120 characters by the
  scope guard - and without it a blocked call in the report would be
  unexplainable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from strands.hooks import (
    AfterModelCallEvent,
    AfterToolCallEvent,
    BeforeToolCallEvent,
    HookRegistry,
)

from ..policy.errors import code_of, message_of
from ..results.models import StepKind, StepStatus, TraceStep

TraceLevel = str  # "off" | "summary" | "full"

ALL_KINDS: frozenset[str] = frozenset(
    {"model_call", "tool_call", "cancelled", "retry", "skill_loaded", "steering", "output"}
)

#: What reaches the report at each level. `summary` leaves out `model_call`
#: because a step per model turn triples the length of a trace while adding
#: nothing a reader of a security report is looking for.
KINDS_BY_LEVEL: dict[TraceLevel, frozenset[str]] = {
    "off": frozenset(),
    "summary": ALL_KINDS - {"model_call"},
    "full": ALL_KINDS,
}

#: Runs last among the after-tool hooks, so it sees the result the way the
#: run ended up with it - after a retry decided, after the injection guard
#: wrapped it.
TRACE_ORDER = 20


@dataclass
class TraceCollector:
    """One per run. Hands out step ids and keeps the ordered log.

    It is a hook provider as well as a collector, and it learns what
    happened by watching events rather than by being told. That keeps the
    guards free of logging code: the scope guard cancels a call, and this
    notices the cancellation on its own.
    """

    level: TraceLevel = "summary"

    exempt: frozenset[str] = frozenset()
    """Framework tools - `retrieve_context`, and the structured-output tool
    named after the check's output model.

    They are skipped rather than logged, and the reason is the status rule
    rather than tidiness. `tools_ran` counts `tool_call` steps, and the
    structured-output tool runs on every turn - count it and *every* run has
    called a tool, which makes "this check measured nothing" unprovable and
    lets a run whose only real probe failed come back `passed`.
    """

    steps: list[TraceStep] = field(default_factory=list)
    _next: int = 1

    # -- writing ---------------------------------------------------------

    def record(
        self,
        kind: StepKind,
        *,
        name: str = "",
        status: StepStatus = "ok",
        summary: str = "",
        detail: str = "",
        code: str | None = None,
        duration_ms: int | None = None,
    ) -> TraceStep | None:
        """Add a step, unless this kind is filtered out at this level.

        Returns the step so a caller can quote its id, or `None` when the
        level dropped it. An id is spent only on a step that is kept, so the
        ids in a report are contiguous.
        """
        if kind not in KINDS_BY_LEVEL.get(self.level, frozenset()):
            return None
        step = TraceStep(
            id=f"s{self._next}",
            kind=kind,
            name=name,
            status=status,
            summary=summary,
            detail=detail,
            code=code,
            duration_ms=duration_ms,
        )
        self._next += 1
        self.steps.append(step)
        return step

    @property
    def tools_ran(self) -> int:
        return sum(1 for step in self.steps if step.measured)

    def last_tool_step(self, name: str) -> TraceStep | None:
        """The most recent call of one tool, for an error to point at."""
        for step in reversed(self.steps):
            if step.kind == "tool_call" and step.name == name:
                return step
        return None

    # -- watching --------------------------------------------------------

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(BeforeToolCallEvent, self._before_tool, order=TRACE_ORDER)
        registry.add_callback(AfterToolCallEvent, self._after_tool, order=TRACE_ORDER)
        registry.add_callback(AfterModelCallEvent, self._after_model, order=TRACE_ORDER)

    def _before_tool(self, event: BeforeToolCallEvent) -> None:
        """Record a refusal here, where the reason still exists.

        By `AfterToolCall` the event carries only `cancel_message`, and a
        hook that cancelled with a `True` rather than a sentence leaves
        nothing to report. Catching it at the decision point keeps the
        reason.
        """
        if not event.cancel_tool:
            return
        reason = event.cancel_tool if isinstance(event.cancel_tool, str) else "call cancelled"
        self.record(
            "cancelled",
            name=event.tool_use.get("name") or "",
            status="cancelled",
            summary=reason,
        )

    def _after_tool(self, event: AfterToolCallEvent) -> None:
        if event.cancel_message:
            return  # already recorded at the decision point
        name = event.tool_use.get("name") or ""
        if name in self.exempt:
            return
        duration = int(event.duration * 1000) if event.duration is not None else None
        failed = _is_error(event.result)
        text = _text_of(event.result) if failed else ""
        self.record(
            "tool_call",
            name=name,
            status="error" if failed else "ok",
            # Our sentence, not the target's: on success it says only that
            # the call completed, never what the target returned.
            summary=message_of(text) if failed else "completed",
            code=code_of(text) if failed else None,
            duration_ms=duration,
        )

    def _after_model(self, event: AfterModelCallEvent) -> None:
        self.record("model_call", name=getattr(event, "model_id", "") or "model")


def _is_error(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    return result.get("status") == "error" or bool(result.get("isError") or result.get("is_error"))


def _text_of(result: Any) -> str:
    if not isinstance(result, dict):
        return ""
    parts = [
        str(block["text"])
        for block in result.get("content") or []
        if isinstance(block, dict) and "text" in block
    ]
    return "\n".join(parts)
