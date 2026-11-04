

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from strands.hooks import AfterToolCallEvent, HookRegistry

from ..results.models import ErrorInfo
from .errors import code_of, is_retryable, message_of

DEFAULT_MAX_ATTEMPTS = 3

#: Below the injection guard (10) and the trace (20), so this reads the raw
#: error text before the guard wraps it. See the module docstring.
RETRY_ORDER = 5


@dataclass
class RetryGuard:
    """One per run. Counts failed attempts and records the ones that stand.

    A hook provider, like the others: it learns what failed by watching
    `AfterToolCall`, so the tools stay free of retry logic.
    """

    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    exempt: frozenset[str] = frozenset()
    """Framework tools - the structured-output tool, `retrieve_context`.
    They are not probes of the target, and retrying one on a transient code
    would retry the model's own answer."""

    errors: list[ErrorInfo] = field(default_factory=list)
    """Failures that were not recovered. The runner collects these into the
    `CheckResult`, so a tool failure lands in `errors`, never in `findings`."""

    #: toolUseId -> how many times this one call has failed so far.
    _attempts: dict[str, int] = field(default_factory=dict)

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(AfterToolCallEvent, self._after_tool, order=RETRY_ORDER)

    def _after_tool(self, event: AfterToolCallEvent) -> None:
        name = event.tool_use.get("name") or ""
        if name in self.exempt:
            return
        if not _is_error(event.result):
            return  # success - a recovered retry lands here and records nothing

        text = _text_of(event.result)
        code = code_of(text)
        key = event.tool_use.get("toolUseId") or name
        self._attempts[key] = self._attempts.get(key, 0) + 1
        attempts = self._attempts[key]

        if is_retryable(code) and attempts < self.max_attempts:
            # Ask Strands to run the tool again. No ErrorInfo yet: this
            # attempt is not the final word, and recording it would flip a
            # recovered run to `partial` for a failure that did not last.
            event.retry = True
            return

        # Terminal: an unretryable code, or the attempts are spent. This is
        # the failure that stands, so it becomes a visible error.
        self.errors.append(
            ErrorInfo(
                kind="tool",
                code=code,
                tool=name,
                message=message_of(text) or "the tool call failed",
            )
        )


def _is_error(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    return result.get("status") == "error" or bool(result.get("isError") or result.get("is_error"))


def _text_of(result: Any) -> str:
    if not isinstance(result, dict):
        return ""
    return "\n".join(
        str(block["text"])
        for block in result.get("content") or []
        if isinstance(block, dict) and "text" in block
    )
