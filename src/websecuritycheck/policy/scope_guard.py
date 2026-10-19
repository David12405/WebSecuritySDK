"""Hard rule - BeforeToolCall.  The blue "Scope guard" box in the diagram.

Out of scope, or not on this check's allowlist, means `event.cancel_tool`
plus an `ErrorInfo(kind="scope")`. The cancellation message goes back to the
model as the tool result, so it must report the block rather than quietly
retry somewhere else.

`in_scope(target, scope, allow_subdomains)` stays a pure function, separate
from the hook, so the same policy can be applied with no agent in the loop.

Framework tools - the ones Strands injects, including the per-check
structured-output tool - are exempt: they take no `target`, so there is
nothing to scope-check, and cancelling them deadlocks the run.

INIT: no implementation yet.
"""
