"""Short-term memory.  Step 4 of the diagram.

Pinned working memory + the last N messages + one-line stubs of the older
ones. This is configuration of Strands' own `context_manager`, not a
hand-written conversation manager: `large_tool_offloading` so a 200 KB tool
result becomes a preview plus a retrievable stash, `proactive_summarization`
for the rest.

What stays ours: the strategy choice, the pinned working-memory block (built
by code and read-only to the model - a hostile line pinned once would ride
along in every later turn), and the framework-tool exemption below.

INIT: the context-manager configuration is not written yet. The exemption is,
because the scope guard cannot be correct without it.
"""

from __future__ import annotations

#: Tools Strands injects itself, which no check declares.
#:
#: `retrieve_context` is how the model reads back tool output that
#: `large_tool_offloading` moved out of the context window.
FRAMEWORK_TOOLS = frozenset({"retrieve_context"})


def framework_tools_for(output_model: type | str) -> frozenset[str]:
    """The exempt set for one check.

    The structured-output tool is injected under the name of the check's own
    output model, so the set cannot be a constant - it is per check.

    All three hooks have to agree on this set. The scope guard must not
    cancel these tools; the injection guard must not wrap them, because the
    structured-output result is the model's own answer rather than target
    bytes; and the retry ledger must not count them, or "this check called
    no tool" becomes unprovable - the structured-output tool runs on every
    turn, so counting it would make every run look like it measured
    something.
    """
    name = output_model if isinstance(output_model, str) else output_model.__name__
    return FRAMEWORK_TOOLS | {name}
