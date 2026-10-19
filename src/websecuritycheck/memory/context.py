"""Short-term memory.  Step 4 of the diagram.

Pinned working memory + the last N messages + one-line stubs of the older
ones. This is configuration of Strands' own `context_manager`, not a
hand-written conversation manager: `large_tool_offloading` so a 200 KB tool
result becomes a preview plus a retrievable stash, `proactive_summarization`
for the rest.

What stays ours: the strategy choice, the pinned working-memory block (built
by code and read-only to the model - a hostile line pinned once would ride
along in every later turn), and the framework-tool exemption that the scope
guard, the injection guard and the retry ledger must all agree on.

INIT: no implementation yet.
"""
