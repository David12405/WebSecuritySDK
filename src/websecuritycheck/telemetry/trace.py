"""The trace: which tools ran, which calls were blocked, which failed.

The output of this SDK is a report, not a conversation - nobody asks the
agent afterwards what it did, so the report has to answer on its own.
Without a trace, `status="partial"` is a word with no content, and the diff
cannot tell a finding that was *fixed* from one whose tool failed this time.

Two constraints are enforced here rather than left to the collector:
`trace_level` decides which step kinds reach the report, and no
target-derived content is ever written into a trace step.

INIT: no implementation yet.
"""
