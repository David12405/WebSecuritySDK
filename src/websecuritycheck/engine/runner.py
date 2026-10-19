"""Builds and drives the agent for one check.  Steps 2 to 7 of the diagram.

Step 2  assemble the Strands `Agent` from the `Check`: prompt, skill text,
        tool allowlist, structured-output schema, hooks, context manager.
Step 3  start the run (BeforeInvocation).
Steps 4-6  the loop, owned by Strands; our policy objects ride along as hooks
        (hard rules) and as a post-answer steering review (soft rules).
Step 7  finish the run (AfterInvocation) and return a `CheckResult`.

The runner owns `status`, `errors`, `diff` and `trace`. The model only ever
produces `CheckOutput` - findings and notes - so it cannot declare a check
passed when a tool failed.

INIT: no implementation yet.
"""
