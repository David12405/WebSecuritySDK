"""Soft rules - the two orange boxes in the diagram.

Before a tool call
    the skill for this check is not loaded yet, or the same call has already
    failed twice -> guide, and let the model retry instead of calling again.

After the final answer (step 6)
    coverage   every topic in `check.required_coverage` is addressed
    grounding  every finding's location appears in some tool result this run
    evidence   every finding quotes something, not a restatement of its title

Deterministic rules only. A rule that cannot be written down cannot be
regression tested, and a security SDK that changes its mind between runs is
worse than one that is predictably strict.

Grounding is the rule that earns its place: a finding whose location never
appears in any tool output was invented, and that is the exact failure mode
the evidence rule exists to stop.

INIT: no implementation yet.
"""
