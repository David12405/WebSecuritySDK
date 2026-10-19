"""Long-term memory - one SQLite row per (target, check, run).

Read at step 3 to pin the previous run's summary, written at step 7 with
this run's findings, errors and tool log. The diff between two runs is what
turns a report into a trend: new / fixed / unchanged.

INIT: no implementation yet.
"""
