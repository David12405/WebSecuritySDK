"""Memory - short term (context manager) and long term (TargetStore).

Long term is implemented: `target_store.TargetStore` is a SQLite history of
runs, and `diff.diff_runs` is the pure comparison that turns a baseline and
this run into a `RunDiff`. The runner reads the baseline before a run and
saves the run after, so each is diffed against the last of the same check on
the same target. Opt-in via `Settings.history_db`.

Short term - the context-manager configuration in `context.py` - is still
deferred. It is not on the critical path while every check is one tool and
one turn and the injection guard already bounds per-call output; only the
framework-tool exemption, which the scope guard needs, lives there today.
"""
