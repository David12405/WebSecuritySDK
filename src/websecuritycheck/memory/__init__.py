"""Memory - durable target storage and the run-history diff.

Two durable stores, two jobs, kept in separate modules on purpose:

**`target_store`** (`TargetStore` / `SQLiteTargetStore`) is the partner's
canonical recon persistence - the `TargetModel` snapshot and the
append-only execution journal, keyed by assessment and target.

**`history`** (`RunHistory`) is the check-result history and the
open-findings ledger behind `CheckResult.diff`: it records each run, diffs
it against the open set, and carries an unverified finding forward until a
later run re-measures it. Opt-in via `Settings.history_db`. The pure
comparison is `memory.diff.diff_runs`.

Short-term context (`context.py`) is still deferred - only the
framework-tool exemption, which the scope guard needs, lives there today.
"""

from .history import RunHistory
from .target_store import SQLiteTargetStore, TargetStore

__all__ = ["RunHistory", "SQLiteTargetStore", "TargetStore"]
