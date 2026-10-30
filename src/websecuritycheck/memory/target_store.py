"""Long-term memory - the run history and the open-findings ledger.

    store = TargetStore(path)
    diff = store.reconcile(result, tools_ok=..., check_tools=...)   # the runner's one call

Two tables, two jobs:

**`runs`** is the append-only history - one row per run of a check on a
target, with that run's reported findings. It answers "what did this run
say" and is never rewritten.

**`open_findings`** is the living ledger - the set of problems currently
*open* for a target and check, meaning present or unverified. It is the
thing a new run is diffed against, and it is what makes `unverified` sticky:
a finding that could not be re-checked stays in the ledger, run after run,
until a successful re-measurement either finds it gone (`fixed`, dropped) or
finds it still there (`present`, kept). Without the ledger the diff could
only reach back to the last run's reported findings, and an unverified
problem would vanish the moment a later run no longer listed it.

**Why SQLite.** History keyed by `(target, check)`, queried for "the most
recent one" and "the open set", is a row store with an index. `sqlite3` is in
the standard library, writes atomically, and keeps it all in one file.

**What never reaches here.** Raw tool output. A finding's `evidence` is a
quotation the model already put in the public `CheckResult`, so it is no more
exposed here than there; the injection guard's raw archive stays in memory
and dies with the run.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..results.models import CheckResult, Finding, RunDiff
from .diff import diff_runs, next_open_findings

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    target      TEXT NOT NULL,
    check_name  TEXT NOT NULL,
    status      TEXT NOT NULL,
    tools_ran   INTEGER NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    findings    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_target_check ON runs (target, check_name, seq);

CREATE TABLE IF NOT EXISTS open_findings (
    target         TEXT NOT NULL,
    check_name     TEXT NOT NULL,
    finding_id     TEXT NOT NULL,
    finding        TEXT NOT NULL,
    status         TEXT NOT NULL,   -- 'present' | 'unverified'
    first_seen_run TEXT,
    updated_run    TEXT,
    PRIMARY KEY (target, check_name, finding_id)
);
"""


@dataclass(frozen=True)
class StoredRun:
    """One past run, read back from the history."""

    run_id: str
    target: str
    check: str
    status: str
    tools_ran: int
    findings: list[Finding]


@dataclass(frozen=True)
class OpenFinding:
    """One entry of the ledger: a finding and how long it has been open."""

    finding: Finding
    status: str  # 'present' | 'unverified'
    first_seen_run: str | None


class TargetStore:
    """Run history plus the open-findings ledger, keyed by target and check.

    Usable as a context manager so the connection closes even if a run
    raises. The schema is created on open, so a fresh path just works.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def __enter__(self) -> TargetStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    # -- the runner's one call --------------------------------------------

    def reconcile(
        self,
        result: CheckResult,
        *,
        tools_ok: set[str],
        check_tools: Sequence[str],
    ) -> RunDiff | None:
        """Record this run, diff it against the open ledger, and update the ledger.

        Returns the `RunDiff` for this run, or `None` on the very first run of
        a target and check - there is nothing measured to compare against, and
        a diff that calls every finding new would read as a wave of problems
        where none has been compared.

        The ledger is read before the run is saved, so a run is never diffed
        against itself, and updated after, so the next run inherits this one's
        open set. All of it is one transaction.
        """
        target, check = result.target, result.check
        open_rows = self._open_rows(target, check)
        open_before = [row.finding for row in open_rows]
        prior = self.baseline(target, check)  # read before we save this run

        diff: RunDiff | None = None
        if prior is not None:
            diff = diff_runs(
                open_before,
                result.findings,
                tools_ok=tools_ok,
                check_tools=check_tools,
                previous_run_id=prior.run_id,
            )

        self._insert_run(result)

        ledger = next_open_findings(
            open_before, result.findings, tools_ok=tools_ok, check_tools=check_tools
        )
        self._write_ledger(target, check, ledger, open_rows, result)

        self._conn.commit()
        return diff

    # -- reading ----------------------------------------------------------

    def baseline(self, target: str, check: str) -> StoredRun | None:
        """The most recent run that measured something, or None.

        Used for the `previous_run_id` marker and to tell a first run from a
        later one. A run with `tools_ran == 0` saw nothing, so it is skipped:
        its empty findings mean "did not look", not "found nothing".
        """
        row = self._conn.execute(
            "SELECT * FROM runs WHERE target = ? AND check_name = ? AND tools_ran > 0 "
            "ORDER BY seq DESC LIMIT 1",
            (target, check),
        ).fetchone()
        return self._row_to_run(row) if row is not None else None

    def history(self, target: str, check: str) -> list[StoredRun]:
        """Every saved run for this target and check, oldest first."""
        rows = self._conn.execute(
            "SELECT * FROM runs WHERE target = ? AND check_name = ? ORDER BY seq ASC",
            (target, check),
        ).fetchall()
        return [self._row_to_run(row) for row in rows]

    def open_findings(self, target: str, check: str) -> list[OpenFinding]:
        """The ledger: every problem currently open for this target and check."""
        return self._open_rows(target, check)

    # -- writing ----------------------------------------------------------

    def save(self, result: CheckResult) -> None:
        """Append one run to the history, without touching the ledger.

        Lower level than `reconcile`; here for callers that only want the
        history written. The runner uses `reconcile`.
        """
        self._insert_run(result)
        self._conn.commit()

    # -- internals --------------------------------------------------------

    def _insert_run(self, result: CheckResult) -> None:
        self._conn.execute(
            "INSERT INTO runs "
            "(run_id, target, check_name, status, tools_ran, started_at, finished_at, findings) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                result.run_id,
                result.target,
                result.check,
                result.status,
                result.tools_ran,
                result.started_at.isoformat() if result.started_at else None,
                result.finished_at.isoformat() if result.finished_at else None,
                _dump_findings(result.findings),
            ),
        )

    def _write_ledger(
        self,
        target: str,
        check: str,
        ledger: Sequence[Finding],
        before: Sequence[OpenFinding],
        result: CheckResult,
    ) -> None:
        """Replace the ledger for one target and check with the new open set.

        `first_seen_run` is preserved across updates - a finding open for five
        runs still knows which run first saw it - and defaults to this run for
        one appearing now.
        """
        first_seen = {row.finding.id: row.first_seen_run for row in before}
        current_ids = {f.id for f in result.findings}
        self._conn.execute(
            "DELETE FROM open_findings WHERE target = ? AND check_name = ?", (target, check)
        )
        self._conn.executemany(
            "INSERT INTO open_findings "
            "(target, check_name, finding_id, finding, status, first_seen_run, updated_run) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    target,
                    check,
                    finding.id,
                    finding.model_dump_json(),
                    "present" if finding.id in current_ids else "unverified",
                    first_seen.get(finding.id, result.run_id),
                    result.run_id,
                )
                for finding in ledger
            ],
        )

    def _open_rows(self, target: str, check: str) -> list[OpenFinding]:
        rows = self._conn.execute(
            "SELECT * FROM open_findings WHERE target = ? AND check_name = ?",
            (target, check),
        ).fetchall()
        return [
            OpenFinding(
                finding=Finding.model_validate_json(row["finding"]),
                status=row["status"],
                first_seen_run=row["first_seen_run"],
            )
            for row in rows
        ]

    @staticmethod
    def _row_to_run(row: sqlite3.Row) -> StoredRun:
        return StoredRun(
            run_id=row["run_id"],
            target=row["target"],
            check=row["check_name"],
            status=row["status"],
            tools_ran=row["tools_ran"],
            findings=[Finding.model_validate(item) for item in json.loads(row["findings"])],
        )


def _dump_findings(findings: Sequence[Finding]) -> str:
    return json.dumps([f.model_dump(mode="json") for f in findings], ensure_ascii=False)
