"""Durable target memory backed by SQLite."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Protocol

from websecuritycheck.domain import ReconProcessingResult, TargetModel, ToolExecutionResult
from websecuritycheck.recon.endpoints import normalize_origin


def target_identity(target: str) -> str:
    """The store key for a target: one site, not one URL.

    A recon run probes many URLs of one site - the root, its assets, an API
    path - and each is a tool call whose `target` is that exact URL. Keyed on
    the raw URL, every probe became a separate stored target, so no single
    `TargetModel` ever held a site's whole surface, and Module 2 (which reads
    one model's endpoints) saw a fragment. Reducing the target to its origin
    - `https://host[:port]`, the same form `recon.endpoints` gives an
    endpoint's `origin` - collapses all of one site's URLs onto one identity,
    so the sub-URLs become endpoints inside one model instead of targets of
    their own. A non-URL target (an Nmap CIDR) has no origin and keeps its
    raw form.
    """
    return normalize_origin(target)


class TargetStore(Protocol):
    def load_target(self, assessment_id: str, target: str) -> TargetModel | None: ...
    def allocate_execution_id(self, assessment_id: str) -> str: ...
    def target_id_for(self, assessment_id: str, target: str) -> str: ...
    def persist(
        self,
        execution: ToolExecutionResult,
        processing: ReconProcessingResult | None,
    ) -> None: ...


class SQLiteTargetStore:
    """Snapshot plus append-only execution journal.

    The store owns one connection and serializes writes with an immediate
    transaction. Callers may safely reuse it across runs of one checker.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(
            """
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS targets (
                assessment_id TEXT NOT NULL,
                canonical_target TEXT NOT NULL,
                target_id TEXT NOT NULL,
                PRIMARY KEY (assessment_id, canonical_target)
            );
            CREATE TABLE IF NOT EXISTS target_snapshots (
                assessment_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                model_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (assessment_id, target_id)
            );
            CREATE TABLE IF NOT EXISTS execution_journal (
                execution_id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                target_id TEXT,
                execution_json TEXT NOT NULL,
                processing_json TEXT,
                created_at TEXT NOT NULL
            );
            INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('schema_version', '1');
            """
        )
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> SQLiteTargetStore:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def load_target(self, assessment_id: str, target: str) -> TargetModel | None:
        row = self._connection.execute(
            """SELECT s.model_json FROM target_snapshots s
               JOIN targets t ON t.assessment_id=s.assessment_id AND t.target_id=s.target_id
               WHERE t.assessment_id=? AND t.canonical_target=?""",
            (assessment_id, target_identity(target)),
        ).fetchone()
        return TargetModel.model_validate(json.loads(row[0])) if row else None

    def allocate_execution_id(self, assessment_id: str) -> str:
        row = self._connection.execute(
            """SELECT COALESCE(MAX(CAST(substr(execution_id, 6) AS INTEGER)), 0)
               FROM execution_journal WHERE assessment_id=? AND execution_id LIKE 'EXEC-%'""",
            (assessment_id,),
        ).fetchone()
        return f"EXEC-{int(row[0]) + 1:03d}"

    def target_id_for(self, assessment_id: str, target: str) -> str:
        """The stable `TGT-xxx` id for a site, allocating one on first sight.

        Public so the adapter can pass it into `process_tool_result`: the
        pipeline otherwise defaults every fresh model to `TGT-001`, and two
        different sites under one assessment would collide on that id and
        overwrite each other's snapshot. Keyed on the origin, so one site has
        one id for the life of the assessment however many of its URLs are
        probed.
        """
        return self._target_id(assessment_id, target)

    def _target_id(self, assessment_id: str, target: str) -> str:
        identity = target_identity(target)
        row = self._connection.execute(
            "SELECT target_id FROM targets WHERE assessment_id=? AND canonical_target=?",
            (assessment_id, identity),
        ).fetchone()
        if row:
            return str(row[0])
        row = self._connection.execute(
            (
                "SELECT COALESCE(MAX(CAST(substr(target_id, 5) AS INTEGER)), 0) "
                "FROM targets WHERE assessment_id=?"
            ),
            (assessment_id,),
        ).fetchone()
        target_id = f"TGT-{int(row[0]) + 1:03d}"
        self._connection.execute(
            "INSERT INTO targets(assessment_id, canonical_target, target_id) VALUES (?, ?, ?)",
            (assessment_id, identity, target_id),
        )
        return target_id

    def persist(
        self,
        execution: ToolExecutionResult,
        processing: ReconProcessingResult | None,
    ) -> None:
        # The site identity, not the exact URL probed: all of a site's URLs
        # key onto one target. The raw URL stays in the journalled execution.
        target = target_identity(execution.target or "")
        with self._connection:
            target_id = self._target_id(execution.assessment_id, target) if target else None
            self._connection.execute(
                """INSERT INTO execution_journal
                   (execution_id, assessment_id, target_id, execution_json,
                    processing_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    execution.execution_id,
                    execution.assessment_id,
                    target_id,
                    execution.model_dump_json(),
                    processing.model_dump_json() if processing else None,
                    (execution.finished_at or execution.started_at).isoformat(),
                ),
            )
            if processing and processing.updated_target_model:
                model = processing.updated_target_model
                self._connection.execute(
                    """INSERT INTO target_snapshots
                       (assessment_id, target_id, revision, model_json, updated_at)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(assessment_id, target_id) DO UPDATE SET
                       revision=excluded.revision, model_json=excluded.model_json,
                       updated_at=excluded.updated_at""",
                    (
                        execution.assessment_id,
                        model.target_id,
                        model.revision,
                        model.model_dump_json(),
                        model.last_updated.isoformat(),
                    ),
                )
                self._connection.execute(
                    """UPDATE targets SET target_id=?
                       WHERE assessment_id=? AND canonical_target=?""",
                    (model.target_id, execution.assessment_id, target),
                )
