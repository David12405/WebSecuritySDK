"""Conversion of L6 artifact manifests into canonical evidence metadata."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any
from websecuritycheck.domain import (
    ArtifactManifest,
    EvidenceArtifactRecord,
    Id,
    ToolExecutionResult,
)


class RecordIdAllocator:
    """Small assessment-scoped numeric ID allocator.

    Existing records seed the allocator, making incremental updates preserve
    IDs without introducing a persistence service or revision history.
    """

    def __init__(self, existing: Iterable[str] = ()) -> None:
        self._next: dict[str, int] = {}
        for value in existing:
            match = re.fullmatch(r"([A-Z]{3,})-(\d{3,})", value)
            if match:
                prefix, number = match.groups()
                self._next[prefix] = max(self._next.get(prefix, 0), int(number)) + 1

    def new(self, prefix: str) -> str:
        number = self._next.get(prefix, 1)
        self._next[prefix] = number + 1
        return f"{prefix}-{number:03d}"


_SENSITIVE_METADATA = ("authorization", "cookie", "password", "secret", "token", "api_key", "apikey")


def _redact_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if any(part in key_text.casefold() for part in _SENSITIVE_METADATA):
                output[key_text] = "<redacted>"
            else:
                output[key_text] = _redact_metadata(item)
        return output
    if isinstance(value, list):
        return [_redact_metadata(item) for item in value]
    return value


def _content_bytes(manifest: ArtifactManifest) -> bytes:
    if manifest.content is not None:
        return manifest.content.encode("utf-8")
    return json.dumps(
        {"artifact_ref": manifest.artifact_ref, "metadata": manifest.metadata},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def create_evidence_records(
    execution: ToolExecutionResult,
    *,
    allocator: RecordIdAllocator | None = None,
) -> list[EvidenceArtifactRecord]:
    allocator = allocator or RecordIdAllocator()
    records: list[EvidenceArtifactRecord] = []
    for manifest in execution.artifact_manifests:
        content = _content_bytes(manifest)
        digest = hashlib.sha256(content).hexdigest()
        if manifest.sha256_hash and manifest.sha256_hash.lower() != digest:
            raise ValueError(f"artifact digest mismatch for {manifest.artifact_ref!r}")
        records.append(
            EvidenceArtifactRecord(
                evidence_id=allocator.new("EVD"),
                assessment_id=execution.assessment_id,
                artifact_type=manifest.artifact_type,
                artifact_ref=manifest.artifact_ref,
                storage_uri=manifest.storage_uri,
                sha256_hash=digest,
                size_bytes=manifest.size_bytes if manifest.size_bytes is not None else len(content),
                media_type=manifest.media_type,
                captured_at=execution.finished_at or execution.started_at,
                execution_ref=execution.execution_id,
                source_tool_id=execution.tool_id,
                provenance={
                    "assessment_id": execution.assessment_id,
                    "execution_id": execution.execution_id,
                    "tool_id": execution.tool_id,
                    "result_type": execution.result_type,
                },
                redaction_applied=manifest.redaction_applied,
                truncated=manifest.truncated or execution.truncated,
                metadata=_redact_metadata({**manifest.metadata, "result_type": execution.result_type}),
            )
        )
    return records


def evidence_refs(records: list[EvidenceArtifactRecord]) -> list[Id]:
    return [record.evidence_id for record in records]
