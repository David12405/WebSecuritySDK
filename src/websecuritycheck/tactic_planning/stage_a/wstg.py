"""WSTG retrieval behind a narrow adapter, with a deterministic reference map.

The canonical reference for a category is decided by code, never by a search:
`SQL_INJECTION` is `WSTG-INPV-05` (versioned `WSTG-v42-INPV-05`). Semantic RAG
may aid discovery, but it cannot override a known mapping.

`RecordedWstgAdapter` is the default and reads a persisted snapshot, so Stage A
runs and tests without the upstream Chroma/MCP service. A live MCP adapter is an
opt-in follow-up; the protocol is the seam that keeps the rest of Stage A blind
to which one it is talking to. All adapter output is untrusted external data,
even though the underlying content is OWASP material.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from ...domain.analysis_models import VulnerabilityCategory
from .models import WstgSnapshot, WstgSnapshotMetadata

#: The one authoritative mapping for the MVP. (bare_id, versioned_id).
CATEGORY_TO_WSTG: dict[VulnerabilityCategory, tuple[str, str]] = {
    VulnerabilityCategory.SQL_INJECTION: ("WSTG-INPV-05", "WSTG-v42-INPV-05"),
}

EXPECTED_WSTG_VERSION = "v42"


class WstgRetrievalError(Exception):
    """Raised when WSTG content cannot be retrieved or fails a provenance check."""


@runtime_checkable
class WstgAdapter(Protocol):
    """The calls Stage A is allowed to make against a WSTG source."""

    def health(self) -> bool: ...

    def get_test_case(self, wstg_id: str) -> WstgSnapshot: ...


class RecordedWstgAdapter:
    """Serve a WSTG snapshot from disk - the default offline adapter.

    Points at a directory holding `<WSTG-ID>.json` snapshot files (the shape of
    `WstgSnapshot`). This is what makes Stage A reproducible in CI: the exact
    upstream bytes are captured once and replayed, with no network or service.
    """

    def __init__(self, snapshot_dir: str | Path) -> None:
        self.snapshot_dir = Path(snapshot_dir)

    def health(self) -> bool:
        return self.snapshot_dir.is_dir()

    def get_test_case(self, wstg_id: str) -> WstgSnapshot:
        path = self.snapshot_dir / f"{wstg_id}.json"
        if not path.is_file():
            raise WstgRetrievalError(
                f"no recorded WSTG snapshot for {wstg_id} at {path}"
            )
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WstgRetrievalError(f"could not read snapshot {path}: {exc}") from exc
        return WstgSnapshot.model_validate(data)


def reference_for(category: VulnerabilityCategory) -> tuple[str, str]:
    """`(bare_id, versioned_id)` for a category, or raise if unsupported."""
    mapping = CATEGORY_TO_WSTG.get(category)
    if mapping is None:
        raise WstgRetrievalError(
            f"no deterministic WSTG mapping for {category.value} in the MVP"
        )
    return mapping


def retrieve_snapshot(
    adapter: WstgAdapter,
    category: VulnerabilityCategory,
    *,
    expected_version: str = EXPECTED_WSTG_VERSION,
) -> WstgSnapshot:
    """Fetch and provenance-check the WSTG test case for a category.

    Fails closed: empty, truncated, version-mismatched, or wrong-id content is
    rejected rather than quietly authored over.
    """
    bare_id, versioned_id = reference_for(category)

    if not adapter.health():
        raise WstgRetrievalError("WSTG adapter reported not ready")

    snapshot = adapter.get_test_case(bare_id)

    if not snapshot.content.strip():
        raise WstgRetrievalError(f"WSTG content for {bare_id} is empty")
    if snapshot.truncated:
        raise WstgRetrievalError(f"WSTG content for {bare_id} is truncated")
    # The source may answer with either the bare or the versioned id; both name
    # the same test case. Anything else is a mismatch.
    if snapshot.returned_id not in {bare_id, versioned_id}:
        raise WstgRetrievalError(
            f"WSTG returned id {snapshot.returned_id!r} does not match requested "
            f"{bare_id!r} / {versioned_id!r}"
        )
    if snapshot.wstg_version != expected_version:
        raise WstgRetrievalError(
            f"WSTG version {snapshot.wstg_version!r} does not match expected "
            f"{expected_version!r}"
        )
    return snapshot


def snapshot_metadata(
    snapshot: WstgSnapshot, *, retrieved_at: datetime | None = None
) -> WstgSnapshotMetadata:
    """Build the canonical-JSON sidecar recorded beside a raw snapshot."""
    return WstgSnapshotMetadata(
        requested_id=snapshot.requested_id,
        returned_id=snapshot.returned_id,
        wstg_version=snapshot.wstg_version,
        source_uri=snapshot.source_uri,
        retrieved_at=retrieved_at or datetime.now(UTC),
        mcp_server=snapshot.mcp_server,
        content_sha256=snapshot.content_hash(),
        license=snapshot.license,
        attribution=snapshot.attribution,
        truncated=snapshot.truncated,
        warnings=snapshot.warnings,
    )
