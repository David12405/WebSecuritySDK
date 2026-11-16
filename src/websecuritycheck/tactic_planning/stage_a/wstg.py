"""WSTG retrieval behind a narrow adapter, with a deterministic reference map.

The canonical reference for a category is decided by code, never by a search:
`SQL_INJECTION` is `WSTG-INPV-05` (versioned `WSTG-v42-INPV-05`). Semantic RAG
may aid discovery, but it cannot override a known mapping.

Two adapters implement the port:

- `RecordedWstgAdapter` reads a persisted snapshot, so Stage A runs and tests
  with no network - the default for CI and the offline example.
- `GithubWstgAdapter` fetches the canonical document straight from the official
  OWASP WSTG repository at a pinned tag (v4.2), by document id. This is the live
  source for the MVP: deterministic, authentic (CC BY-SA 4.0), and needing no
  vector database or service. A semantic RAG/MCP source is a future option for
  *discovering* an id when no known mapping exists - it never decides the
  canonical reference.

All adapter output is untrusted external data, even though the underlying content
is OWASP material.
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

#: The official OWASP WSTG repository and the release tag the MVP pins.
OWASP_WSTG_REPO = "OWASP/wstg"
OWASP_WSTG_TAG = "v4.2"
OWASP_WSTG_RAW_BASE = "https://raw.githubusercontent.com"

#: Bare WSTG id -> its document path within the repo at `OWASP_WSTG_TAG`.
WSTG_DOC_PATHS: dict[str, str] = {
    "WSTG-INPV-05": (
        "document/4-Web_Application_Security_Testing/"
        "07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md"
    ),
}


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


class GithubWstgAdapter:
    """Fetch a WSTG document straight from the official OWASP repo by id.

    Pins the release tag (default v4.2) so the content matches the WSTG-INPV-05
    numbering, and resolves a bare id to its canonical document path. No vector
    database and no service - a single HTTPS GET of the authoritative markdown.
    """

    def __init__(
        self,
        *,
        tag: str = OWASP_WSTG_TAG,
        wstg_version: str = EXPECTED_WSTG_VERSION,
        doc_paths: dict[str, str] | None = None,
        raw_base: str = OWASP_WSTG_RAW_BASE,
        repo: str = OWASP_WSTG_REPO,
        timeout: float = 15.0,
    ) -> None:
        self.tag = tag
        self.wstg_version = wstg_version
        self.doc_paths = doc_paths or WSTG_DOC_PATHS
        self.raw_base = raw_base.rstrip("/")
        self.repo = repo
        self.timeout = timeout

    def health(self) -> bool:
        return True

    def _url(self, path: str) -> str:
        return f"{self.raw_base}/{self.repo}/{self.tag}/{path}"

    def get_test_case(self, wstg_id: str) -> WstgSnapshot:
        import httpx

        path = self.doc_paths.get(wstg_id)
        if path is None:
            raise WstgRetrievalError(
                f"no OWASP WSTG document path for {wstg_id} (tag {self.tag})"
            )
        url = self._url(path)
        try:
            response = httpx.get(url, timeout=self.timeout, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise WstgRetrievalError(f"could not fetch {url}: {exc}") from exc
        content = response.text
        if not content.strip():
            raise WstgRetrievalError(f"OWASP WSTG document at {url} is empty")
        suffix = wstg_id.removeprefix("WSTG-")
        return WstgSnapshot(
            requested_id=wstg_id,
            returned_id=f"WSTG-{self.wstg_version}-{suffix}",
            wstg_version=self.wstg_version,
            content=content,
            truncated=False,
            source_uri=url,
            mcp_server=f"github:{self.repo}@{self.tag}",
            upstream_metadata={"repo": self.repo, "git_tag": self.tag},
            license="CC BY-SA 4.0",
            attribution=f"OWASP Web Security Testing Guide {self.tag} (CC BY-SA 4.0)",
        )


def reference_for(category: VulnerabilityCategory) -> tuple[str, str]:
    """`(bare_id, versioned_id)` for a category, or raise if unsupported."""
    mapping = CATEGORY_TO_WSTG.get(category)
    if mapping is None:
        raise WstgRetrievalError(
            f"no deterministic WSTG mapping for {category.value} in the MVP"
        )
    return mapping


def validate_snapshot(
    snapshot: WstgSnapshot,
    category: VulnerabilityCategory,
    *,
    expected_version: str = EXPECTED_WSTG_VERSION,
) -> WstgSnapshot:
    """Provenance-check a snapshot (from a source or the cache), fail-closed.

    Empty, truncated, version-mismatched, or wrong-id content is rejected rather
    than quietly authored over.
    """
    bare_id, versioned_id = reference_for(category)
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


def retrieve_snapshot(
    adapter: WstgAdapter,
    category: VulnerabilityCategory,
    *,
    expected_version: str = EXPECTED_WSTG_VERSION,
) -> WstgSnapshot:
    """Fetch the WSTG test case for a category from a source, then validate it."""
    bare_id, _versioned_id = reference_for(category)
    if not adapter.health():
        raise WstgRetrievalError("WSTG adapter reported not ready")
    snapshot = adapter.get_test_case(bare_id)
    return validate_snapshot(snapshot, category, expected_version=expected_version)


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
