"""The file-based tactic registry: canonical YAML/JSON artefacts on disk.

Files are canonical, so the WSTG source, the tactic, the metadata, and the hashes
are directly auditable and usable as deterministic fixtures. A `TacticRegistry`
protocol keeps a future SQLite index possible without changing callers.

Writes are atomic: an artefact is written to a temporary sibling and
`os.replace`d into place, and `active.json` is written last, so a reader sees
either the previous complete version or the new one, never a half-written tactic.
A single-writer lock prevents two hypotheses from authoring the same cold tactic
at once.
"""

from __future__ import annotations

import errno
import json
import os
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Protocol

import yaml

from .models import (
    AdmittedTactic,
    RegistryManifest,
    TacticDocument,
    TacticMetadata,
    TacticState,
    WstgSnapshot,
    WstgSnapshotMetadata,
)

DEFAULT_ROOT = Path(".websec") / "tactic-registry"
FIRST_VERSION = "0.1.0"


class RegistryError(Exception):
    """Raised on storage corruption or a failed atomic write."""


class TacticRegistry(Protocol):
    def get_active(self, category: str) -> AdmittedTactic | None: ...

    def list_versions(self, category: str) -> list[str]: ...

    def next_version(self, category: str) -> str: ...

    def find_by_content_hash(self, category: str, content_sha256: str) -> AdmittedTactic | None: ...

    def publish(
        self,
        document: TacticDocument,
        metadata: TacticMetadata,
        *,
        snapshot: WstgSnapshot,
        snapshot_metadata: WstgSnapshotMetadata,
    ) -> AdmittedTactic: ...


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


def _canonical_json(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


class FileTacticRegistry:
    """A `TacticRegistry` backed by a JSON/YAML directory tree."""

    def __init__(self, root: str | Path = DEFAULT_ROOT) -> None:
        self.root = Path(root)

    # --- paths ----------------------------------------------------------- #

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    def _category_dir(self, category: str) -> Path:
        return self.root / "tactics" / category

    def _active_path(self, category: str) -> Path:
        return self._category_dir(category) / "active.json"

    def _tactic_path(self, category: str, version: str) -> Path:
        return self._category_dir(category) / f"{version}.yaml"

    def _metadata_path(self, category: str, version: str) -> Path:
        return self._category_dir(category) / f"{version}.metadata.json"

    def _wstg_dir(self, snapshot: WstgSnapshot) -> Path:
        return self.root / "wstg" / snapshot.wstg_version / snapshot.requested_id

    # --- reads ----------------------------------------------------------- #

    def load_manifest(self) -> RegistryManifest:
        if not self.manifest_path.is_file():
            return RegistryManifest()
        try:
            return RegistryManifest.model_validate_json(self.manifest_path.read_text("utf-8"))
        except Exception as exc:
            raise RegistryError(f"corrupt manifest at {self.manifest_path}: {exc}") from exc

    def list_versions(self, category: str) -> list[str]:
        directory = self._category_dir(category)
        if not directory.is_dir():
            return []
        versions = [p.stem for p in directory.glob("*.yaml")]
        return sorted(versions, key=_version_key)

    def _load_version(self, category: str, version: str) -> AdmittedTactic:
        tactic_path = self._tactic_path(category, version)
        metadata_path = self._metadata_path(category, version)
        if not tactic_path.is_file() or not metadata_path.is_file():
            raise RegistryError(f"missing tactic or metadata for {category} {version}")
        document = TacticDocument.model_validate(yaml.safe_load(tactic_path.read_text("utf-8")))
        metadata = TacticMetadata.model_validate_json(metadata_path.read_text("utf-8"))
        # The YAML content hash must still match its metadata, or the file was
        # tampered with after admission.
        if document.canonical_content_hash() != metadata.content_sha256:
            raise RegistryError(
                f"content hash mismatch for {category} {version}: file does not match metadata"
            )
        return AdmittedTactic(document=document, metadata=metadata)

    def get_active(self, category: str) -> AdmittedTactic | None:
        active_path = self._active_path(category)
        if not active_path.is_file():
            return None
        try:
            pointer = json.loads(active_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError(f"corrupt active pointer at {active_path}: {exc}") from exc
        version = pointer.get("active_version")
        if not version:
            return None
        admitted = self._load_version(category, version)
        if admitted.metadata.state != TacticState.ACTIVE:
            return None
        return admitted

    def find_by_content_hash(self, category: str, content_sha256: str) -> AdmittedTactic | None:
        for version in self.list_versions(category):
            admitted = self._load_version(category, version)
            if admitted.metadata.content_sha256 == content_sha256:
                return admitted
        return None

    # --- version allocation ---------------------------------------------- #

    def next_version(self, category: str) -> str:
        versions = self.list_versions(category)
        if not versions:
            return FIRST_VERSION
        highest = max(versions, key=_version_key)
        major, minor, patch = (int(part) for part in highest.split("."))
        return f"{major}.{minor}.{patch + 1}"

    # --- writes ---------------------------------------------------------- #

    def save_wstg_snapshot(
        self, snapshot: WstgSnapshot, metadata: WstgSnapshotMetadata
    ) -> Path:
        directory = self._wstg_dir(snapshot)
        _atomic_write(directory / "raw.json", _canonical_json(snapshot.model_dump(mode="json")))
        _atomic_write(
            directory / "metadata.json", _canonical_json(metadata.model_dump(mode="json"))
        )
        return directory

    def publish(
        self,
        document: TacticDocument,
        metadata: TacticMetadata,
        *,
        snapshot: WstgSnapshot,
        snapshot_metadata: WstgSnapshotMetadata,
    ) -> AdmittedTactic:
        category = metadata.vulnerability_category
        version = metadata.tactic_version
        with self._lock():
            self.save_wstg_snapshot(snapshot, snapshot_metadata)
            _atomic_write(
                self._tactic_path(category, version),
                yaml.safe_dump(
                    document.model_dump(mode="json"), sort_keys=False, allow_unicode=True
                ),
            )
            _atomic_write(
                self._metadata_path(category, version),
                _canonical_json(metadata.model_dump(mode="json")),
            )
            self._update_manifest(category, version)
            # active.json is written last: a reader never sees it point at a
            # version whose files are not yet complete.
            _atomic_write(
                self._active_path(category),
                _canonical_json({"active_version": version}),
            )
        return AdmittedTactic(document=document, metadata=metadata)

    def _update_manifest(self, category: str, version: str) -> None:
        manifest = self.load_manifest()
        entry = manifest.tactics.get(category)
        if entry is None:
            from .models import ManifestEntry

            entry = ManifestEntry()
            manifest.tactics[category] = entry
        if version not in entry.versions:
            entry.versions.append(version)
            entry.versions.sort(key=_version_key)
        entry.active_version = version
        _atomic_write(self.manifest_path, _canonical_json(manifest.model_dump(mode="json")))

    # --- single-writer lock ---------------------------------------------- #

    @contextmanager
    def _lock(self, *, timeout: float = 10.0, poll: float = 0.05) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True)
        lock_path = self.root / ".registry.lock"
        deadline = time.monotonic() + timeout
        fd: int | None = None
        while True:
            try:
                fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                if time.monotonic() >= deadline:
                    raise RegistryError(
                        f"could not acquire registry lock at {lock_path} within {timeout}s"
                    ) from exc
                time.sleep(poll)
        try:
            yield
        finally:
            if fd is not None:
                os.close(fd)
            with suppress(OSError):
                lock_path.unlink()


def _version_key(version: str) -> tuple[int, int, int]:
    try:
        major, minor, patch = (int(part) for part in version.split("."))
    except ValueError:
        return (0, 0, 0)
    return (major, minor, patch)
