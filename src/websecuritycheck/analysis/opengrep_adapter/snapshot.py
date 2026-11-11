"""Source snapshot discovery, hashing, and git revision metadata."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "coverage",
        "htmlcov",
        ".tox",
    }
)


def _has_symlink_component(path: Path, stop_at: Path | None = None) -> bool:
    """Check whether a path or any of its parent components is a symlink."""
    try:
        current = path
        while True:
            if current.is_symlink():
                return True
            if stop_at is not None and current == stop_at:
                break
            if current.parent == current:
                break
            current = current.parent
    except OSError:
        return True
    return False


def _find_git_root(path: Path) -> Path | None:
    """Walk parent directories to locate the enclosing .git root."""
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


@dataclass(frozen=True)
class SourceSnapshotInfo:
    """Deterministic snapshot metadata for static source verification."""

    source_revision: str | None
    git_head: str | None
    tree_sha256: str | None
    is_dirty: bool
    error: str | None = None


def resolve_source_snapshot(target_root: str | Path, subpath: str = ".") -> SourceSnapshotInfo:
    """Deterministically resolve source snapshot revision, tree hash, and dirty status."""
    resolved_root = Path(target_root).resolve()
    if subpath and subpath != ".":
        target_path = (resolved_root / subpath).resolve()
    else:
        target_path = resolved_root

    if not target_path.exists():
        return SourceSnapshotInfo(
            source_revision=None,
            git_head=None,
            tree_sha256=None,
            is_dirty=False,
            error=f"Target path does not exist: {target_path}",
        )

    files_to_hash: list[tuple[str, Path]] = []
    if target_path.is_file():
        if target_path.is_symlink():
            return SourceSnapshotInfo(
                source_revision=None,
                git_head=None,
                tree_sha256=None,
                is_dirty=False,
                error=f"Symlinked source file is not permitted: {target_path}",
            )
        files_to_hash.append((target_path.name, target_path))
    else:
        for candidate in sorted(target_path.rglob("*")):
            if candidate.is_symlink():
                return SourceSnapshotInfo(
                    source_revision=None,
                    git_head=None,
                    tree_sha256=None,
                    is_dirty=False,
                    error=f"Symlinked source file is not permitted: {candidate}",
                )
            try:
                rel = candidate.relative_to(target_path)
            except ValueError:
                continue
            if any(part in _IGNORED_DIRS for part in rel.parts):
                continue
            if candidate.is_file():
                files_to_hash.append((rel.as_posix(), candidate))

    hasher = hashlib.sha256()
    for rel_posix, file_path in sorted(files_to_hash, key=lambda x: x[0]):
        rel_bytes = rel_posix.encode("utf-8")
        hasher.update(len(rel_bytes).to_bytes(8, "big"))
        hasher.update(rel_bytes)
        try:
            file_content = file_path.read_bytes()
        except OSError as exc:
            return SourceSnapshotInfo(
                source_revision=None,
                git_head=None,
                tree_sha256=None,
                is_dirty=False,
                error=f"Failed to read source file {file_path}: {exc}",
            )
        hasher.update(len(file_content).to_bytes(8, "big"))
        hasher.update(file_content)
    tree_sha256 = hasher.hexdigest() if files_to_hash else None

    git_root = _find_git_root(resolved_root)
    git_head: str | None = None
    is_dirty = False

    if git_root is not None:
        try:
            completed_head = subprocess.run(
                [
                    "git",
                    "-c",
                    f"safe.directory={git_root.as_posix()}",
                    "rev-parse",
                    "HEAD",
                ],
                cwd=git_root,
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if completed_head.returncode == 0:
                head_str = completed_head.stdout.strip()
                if head_str and len(head_str) >= 7 and "\n" not in head_str:
                    git_head = head_str
        except (OSError, subprocess.TimeoutExpired):
            pass

        if git_head is not None:
            try:
                rel_to_git = target_path.relative_to(git_root).as_posix()
            except ValueError:
                rel_to_git = "."

            try:
                status_cmd = [
                    "git",
                    "-c",
                    f"safe.directory={git_root.as_posix()}",
                    "status",
                    "--porcelain=v1",
                    "-z",
                    "--untracked-files=all",
                ]
                if rel_to_git != ".":
                    status_cmd.extend(["--", rel_to_git])

                completed_status = subprocess.run(
                    status_cmd,
                    cwd=git_root,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if completed_status.returncode == 0:
                    status_out = completed_status.stdout.strip()
                    is_dirty = bool(status_out)
            except (OSError, subprocess.TimeoutExpired):
                pass

    return SourceSnapshotInfo(
        source_revision=git_head,
        git_head=git_head,
        tree_sha256=tree_sha256,
        is_dirty=is_dirty,
        error=None,
    )


def _source_revision(target_root: str) -> str | None:
    return resolve_source_snapshot(target_root).source_revision


__all__ = [
    "_IGNORED_DIRS",
    "SourceSnapshotInfo",
    "_find_git_root",
    "_has_symlink_component",
    "_source_revision",
    "resolve_source_snapshot",
]
