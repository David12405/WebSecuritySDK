"""Concurrency-safe async adapter, strict offline ruleset guard, and scope validator for M2-T03."""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import subprocess
import uuid

from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from typing import Any, Protocol, runtime_checkable

from mcp_servers.websec_tools.analysis import semgrep as l6_semgrep
from mcp_servers.websec_tools.errors import ToolError
from websecuritycheck.domain.analysis_models import Module2AnalysisRequest
from websecuritycheck.domain.enums import TestingMode

_REGISTRY_RULESET_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ALLOWED_RULESET_SUFFIXES = frozenset({".yaml", ".yml", ".json"})
_MAX_RULESET_DIR_SCAN_FILES = 500
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


@runtime_checkable
class AsyncSourceAnalysisPort(Protocol):
    """Asynchronous port interface for running static source analysis."""

    async def analyze(
        self,
        target_root: str,
        subpath: str = ".",
        *,
        source_repository_ref: str | None = None,
    ) -> dict[str, Any]:
        """Return a Layer 6 Semgrep envelope or raw Semgrep JSON dictionary."""
        ...


def _normalize_logical_abs_path(raw_path: str) -> tuple[PurePath, str] | None:
    """Normalize a logical absolute path (POSIX or Windows) and reject traversal."""
    cleaned = raw_path.strip()
    if not cleaned or "\x00" in cleaned or any(ord(c) < 32 for c in cleaned):
        return None
    cleaned_fwd = cleaned.replace("\\", "/")
    is_win = bool(re.match(r"^[A-Za-z]:", cleaned_fwd))
    is_posix = cleaned_fwd.startswith("/")
    if not (is_win or is_posix):
        return None

    pure: PurePath = PureWindowsPath(cleaned) if is_win else PurePosixPath(cleaned_fwd)
    if ".." in pure.parts:
        return None
    return pure, cleaned_fwd


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


def _directory_has_rule_file(directory: Path) -> bool:
    """Verify that a local ruleset directory contains at least one non-symlinked YAML/JSON file."""
    inspected = 0
    stack = [directory]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                return False
            if entry.is_dir():
                if entry.name not in _IGNORED_DIRS:
                    stack.append(entry)
            elif entry.is_file():
                inspected += 1
                if entry.suffix.lower() in _ALLOWED_RULESET_SUFFIXES:
                    return True
                if inspected >= _MAX_RULESET_DIR_SCAN_FILES:
                    return False
    return False


def _ruleset_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    files: list[Path] = []
    for candidate in sorted(path.rglob("*")):
        if candidate.is_symlink():
            raise ToolError("E_TOOL_UNAVAILABLE", "Symlinked Semgrep rules are not permitted")
        if any(part in _IGNORED_DIRS for part in candidate.relative_to(path).parts):
            continue
        if candidate.is_file() and candidate.suffix.lower() in _ALLOWED_RULESET_SUFFIXES:
            files.append(candidate)
        if len(files) > _MAX_RULESET_DIR_SCAN_FILES:
            raise ToolError("E_TOOL_UNAVAILABLE", "Semgrep ruleset directory is too large")
    return files


def compute_ruleset_sha256(ruleset_path: str | Path) -> str:
    """Return a stable digest for one approved rule file or a rule directory."""
    resolved = Path(validate_offline_ruleset_path(ruleset_path))
    if resolved.is_file():
        # Preserve the conventional sha256sum value for a single ruleset file.
        return hashlib.sha256(resolved.read_bytes()).hexdigest()

    digest = hashlib.sha256()
    base = resolved
    for rule_file in _ruleset_files(resolved):
        relative = rule_file.relative_to(base).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        content = rule_file.read_bytes()
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _find_git_root(path: Path) -> Path | None:
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

    # Compute deterministic tree_sha256
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

    # Resolve Git metadata
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



def validate_source_analysis_scope(
    request: Module2AnalysisRequest,
    *,
    require_existing_filesystem: bool = False,
) -> tuple[str | None, str | None]:
    """Strictly validate whether static source analysis is authorized.

    No bypass flags exist. Both offline payload parsing and live filesystem
    scanning require:
    1. target_model.scope_rules is present.
    2. scope_rules.testing_mode is GRAYBOX or WHITEBOX (never BLACKBOX).
    3. scope_rules.source_repository_ref is configured and non-empty.
    4. request.source_repo_path is provided and stays within source_repository_ref.
    5. When require_existing_filesystem=True, both paths must exist on disk as
       non-symlinked directories and resolve within the approved repository root.
    """
    rules = request.target_model.scope_rules
    if rules is None:
        return (
            None,
            "Refused static source analysis: TargetModel.scope_rules is missing",
        )

    if rules.testing_mode == TestingMode.BLACKBOX:
        return (
            None,
            "Static source code analysis is not permitted when testing_mode is BLACKBOX",
        )

    raw_repo = request.source_repo_path
    if raw_repo is None or not raw_repo.strip():
        return (
            None,
            "No source_repo_path provided in Module2AnalysisRequest; "
            "skipped Semgrep static analysis",
        )

    approved_ref = rules.source_repository_ref
    if approved_ref is None or not approved_ref.strip():
        return (
            None,
            "AssessmentConfig.source_repository_ref is not configured; "
            "refused to analyze unapproved source_repo_path",
        )

    target_norm = _normalize_logical_abs_path(raw_repo)
    approved_norm = _normalize_logical_abs_path(approved_ref)
    if target_norm is None:
        return (
            None,
            f"Refused to analyze invalid or relative source_repo_path {raw_repo!r}",
        )
    if approved_norm is None:
        return (
            None,
            "Refused to analyze source code: scope_rules.source_repository_ref "
            f"{approved_ref!r} is not a valid absolute path",
        )

    pure_target, str_target = target_norm
    pure_approved, _str_approved = approved_norm

    # Check relative-to relationship
    try:
        is_rel = pure_target.is_relative_to(pure_approved)
    except (ValueError, TypeError):
        is_rel = False

    if not is_rel:
        return (
            None,
            f"Refused to analyze unauthorized source_repo_path {raw_repo!r} "
            f"outside approved source_repository_ref {approved_ref!r}",
        )

    if require_existing_filesystem:
        try:
            approved_path = Path(approved_ref.strip())
            target_path = Path(raw_repo.strip())
            if not approved_path.is_absolute() or not target_path.is_absolute():
                return (
                    None,
                    "Refused live Semgrep scan: repository paths must be OS-absolute",
                )
            if _has_symlink_component(approved_path) or _has_symlink_component(target_path):
                return (
                    None,
                    "Refused live Semgrep scan: symlinked repository paths are not permitted",
                )
            resolved_approved = approved_path.resolve(strict=True)
            resolved_target = target_path.resolve(strict=True)
            if not resolved_approved.is_dir() or not resolved_target.is_dir():
                return (
                    None,
                    "Refused live Semgrep scan: repository path is not an existing directory",
                )
            resolved_target.relative_to(resolved_approved)
            return (str(resolved_target), None)
        except (OSError, RuntimeError, ValueError):
            return (
                None,
                f"Refused live Semgrep scan: {raw_repo!r} could not be verified "
                f"within approved directory {approved_ref!r}",
            )

    return (str_target, None)


def validate_offline_ruleset_path(ruleset_value: str | Path | None = None) -> str:
    """Strictly validate an existing local Semgrep YAML/JSON ruleset file or rules directory.

    Unconditionally rejects missing rulesets, relative paths, symlinks, URLs,
    remote registry rulesets (e.g. 'p/default', 'r/python'), non-YAML/JSON files,
    and directories without valid rule files. Never mutates os.environ.
    """
    if ruleset_value is not None:
        raw = str(ruleset_value).strip()
    else:
        env_raw = os.environ.get("WEBSEC_SEMGREP_RULESET")
        raw = env_raw.strip() if isinstance(env_raw, str) else ""

    if not raw:
        raise ToolError(
            "E_TOOL_UNAVAILABLE",
            "Strict offline Semgrep policy requires an explicit local ruleset path "
            "(via ruleset_path or WEBSEC_SEMGREP_RULESET); remote rulesets are prohibited",
        )
    if "\x00" in raw or any(ord(c) < 32 for c in raw) or raw.startswith("-"):
        raise ToolError("E_TOOL_UNAVAILABLE", "Semgrep ruleset configuration is invalid")

    if "://" in raw or _REGISTRY_RULESET_RE.fullmatch(raw):
        raise ToolError(
            "E_TOOL_UNAVAILABLE",
            f"Remote Semgrep registry ruleset {raw!r} is strictly prohibited; "
            "provide an existing absolute local ruleset path",
        )

    candidate = Path(raw)
    if not candidate.is_absolute() or _has_symlink_component(candidate) or not candidate.exists():
        raise ToolError(
            "E_TOOL_UNAVAILABLE",
            f"Local Semgrep ruleset path {raw!r} must be an existing non-symlinked absolute path",
        )
    resolved = candidate.resolve(strict=True)
    if resolved.is_file():
        if resolved.suffix.lower() not in _ALLOWED_RULESET_SUFFIXES:
            raise ToolError(
                "E_TOOL_UNAVAILABLE",
                f"Local Semgrep ruleset file {raw!r} must have a .yaml, .yml, or .json extension",
            )
        return str(resolved)
    if resolved.is_dir():
        if not _directory_has_rule_file(resolved):
            raise ToolError(
                "E_TOOL_UNAVAILABLE",
                f"Local Semgrep ruleset directory {raw!r} must contain at least one "
                "non-symlinked .yaml, .yml, or .json rule file",
            )
        return str(resolved)
    raise ToolError(
        "E_TOOL_UNAVAILABLE",
        f"Local Semgrep ruleset path {raw!r} must be a regular YAML/JSON file or directory",
    )


def _validate_layer6_startup_env() -> str | None:
    """Validate Layer 6 process-environment startup dependencies without mutating os.environ.

    Layer 6 analyze_source() unconditionally reads WEBSEC_SEMGREP_PATH (line 271)
    and WEBSEC_SEMGREP_RULESET (line 272) BEFORE invoking the injected runner.
    Therefore:
    - If WEBSEC_SEMGREP_PATH is set in os.environ, it must be non-empty and valid.
    - If WEBSEC_SEMGREP_RULESET is set in os.environ, it must be a valid local
      offline ruleset path (never '', a broken path, or a remote registry ruleset).
    Returns the validated environment ruleset path if set, or None if unset.
    """
    env_exec = os.environ.get("WEBSEC_SEMGREP_PATH")
    if env_exec is not None and (
        not isinstance(env_exec, str)
        or not env_exec
        or "\x00" in env_exec
        or any(ord(c) < 32 for c in env_exec)
        or env_exec.startswith("-")
    ):
        raise ToolError(
            "E_TOOL_UNAVAILABLE",
            "Process environment variable WEBSEC_SEMGREP_PATH is invalid",
        )

    env_ruleset = os.environ.get("WEBSEC_SEMGREP_RULESET")
    if env_ruleset is not None:
        return validate_offline_ruleset_path(env_ruleset)
    return None


class LocalSemgrepAdapter:
    """Concurrency-safe async adapter wrapping Layer 6 Semgrep with strict offline rulesets.

    Never mutates process-global os.environ. Validates Layer 6 startup environment
    compatibility and the per-invocation local ruleset upfront, binds the approved
    ruleset to an isolated per-call runner closure, and stamps accurate ruleset
    provenance ('local-approved' + 'ruleset_ref') onto the returned envelope.
    """

    def __init__(
        self,
        *,
        ruleset_path: str | Path | None = None,
        runner: l6_semgrep.Runner | None = None,
    ) -> None:
        self._ruleset_path = ruleset_path
        self._runner = runner

    async def analyze(
        self,
        target_root: str,
        subpath: str = ".",
        *,
        source_repository_ref: str | None = None,
    ) -> dict[str, Any]:
        # 1. Verify Layer 6 startup environment variables so line 271-272 of Layer 6
        #    cannot fail unpredictably or accept an unapproved remote ruleset.
        validated_env_ruleset = _validate_layer6_startup_env()

        # 2. Resolve and validate the per-invocation local ruleset BEFORE calling Layer 6.
        if self._ruleset_path is not None:
            approved_ruleset = validate_offline_ruleset_path(self._ruleset_path)
        elif validated_env_ruleset is not None:
            approved_ruleset = validated_env_ruleset
        else:
            raise ToolError(
                "E_TOOL_UNAVAILABLE",
                "Strict offline Semgrep policy requires an explicit local ruleset path "
                "(via ruleset_path or WEBSEC_SEMGREP_RULESET); remote rulesets are prohibited",
            )

        ruleset_ref = Path(approved_ruleset).name
        execution_ref = f"EXEC-{uuid.uuid4().int}"
        base_runner = self._runner or l6_semgrep._default_runner

        # Pre-scan TOCTOU capture
        pre_ruleset_sha256 = compute_ruleset_sha256(approved_ruleset)
        pre_snapshot = resolve_source_snapshot(target_root, subpath)
        if pre_snapshot.error:
            raise ToolError("E_TOOL_UNAVAILABLE", pre_snapshot.error)

        # 3. Bind approved_ruleset into a per-call runner closure (zero os.environ mutation)
        async def _isolated_runner(
            argv: list[str], cwd: Path, output_path: Path, stderr_path: Path
        ) -> int:
            config_args = [arg for arg in argv if arg.startswith("--config=")]
            if len(config_args) != 1:
                msg = (
                    "Unexpected Semgrep command structure: expected exactly one --config argument, "
                    f"found {len(config_args)}"
                )
                raise ToolError("E_TOOL_FAILED", msg)
            rewritten_argv = [
                f"--config={approved_ruleset}" if arg.startswith("--config=") else arg
                for arg in argv
            ]
            return await base_runner(rewritten_argv, cwd, output_path, stderr_path)

        envelope_result = await l6_semgrep.analyze_source(
            target_root, subpath, runner=_isolated_runner
        )

        # Post-scan TOCTOU verification
        post_ruleset_sha256 = compute_ruleset_sha256(approved_ruleset)
        post_snapshot = resolve_source_snapshot(target_root, subpath)
        if pre_ruleset_sha256 != post_ruleset_sha256:
            raise ToolError(
                "E_TOOL_FAILED",
                "Provenance integrity check failed: ruleset mutated during Semgrep execution",
            )
        if (
            pre_snapshot.git_head != post_snapshot.git_head
            or pre_snapshot.tree_sha256 != post_snapshot.tree_sha256
        ):
            raise ToolError(
                "E_TOOL_FAILED",
                "Provenance integrity check failed: source files mutated during Semgrep execution",
            )

        # 4. Stamp accurate per-invocation ruleset provenance onto the returned envelope
        if isinstance(envelope_result, dict) and isinstance(envelope_result.get("data"), dict):
            data = envelope_result["data"]
            data["ruleset"] = "local-approved"
            data["ruleset_ref"] = ruleset_ref
            data["ruleset_path"] = approved_ruleset
            data["ruleset_sha256"] = pre_ruleset_sha256
            data["execution_ref"] = execution_ref
            data["source_repo_path"] = str(Path(target_root).resolve())
            if source_repository_ref is not None:
                data["source_repository_ref"] = source_repository_ref
            if pre_snapshot.source_revision is not None:
                data["source_revision"] = pre_snapshot.source_revision
            if pre_snapshot.tree_sha256 is not None:
                data["source_tree_sha256"] = pre_snapshot.tree_sha256
            data["worktree_dirty"] = pre_snapshot.is_dirty
            data["derivation_modality"] = "static_source_snapshot"
        return envelope_result

    def run_sync(self, target_root: str, subpath: str = ".") -> dict[str, Any]:
        """Synchronous convenience wrapper ONLY for standalone non-async callers."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.analyze(target_root, subpath))
        raise RuntimeError(
            "LocalSemgrepAdapter.run_sync() cannot be called inside a running asyncio "
            "event loop; use 'await adapter.analyze(...)' or "
            "'await aextract_sink_candidates(...)' instead"
        )


__all__ = [
    "AsyncSourceAnalysisPort",
    "LocalSemgrepAdapter",
    "SourceSnapshotInfo",
    "compute_ruleset_sha256",
    "resolve_source_snapshot",
    "validate_offline_ruleset_path",
    "validate_source_analysis_scope",
]
