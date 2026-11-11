"""Strict offline ruleset validation and repository authorization scope checks."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

from mcp_servers.websec_tools.errors import ToolError
from websecuritycheck.domain.analysis_models import Module2AnalysisRequest
from websecuritycheck.domain.enums import TestingMode

from .snapshot import _IGNORED_DIRS, _has_symlink_component

_REGISTRY_RULESET_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ALLOWED_RULESET_SUFFIXES = frozenset({".yaml", ".yml", ".json"})
_MAX_RULESET_DIR_SCAN_FILES = 500


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
            raise ToolError("E_TOOL_UNAVAILABLE", "Symlinked Opengrep rules are not permitted")
        if any(part in _IGNORED_DIRS for part in candidate.relative_to(path).parts):
            continue
        if candidate.is_file() and candidate.suffix.lower() in _ALLOWED_RULESET_SUFFIXES:
            files.append(candidate)
        if len(files) > _MAX_RULESET_DIR_SCAN_FILES:
            raise ToolError("E_TOOL_UNAVAILABLE", "Opengrep ruleset directory is too large")
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
            "skipped Opengrep static analysis",
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
                    "Refused live Opengrep scan: repository paths must be OS-absolute",
                )
            if _has_symlink_component(approved_path) or _has_symlink_component(target_path):
                return (
                    None,
                    "Refused live Opengrep scan: symlinked repository paths are not permitted",
                )
            resolved_approved = approved_path.resolve(strict=True)
            resolved_target = target_path.resolve(strict=True)
            if not resolved_approved.is_dir() or not resolved_target.is_dir():
                return (
                    None,
                    "Refused live Opengrep scan: repository path is not an existing directory",
                )
            resolved_target.relative_to(resolved_approved)
            return (str(resolved_target), None)
        except (OSError, RuntimeError, ValueError):
            return (
                None,
                f"Refused live Opengrep scan: {raw_repo!r} could not be verified "
                f"within approved directory {approved_ref!r}",
            )

    return (str_target, None)


def validate_offline_ruleset_path(ruleset_value: str | Path | None = None) -> str:
    """Strictly validate an existing local Opengrep YAML/JSON ruleset file or rules directory.

    Unconditionally rejects missing rulesets, relative paths, symlinks, URLs,
    remote registry rulesets (e.g. 'p/default', 'r/python'), non-YAML/JSON files,
    and directories without valid rule files. Never mutates os.environ.
    """
    if ruleset_value is not None:
        raw = str(ruleset_value).strip()
    else:
        env_raw = os.environ.get("WEBSEC_OPENGREP_RULESET")
        raw = env_raw.strip() if isinstance(env_raw, str) else ""

    if not raw:
        raise ToolError(
            "E_TOOL_UNAVAILABLE",
            "Strict offline Opengrep policy requires an explicit local ruleset path "
            "(via ruleset_path or WEBSEC_OPENGREP_RULESET); remote rulesets are prohibited",
        )
    if "\x00" in raw or any(ord(c) < 32 for c in raw) or raw.startswith("-"):
        raise ToolError("E_TOOL_UNAVAILABLE", "Opengrep ruleset configuration is invalid")

    if "://" in raw or _REGISTRY_RULESET_RE.fullmatch(raw):
        raise ToolError(
            "E_TOOL_UNAVAILABLE",
            f"Remote Opengrep registry ruleset {raw!r} is strictly prohibited; "
            "provide an existing absolute local ruleset path",
        )

    candidate = Path(raw)
    if not candidate.is_absolute() or _has_symlink_component(candidate) or not candidate.exists():
        raise ToolError(
            "E_TOOL_UNAVAILABLE",
            f"Local Opengrep ruleset path {raw!r} must be an existing non-symlinked absolute path",
        )
    resolved = candidate.resolve(strict=True)
    if resolved.is_file():
        if resolved.suffix.lower() not in _ALLOWED_RULESET_SUFFIXES:
            raise ToolError(
                "E_TOOL_UNAVAILABLE",
                f"Local Opengrep ruleset file {raw!r} must have a .yaml, .yml, or .json extension",
            )
        return str(resolved)
    if resolved.is_dir():
        if not _directory_has_rule_file(resolved):
            raise ToolError(
                "E_TOOL_UNAVAILABLE",
                f"Local Opengrep ruleset directory {raw!r} must contain at least one "
                "non-symlinked .yaml, .yml, or .json rule file",
            )
        return str(resolved)
    raise ToolError(
        "E_TOOL_UNAVAILABLE",
        f"Local Opengrep ruleset path {raw!r} must be a regular YAML/JSON file or directory",
    )


__all__ = [
    "compute_ruleset_sha256",
    "validate_offline_ruleset_path",
    "validate_source_analysis_scope",
]

