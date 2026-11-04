"""Concurrency-safe async adapter, strict offline ruleset guard, and scope validator for M2-T03."""

from __future__ import annotations

import asyncio
import os
import re
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

    async def analyze(self, target_root: str, subpath: str = ".") -> dict[str, Any]:
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

    async def analyze(self, target_root: str, subpath: str = ".") -> dict[str, Any]:
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
        base_runner = self._runner or l6_semgrep._default_runner

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
        # 4. Stamp accurate per-invocation ruleset provenance onto the returned envelope
        if isinstance(envelope_result, dict) and isinstance(envelope_result.get("data"), dict):
            envelope_result["data"]["ruleset"] = "local-approved"
            envelope_result["data"]["ruleset_ref"] = ruleset_ref
            envelope_result["data"]["ruleset_path"] = approved_ruleset
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
    "validate_offline_ruleset_path",
    "validate_source_analysis_scope",
]
