"""Concurrency-safe async Opengrep adapter wrapping Layer 6 static analysis."""

from __future__ import annotations

import asyncio
import os
import uuid
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from mcp_servers.websec_tools.analysis import opengrep as l6_opengrep
from mcp_servers.websec_tools.errors import ToolError

from .scope import compute_ruleset_sha256, validate_offline_ruleset_path
from .snapshot import resolve_source_snapshot


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
        """Return a Layer 6 Opengrep envelope or raw Opengrep JSON dictionary."""
        ...


def _validate_layer6_startup_env() -> str | None:
    """Validate Layer 6 process-environment startup dependencies without mutating os.environ."""
    env_exec = os.environ.get("WEBSEC_OPENGREP_PATH")
    if (
        env_exec is not None
        and env_exec != ""
        and (
            not isinstance(env_exec, str)
            or not env_exec.strip()
            or "\x00" in env_exec
            or any(ord(c) < 32 for c in env_exec)
            or env_exec.startswith("-")
        )
    ):
        raise ToolError(
            "E_TOOL_UNAVAILABLE",
            "Process environment variable WEBSEC_OPENGREP_PATH is invalid",
        )

    env_ruleset = os.environ.get("WEBSEC_OPENGREP_RULESET")
    if env_ruleset is not None and env_ruleset != "":
        return validate_offline_ruleset_path(env_ruleset)
    return None


class LocalOpengrepAdapter:
    """Concurrency-safe async adapter wrapping Layer 6 Opengrep with strict offline rulesets."""

    def __init__(
        self,
        *,
        ruleset_path: str | Path | None = None,
        runner: l6_opengrep.Runner | None = None,
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
        validated_env_ruleset = _validate_layer6_startup_env()

        if self._ruleset_path is not None:
            approved_ruleset = validate_offline_ruleset_path(self._ruleset_path)
        elif validated_env_ruleset is not None:
            approved_ruleset = validated_env_ruleset
        else:
            raise ToolError(
                "E_TOOL_UNAVAILABLE",
                "Strict offline Opengrep policy requires an explicit local ruleset path "
                "(via ruleset_path or WEBSEC_OPENGREP_RULESET); remote rulesets are prohibited",
            )

        ruleset_ref = Path(approved_ruleset).name
        execution_ref = f"EXEC-{uuid.uuid4().int}"
        base_runner = self._runner or l6_opengrep._default_runner

        pre_ruleset_sha256 = compute_ruleset_sha256(approved_ruleset)
        pre_snapshot = resolve_source_snapshot(target_root, subpath)
        if pre_snapshot.error:
            raise ToolError("E_TOOL_UNAVAILABLE", pre_snapshot.error)

        async def _isolated_runner(
            argv: list[str], cwd: Path, output_path: Path, stderr_path: Path
        ) -> int:
            config_args = [arg for arg in argv if arg.startswith("--config=")]
            if len(config_args) != 1:
                msg = (
                    "Unexpected Opengrep command structure: expected one --config argument, "
                    f"found {len(config_args)}"
                )
                raise ToolError("E_TOOL_FAILED", msg)
            rewritten_argv = [
                f"--config={approved_ruleset}" if arg.startswith("--config=") else arg
                for arg in argv
            ]
            return await base_runner(rewritten_argv, cwd, output_path, stderr_path)

        envelope_result = await l6_opengrep.analyze_source(
            target_root, subpath, runner=_isolated_runner
        )

        post_ruleset_sha256 = compute_ruleset_sha256(approved_ruleset)
        post_snapshot = resolve_source_snapshot(target_root, subpath)
        if pre_ruleset_sha256 != post_ruleset_sha256:
            raise ToolError(
                "E_TOOL_FAILED",
                "Provenance integrity check failed: ruleset mutated during Opengrep execution",
            )
        if (
            pre_snapshot.git_head != post_snapshot.git_head
            or pre_snapshot.tree_sha256 != post_snapshot.tree_sha256
        ):
            raise ToolError(
                "E_TOOL_FAILED",
                "Provenance integrity check failed: source files mutated during Opengrep execution",
            )

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
            "LocalOpengrepAdapter.run_sync() cannot be called inside a running asyncio "
            "event loop; use 'await adapter.analyze(...)' or "
            "'await aextract_sink_candidates(...)' instead"
        )


__all__ = [
    "AsyncSourceAnalysisPort",
    "LocalOpengrepAdapter",
]

