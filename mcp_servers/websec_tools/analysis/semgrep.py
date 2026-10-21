"""Server-controlled, bounded Semgrep integration."""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Awaitable, Callable

from pydantic import BaseModel, ConfigDict

from ..errors import ToolError, envelope
from .source import (
    IGNORED_DIRS,
    _resolve_relative,
    _validate_root,
    is_analyzer_safe,
    is_exposure_safe,
    relative_path,
)

DEFAULT_SEMGREP_PATH = "semgrep"
DEFAULT_RULESET = "p/default"
GLOBAL_TIMEOUT = 120.0
MAX_JSON_BYTES = 10 * 1024 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_FINDINGS = 500
MAX_OPTIONAL_DEPTH = 6
MAX_OPTIONAL_ENTRIES = 50
MAX_OPTIONAL_STRING = 2_048
_REGISTRY_RULESET = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SemgrepFinding(_Model):
    rule_id: str
    file: str
    start_line: int
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None
    message: str | None = None
    severity: str | None = None
    snippet: str | None = None
    metadata: dict[str, Any] | None = None
    metavariables: dict[str, Any] | None = None
    dataflow_trace: Any | None = None


class SemgrepAnalysisResult(_Model):
    tool: str = "semgrep"
    version: str | None = None
    ruleset: str
    status: str
    path: str
    files_scanned: int | None = None
    findings: list[SemgrepFinding]
    errors: list[Any]


def _configuration(value: str | None, *, executable: bool = False) -> str:
    if value is None:
        return DEFAULT_SEMGREP_PATH if executable else DEFAULT_RULESET
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or any(ord(c) < 32 for c in value)
    ):
        raise ToolError("E_TOOL_UNAVAILABLE", "Semgrep configuration is invalid")
    if value.startswith("-"):
        raise ToolError("E_TOOL_UNAVAILABLE", "Semgrep configuration is invalid")
    if executable:
        return value
    if _REGISTRY_RULESET.fullmatch(value):
        return value
    local = Path(value)
    if not local.is_absolute() or not local.exists():
        raise ToolError("E_TOOL_UNAVAILABLE", "Semgrep configuration is invalid")
    return str(local.resolve())


def _ruleset() -> tuple[str, str]:
    raw = os.environ.get("WEBSEC_SEMGREP_RULESET")
    configured = _configuration(raw)
    return configured, "local-approved" if Path(configured).is_absolute() else configured


def _cap(value: Any, depth: int = 0) -> Any:
    if depth >= MAX_OPTIONAL_DEPTH:
        return None
    if isinstance(value, str):
        return value[:MAX_OPTIONAL_STRING]
    if isinstance(value, list):
        return [_cap(item, depth + 1) for item in value[:MAX_OPTIONAL_ENTRIES]]
    if isinstance(value, dict):
        return {
            str(k)[:MAX_OPTIONAL_STRING]: _cap(v, depth + 1)
            for k, v in list(value.items())[:MAX_OPTIONAL_ENTRIES]
        }
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return None


def _safe_diagnostic(value: Any, root: Path) -> Any:
    capped = _cap(value)
    if isinstance(capped, dict):
        if isinstance(capped.get("path"), str):
            try:
                capped["path"] = relative_path(root, _resolve_reported_path(root, capped["path"]))
            except ToolError:
                capped.pop("path", None)
        return capped
    return capped


def _location(value: Any) -> tuple[int, int | None]:
    if not isinstance(value, dict):
        return 0, None
    line = value.get("line")
    column = value.get("col")
    return (line if isinstance(line, int) and line > 0 else 0,
            column if isinstance(column, int) and column > 0 else None)


def _resolve_reported_path(root: Path, value: str) -> Path:
    reported = Path(value)
    if reported.is_absolute():
        try:
            resolved = reported.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            raise ToolError("E_PARSE", "Semgrep output is invalid") from None
        if not is_analyzer_safe(resolved):
            raise ToolError("E_PARSE", "Semgrep output is invalid")
        return resolved
    return _resolve_relative(root, value, reject_symlink=True)


def _normalize(
    raw: dict[str, Any], root: Path, path: str, ruleset: str
) -> tuple[dict[str, Any], bool]:
    results = raw.get("results")
    if not isinstance(results, list):
        raise ToolError("E_PARSE", "Semgrep output is invalid")
    errors = raw.get("errors", [])
    if not isinstance(errors, list):
        errors = []
    paths = raw.get("paths")
    files_scanned: int | None = None
    if (
        isinstance(paths, dict)
        and isinstance(paths.get("scanned"), list)
        and all(isinstance(item, str) for item in paths["scanned"])
    ):
        files_scanned = len(paths["scanned"])
    findings: list[SemgrepFinding] = []
    truncated = len(results) > MAX_FINDINGS
    for item in results[:MAX_FINDINGS]:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("check_id"), str)
            or not isinstance(item.get("path"), str)
        ):
            continue
        try:
            finding_path = _resolve_reported_path(root, item["path"])
        except ToolError:
            continue
        if not is_analyzer_safe(finding_path):
            continue
        start_line, start_col = _location(item.get("start"))
        end_line, end_col = _location(item.get("end"))
        if start_line == 0:
            continue
        extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
        exposed = is_exposure_safe(finding_path)
        metavars = extra.get("metavars") if isinstance(extra.get("metavars"), dict) else None
        if not exposed and metavars is not None:
            metavars = {
                key: value for key, value in metavars.items()
                if not (isinstance(value, dict) and "abstract_content" in value)
            }
        trace = extra.get("dataflow_trace") if exposed else None
        snippet = extra.get("lines") if exposed and isinstance(extra.get("lines"), str) else None
        findings.append(SemgrepFinding(
            rule_id=item["check_id"], file=relative_path(root, finding_path),
            start_line=start_line, start_column=start_col, end_line=end_line or None,
            end_column=end_col,
            message=extra.get("message") if isinstance(extra.get("message"), str) else None,
            severity=extra.get("severity") if isinstance(extra.get("severity"), str) else None,
            snippet=snippet[:MAX_OPTIONAL_STRING] if snippet else None,
            metadata=(
                _cap(extra.get("metadata"))
                if isinstance(extra.get("metadata"), dict) else None
            ),
            metavariables=_cap(metavars) if metavars is not None else None,
            dataflow_trace=_cap(trace) if trace is not None else None,
        ))
    version = raw.get("version") if isinstance(raw.get("version"), str) else None
    result = SemgrepAnalysisResult(
        ruleset=ruleset,
        status="completed",
        path=relative_path(root, _resolve_relative(root, path, reject_symlink=True)),
        version=version, files_scanned=files_scanned, findings=findings,
        errors=[_safe_diagnostic(error, root) for error in errors],
    ).model_dump(mode="json")
    return result, truncated


Runner = Callable[[list[str], Path, Path, Path], Awaitable[int]]


async def _default_runner(argv: list[str], cwd: Path, output_path: Path, stderr_path: Path) -> int:
    child_env = os.environ.copy()
    child_env.pop("SEMGREP_APP_TOKEN", None)
    child_env["SEMGREP_SEND_METRICS"] = "off"
    stderr_handle = stderr_path.open("wb")
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd),
            env=child_env,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=stderr_handle,
        )
        wait_task = asyncio.create_task(process.wait())
        try:
            while True:
                done, _ = await asyncio.wait({wait_task}, timeout=0.1)
                if output_path.exists() and output_path.stat().st_size > MAX_JSON_BYTES:
                    process.kill()
                    await process.wait()
                    raise ToolError("E_TOOL_FAILED", "Semgrep output is too large")
                if stderr_path.exists() and stderr_path.stat().st_size > MAX_STDERR_BYTES:
                    process.kill()
                    await process.wait()
                    raise ToolError("E_TOOL_FAILED", "Semgrep diagnostics are too large")
                if done:
                    return int(wait_task.result() or 0)
        except asyncio.CancelledError:
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
        finally:
            if not wait_task.done():
                wait_task.cancel()
    except FileNotFoundError:
        raise ToolError("E_TOOL_UNAVAILABLE", "Semgrep is unavailable") from None
    except OSError:
        raise ToolError("E_TOOL_UNAVAILABLE", "Semgrep is unavailable") from None
    finally:
        stderr_handle.close()


async def analyze_source(
    target: str, path: str = ".", *, runner: Runner | None = None
) -> dict[str, Any]:
    root = _validate_root(target)
    scan_path = _resolve_relative(root, path, reject_symlink=True)
    if not scan_path.is_dir() and not scan_path.is_file():
        raise ToolError("E_INVALID_ARGUMENT", "scan path is invalid")
    executable = _configuration(os.environ.get("WEBSEC_SEMGREP_PATH"), executable=True)
    configured_ruleset, output_ruleset = _ruleset()
    relative_scan = relative_path(root, scan_path)
    with tempfile.TemporaryDirectory(prefix="websec-semgrep-") as temp_name:
        temp = Path(temp_name)
        output_path, stderr_path = temp / "result.json", temp / "stderr.log"
        argv = [
            executable, "scan", f"--json-output={output_path}",
            f"--config={configured_ruleset}", "--oss-only", "--metrics=off",
            "--disable-version-check", "--no-autofix", "--max-target-bytes=1000000",
            "--max-lines-per-finding=10", "--max-chars-per-line=200", "--timeout=5",
            "--timeout-threshold=3", "--jobs=1",
        ]
        argv.extend(f"--exclude={name}" for name in sorted(IGNORED_DIRS))
        argv.append(relative_scan)
        execute = runner or _default_runner
        try:
            code = await asyncio.wait_for(
                execute(argv, root, output_path, stderr_path), timeout=GLOBAL_TIMEOUT
            )
        except asyncio.TimeoutError:
            raise ToolError("E_TIMEOUT", "Semgrep timed out") from None
        if code != 0:
            raise ToolError("E_TOOL_FAILED", "Semgrep failed")
        try:
            if not output_path.exists() or output_path.stat().st_size > MAX_JSON_BYTES:
                raise ToolError("E_PARSE", "Semgrep output is invalid")
            raw = json.loads(output_path.read_text(encoding="utf-8"))
        except ToolError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            raise ToolError("E_PARSE", "Semgrep output is invalid") from None
    if not isinstance(raw, dict):
        raise ToolError("E_PARSE", "Semgrep output is invalid")
    data, truncated = _normalize(raw, root, path, output_ruleset)
    return envelope(
        f"Semgrep completed with {len(data['findings'])} findings", data, truncated=truncated
    )


__all__ = ["analyze_source", "SemgrepAnalysisResult", "SemgrepFinding"]
