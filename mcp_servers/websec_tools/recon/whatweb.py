"""Constrained WhatWeb fingerprinting for Layer 6."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..errors import ToolError, envelope
from ..probes import _validate_target

MAX_OUTPUT_BYTES = 10 * 1024 * 1024
WHATWEB_TIMEOUT_SECONDS = 60.0
MAX_TECHNOLOGIES = 200
ALLOWED_ATTRIBUTES = frozenset(
    {"string", "account", "module", "filepath", "os", "description", "website", "engine"}
)

Runner = Callable[[list[str], Path, float], Awaitable[int]]


class TechnologyAttribute(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    values: list[str] = Field(default_factory=list)


class TechnologyFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    versions: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)
    certainty: int | None = None
    confidence: str
    attributes: list[TechnologyAttribute] = Field(default_factory=list)


class WebFingerprintResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    technologies: list[TechnologyFingerprint] = Field(default_factory=list)
    artifact_manifests: list[dict[str, Any]] = Field(default_factory=list)


def _as_strings(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return sorted({str(item) for item in values if isinstance(item, (str, int, float))})


def _confidence(certainty: int | None) -> str:
    if certainty is None:
        return "HIGH"
    if not 0 <= certainty <= 100:
        return "UNKNOWN"
    if certainty < 40:
        return "LOW"
    if certainty < 80:
        return "MEDIUM"
    return "HIGH"


def parse_whatweb_json(raw: bytes, *, target: str) -> WebFingerprintResult:
    if len(raw) > MAX_OUTPUT_BYTES:
        raise ToolError("E_TOOL_FAILED", "WhatWeb output exceeded the size limit")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolError("E_PARSE", "WhatWeb JSON output could not be parsed") from exc

    records = document if isinstance(document, list) else [document]
    plugins: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        candidate = record.get("plugins")
        if isinstance(candidate, dict):
            for name, details in candidate.items():
                if isinstance(name, str) and isinstance(details, dict):
                    plugins[name] = details
    technologies: list[TechnologyFingerprint] = []
    for name in sorted(plugins):
        details = plugins[name]
        raw_certainty = details.get("certainty")
        certainty = (
            raw_certainty
            if isinstance(raw_certainty, int) and not isinstance(raw_certainty, bool)
            else 100
        )
        attributes: list[TechnologyAttribute] = []
        for attribute_name in sorted(details):
            if attribute_name not in ALLOWED_ATTRIBUTES:
                continue
            values = _as_strings(details[attribute_name])
            if values:
                attributes.append(TechnologyAttribute(name=attribute_name, values=values))
        technologies.append(
            TechnologyFingerprint(
                name=name,
                versions=_as_strings(details.get("version", details.get("versions"))),
                categories=_as_strings(details.get("categories")),
                certainty=certainty,
                confidence=_confidence(certainty),
                attributes=attributes,
            )
        )
    return WebFingerprintResult(
        target=target,
        technologies=technologies[:MAX_TECHNOLOGIES],
        artifact_manifests=[{
            "artifact_ref": f"whatweb-output-{hashlib.sha256(raw).hexdigest()[:16]}",
            "artifact_type": "TOOL_RAW_OUTPUT",
            "content": raw.decode("utf-8", errors="replace"),
            "media_type": "application/json",
            "redaction_applied": False,
        }],
    )


async def _default_runner(argv: list[str], output_path: Path, timeout: float) -> int:
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise ToolError("E_TOOL_UNAVAILABLE", "WhatWeb executable is not available") from exc
    except OSError as exc:
        raise ToolError("E_TOOL_UNAVAILABLE", "WhatWeb executable could not be started") from exc
    try:
        _stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError as exc:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.communicate()
        raise ToolError("E_TIMEOUT", "WhatWeb execution timed out") from exc
    except asyncio.CancelledError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.communicate()
        raise
    return process.returncode or 0


async def fingerprint_web(
    target: str,
    *,
    runner: Runner | None = None,
    executable: str | None = None,
) -> dict[str, Any]:
    _validate_target(target)
    executable = executable or os.getenv("WEBSEC_WHATWEB_PATH", "whatweb")
    with tempfile.TemporaryDirectory(prefix="websec-whatweb-") as directory:
        output_path = Path(directory) / "result.json"
        argv = [
            executable,
            "--aggression=1",
            "--follow-redirect=never",
            f"--log-json={output_path}",
            target,
        ]
        try:
            returncode = await (runner or _default_runner)(
                argv, output_path, WHATWEB_TIMEOUT_SECONDS
            )
        except ToolError:
            raise
        except TimeoutError as exc:
            raise ToolError("E_TIMEOUT", "WhatWeb execution timed out") from exc
        except OSError as exc:
            raise ToolError(
                "E_TOOL_UNAVAILABLE", "WhatWeb executable could not be started"
            ) from exc
        except Exception as exc:
            raise ToolError("E_TOOL_FAILED", "WhatWeb execution failed") from exc
        if returncode != 0:
            raise ToolError("E_TOOL_FAILED", f"WhatWeb exited with code {returncode}")
        try:
            raw = output_path.read_bytes()
        except FileNotFoundError as exc:
            raise ToolError("E_PARSE", "WhatWeb did not produce JSON output") from exc
        result = parse_whatweb_json(raw, target=target)
    return envelope(
        f"WhatWeb identified {len(result.technologies)} technologies on {target}",
        result.model_dump(mode="json"),
        len(result.technologies) >= MAX_TECHNOLOGIES,
    )
