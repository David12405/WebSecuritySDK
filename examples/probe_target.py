"""Direct Layer 6 recon verification runner.

This utility intentionally bypasses MCP, Layer 5 authorization and Agent
runtime. Use it only against targets the operator is authorized to assess.

Examples::

    python examples/probe_target.py 192.168.56.10
    python examples/probe_target.py https://example.com --tool get_response_headers
    python examples/probe_target.py 192.168.56.10 --json recon-report.json
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from mcp_servers.websec_tools import probes  # noqa: E402

try:
    from mcp_servers.websec_tools import recon as recon_tools  # noqa: E402
except ImportError:
    from mcp_servers.websec_tools import nmap, openapi, whatweb, zap  # noqa: E402

    class _FlatReconTools:
        nmap = nmap
        openapi = openapi
        whatweb = whatweb
        zap = zap

    recon_tools = _FlatReconTools()
from mcp_servers.websec_tools.errors import ToolError, safe_message  # noqa: E402

TOOL_ORDER = (
    "discover_hosts",
    "discover_services",
    "get_response_headers",
    "get_cookies",
    "get_tls_info",
    "get_cors_policy",
    "fingerprint_web",
    "crawl_web",
    "passive_web_analysis",
    "parse_api_spec",
)
OPENAPI_CANDIDATE_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/v3/api-docs",
)
MAX_WEB_TARGETS = 10

ToolCall = Callable[[str], Awaitable[dict[str, Any]]]


def _is_url(value: str) -> bool:
    parsed = urlsplit(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


def _classify_target(target: str) -> str:
    if not isinstance(target, str) or not target.strip():
        raise ValueError("target is empty")
    if "://" in target:
        try:
            probes._validate_target(target)
        except ToolError as exc:
            raise ValueError(exc.message) from exc
        return "url"
    try:
        recon_tools.nmap._validate_target(target)
    except ToolError as exc:
        raise ValueError(exc.message) from exc
    return "network"


def _canonical_url(target: str) -> str:
    probes._validate_target(target)
    parsed = urlsplit(target)
    hostname = parsed.hostname or ""
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ToolError("E_INVALID_TARGET", "target hostname is invalid") from exc
    port = parsed.port
    if ":" in hostname:
        host = f"[{hostname}]"
    else:
        host = hostname
    if port is not None and not (
        (parsed.scheme == "http" and port == 80)
        or (parsed.scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))


def _network_target(target: str) -> str:
    if _is_url(target):
        return urlsplit(target).hostname or target
    return target


def _build_url(address: str, scheme: str, port: int | None) -> str:
    host = address
    try:
        if ipaddress.ip_address(address).version == 6:
            host = f"[{address}]"
    except ValueError:
        host = address.encode("idna").decode("ascii").lower()
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    return f"{scheme}://{host}/"


def _service_scheme(service: Mapping[str, Any]) -> str | None:
    try:
        port = int(service.get("port"))
    except (TypeError, ValueError):
        return None
    name = str(service.get("service") or "").lower()
    tunnel = str(service.get("tunnel") or "").lower()
    if (
        name == "https"
        or ("ssl" in name and "http" in name)
        or tunnel in {"ssl", "tls"}
        or port in {443, 8443, 9443}
    ):
        return "https"
    if "http" in name or port in {80, 8000, 8080, 8888}:
        return "http"
    return None


def _derive_web_targets(service_result: Mapping[str, Any]) -> list[str]:
    candidates: set[str] = set()
    data = service_result.get("data")
    if not isinstance(data, Mapping):
        return []
    for host in data.get("hosts", []):
        if not isinstance(host, Mapping):
            continue
        address = host.get("address")
        if not isinstance(address, str):
            continue
        for service in host.get("services", []):
            if not isinstance(service, Mapping):
                continue
            scheme = _service_scheme(service)
            if scheme is None:
                continue
            port = service.get("port")
            port = port if isinstance(port, int) else None
            candidates.add(_build_url(address, scheme, port))
    return sorted(candidates)[:MAX_WEB_TARGETS]


def _limit_web_targets(targets: Sequence[str], pinned: str | None = None) -> list[str]:
    unique = set(targets)
    if pinned is not None:
        unique.add(pinned)
    if pinned is not None:
        remaining = sorted(unique - {pinned})[: MAX_WEB_TARGETS - 1]
        return sorted([pinned, *remaining])
    return sorted(unique)[:MAX_WEB_TARGETS]


def _looks_like_openapi_url(target: str) -> bool:
    path = urlsplit(target).path.lower()
    return "openapi" in path or "swagger" in path or path.rstrip("/") == "/v3/api-docs"


def _origin_url(target: str) -> str:
    parsed = urlsplit(target)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _openapi_candidates(web_targets: Sequence[str], input_url: str | None) -> list[str]:
    candidates: list[str] = []
    if input_url and _looks_like_openapi_url(input_url):
        candidates.append(input_url)
    for target in web_targets:
        origin = _origin_url(target)
        for suffix in OPENAPI_CANDIDATE_PATHS:
            candidates.append(origin.rstrip("/") + suffix)
    return list(dict.fromkeys(candidates))


def _empty_tool_result(status: str, reason: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"status": status, "invocations": []}
    if reason is not None:
        result["reason"] = reason
    return result


def _aggregate(
    invocations: list[dict[str, Any]], skipped_reason: str | None = None
) -> dict[str, Any]:
    if any(item["status"] == "error" for item in invocations):
        status = "error"
    elif any(item["status"] == "success" for item in invocations):
        status = "success"
    else:
        status = "skipped"
    output: dict[str, Any] = {"status": status, "invocations": invocations}
    if status == "skipped" and skipped_reason:
        output["reason"] = skipped_reason
    return output


async def _call_one(
    target: str,
    tool: ToolCall,
) -> dict[str, Any]:
    try:
        result = await tool(target)
        if not isinstance(result, dict) or set(result) != {"summary", "data", "truncated"}:
            raise ToolError("E_INTERNAL", "tool returned an invalid envelope")
        return {"target": target, "status": "success", "result": result}
    except ToolError as exc:
        return {
            "target": target,
            "status": "error",
            "error": {"code": exc.code, "message": safe_message(exc, "tool failed")},
        }
    except Exception:
        return {
            "target": target,
            "status": "error",
            "error": {"code": "E_INTERNAL", "message": "tool failed"},
        }


def _tool_calls() -> dict[str, ToolCall]:
    return {
        "discover_hosts": recon_tools.nmap.discover_hosts,
        "discover_services": recon_tools.nmap.discover_services,
        "get_response_headers": probes.get_response_headers,
        "get_cookies": probes.get_cookies,
        "get_tls_info": probes.get_tls_info,
        "get_cors_policy": probes.get_cors_policy,
        "fingerprint_web": recon_tools.whatweb.fingerprint_web,
        "crawl_web": recon_tools.zap.crawl_web,
        "passive_web_analysis": recon_tools.zap.passive_web_analysis,
        "parse_api_spec": recon_tools.openapi.parse_api_spec,
    }


async def _run_explicit(target: str, selected: Sequence[str]) -> tuple[dict[str, Any], int]:
    calls = _tool_calls()
    results: dict[str, Any] = {}
    for name in TOOL_ORDER:
        if name not in selected:
            continue
        invocation = await _call_one(target, calls[name])
        results[name] = _aggregate([invocation])
    report = {
        "target": target,
        "web_targets": [_canonical_url(target)] if _is_url(target) else [],
        "results": results,
    }
    return report, 1 if any(item["status"] != "success" for item in results.values()) else 0


async def _run_openapi_candidates(
    candidates: Sequence[str],
    calls: Mapping[str, ToolCall],
) -> dict[str, Any]:
    non_match_codes = {"E_HTTP", "E_PARSE", "E_UNSUPPORTED_INPUT"}
    for candidate in candidates:
        invocation = await _call_one(candidate, calls["parse_api_spec"])
        if invocation["status"] == "success":
            return _aggregate([invocation])
        error = invocation.get("error", {})
        if error.get("code") not in non_match_codes:
            return _aggregate([invocation])
    return _empty_tool_result("skipped", "no OpenAPI specification discovered")


async def _run_all(target: str) -> tuple[dict[str, Any], int]:
    kind = _classify_target(target)
    input_url = _canonical_url(target) if kind == "url" else None
    network_target = _network_target(target)
    calls = _tool_calls()
    results: dict[str, Any] = {}
    host_invocation = await _call_one(network_target, calls["discover_hosts"])
    service_invocation = await _call_one(
        network_target, calls["discover_services"]
    )
    results["discover_hosts"] = _aggregate([host_invocation])
    results["discover_services"] = _aggregate([service_invocation])

    web_targets: list[str] = []
    if input_url:
        web_targets.append(input_url)
    if service_invocation["status"] == "success":
        derived = _derive_web_targets(service_invocation["result"])
        web_targets = _limit_web_targets([*web_targets, *derived], pinned=input_url)
    else:
        web_targets = _limit_web_targets(web_targets, pinned=input_url)

    for name in (
        "get_response_headers",
        "get_cookies",
        "get_tls_info",
        "get_cors_policy",
        "fingerprint_web",
        "crawl_web",
        "passive_web_analysis",
    ):
        invocations: list[dict[str, Any]] = []
        for web_target in web_targets:
            if name == "get_tls_info" and not web_target.lower().startswith("https://"):
                continue
            invocations.append(await _call_one(web_target, calls[name]))
        results[name] = _aggregate(invocations, "no applicable web target discovered")

    results["parse_api_spec"] = await _run_openapi_candidates(
        _openapi_candidates(web_targets, input_url), calls
    )
    report = {"target": target, "web_targets": web_targets, "results": results}
    failed = any(item["status"] == "error" for item in results.values())
    return report, 1 if failed else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run direct Layer 6 recon verification")
    parser.add_argument("target", help="absolute HTTP(S) URL, hostname, IP or CIDR")
    parser.add_argument("--tool", action="append", choices=(*TOOL_ORDER, "all"))
    parser.add_argument("--json", dest="json_path", type=Path)
    return parser


async def run_recon(
    target: str, selected: Sequence[str] | None = None
) -> tuple[dict[str, Any], int]:
    selected = tuple(selected or ("all",))
    if selected == ("all",):
        return await _run_all(target)
    if "all" in selected:
        raise ValueError("--tool all cannot be combined with other tools")
    _classify_target(target)
    return await _run_explicit(target, selected)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    selected = tuple(args.tool or ("all",))
    try:
        report, exit_code = asyncio.run(run_recon(args.target, selected))
    except ValueError as exc:
        parser.error(str(exc))
    except ToolError as exc:
        report = {
            "target": args.target,
            "web_targets": [],
            "results": {
                "runner": {
                    "status": "error",
                    "error": {"code": exc.code, "message": safe_message(exc, "runner failed")},
                }
            },
        }
        exit_code = 1
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    print(payload, end="")
    if args.json_path is not None:
        args.json_path.write_text(payload, encoding="utf-8", newline="\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
