"""Constrained, machine-readable Nmap tools for Layer 6."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import os
import re
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..errors import ToolError, envelope

MAX_HOSTS = 256
MAX_PORTS = 100
MAX_XML_BYTES = 10 * 1024 * 1024
NMAP_TIMEOUT_SECONDS = 120.0
NMAP_EXECUTABLE = "nmap"
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)

Runner = Callable[[list[str], float], Awaitable[tuple[int, bytes, bytes]]]


class NmapHost(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    address_type: Literal["ipv4", "ipv6", "mac", "unknown"]
    hostnames: list[str] = Field(default_factory=list)
    state: str
    state_reason: str | None = None


class NetworkService(BaseModel):
    model_config = ConfigDict(extra="forbid")

    port: int = Field(ge=1, le=65535)
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    tunnel: str | None = None
    cpe: list[str] = Field(default_factory=list)


class NmapServiceHost(BaseModel):
    model_config = ConfigDict(extra="forbid")

    address: str
    address_type: str
    hostnames: list[str] = Field(default_factory=list)
    state: str
    services: list[NetworkService] = Field(default_factory=list)


class NmapHostDiscoveryResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    profile: Literal["host-discovery"]
    hosts: list[NmapHost] = Field(default_factory=list)
    artifact_manifests: list[dict[str, Any]] = Field(default_factory=list)


class NmapServiceDiscoveryResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    profile: Literal["service-top-100", "service-explicit-ports"]
    requested_ports: list[int] = Field(default_factory=list)
    hosts: list[NmapServiceHost] = Field(default_factory=list)
    artifact_manifests: list[dict[str, Any]] = Field(default_factory=list)


def _validate_target(target: str) -> ipaddress._BaseNetwork | ipaddress._BaseAddress | str:
    if not isinstance(target, str) or not target or any(char in target for char in "?#"):
        raise ToolError("E_INVALID_TARGET", "target must be a hostname, IP address or CIDR")
    if "://" in target or any(char.isspace() for char in target):
        raise ToolError("E_INVALID_TARGET", "target must not be a URL or contain whitespace")
    try:
        parsed = ipaddress.ip_network(target, strict=False)
    except ValueError:
        try:
            parsed = ipaddress.ip_address(target)
        except ValueError:
            if not _HOSTNAME_RE.fullmatch(target):
                raise ToolError("E_INVALID_TARGET", "target is not a valid host or CIDR") from None
            return target
    if parsed.num_addresses > MAX_HOSTS:
        raise ToolError("E_INVALID_ARGUMENT", f"target expands to more than {MAX_HOSTS} hosts")
    return parsed


def _address_type(value: str | None) -> str:
    if value in {"ipv4", "ipv6", "mac"}:
        return value
    return "unknown"


def _text(element: ET.Element | None, attribute: str | None = None) -> str | None:
    if element is None:
        return None
    value = element.attrib.get(attribute) if attribute is not None else element.text
    if value is None:
        return None
    value = value.strip()
    return value or None


def parse_nmap_xml(
    xml_bytes: bytes,
    *,
    target: str,
    profile: str,
    ports: list[int] | None = None,
) -> BaseModel:
    if profile not in {"host-discovery", "service-top-100", "service-explicit-ports"}:
        raise ToolError("E_INVALID_ARGUMENT", "unsupported Nmap profile")
    if len(xml_bytes) > MAX_XML_BYTES:
        raise ToolError("E_TOOL_FAILED", "Nmap XML output exceeded the size limit")
    try:
        root = ET.fromstring(xml_bytes)
    except (ET.ParseError, ValueError) as exc:
        raise ToolError("E_PARSE", "Nmap XML output could not be parsed") from exc
    if root.tag != "nmaprun":
        raise ToolError("E_PARSE", "Nmap XML root is not nmaprun")

    hosts: list[NmapHost] = []
    service_hosts: list[NmapServiceHost] = []
    for host in root.findall("host"):
        addresses = host.findall("address")
        primary = next(
            (item for item in addresses if item.attrib.get("addrtype") in {"ipv4", "ipv6"}),
            None,
        )
        if primary is None:
            primary = addresses[0] if addresses else None
        address = _text(primary, "addr")
        if not address:
            continue
        hostnames = [
            name
            for item in host.findall("./hostnames/hostname")
            if (name := _text(item, "name"))
        ]
        status_node = host.find("status")
        status = _text(status_node, "state") or "unknown"
        reason = _text(status_node, "reason")
        address_type = _address_type(
            primary.attrib.get("addrtype") if primary is not None else None
        )
        if profile == "host-discovery":
            hosts.append(
                NmapHost(
                    address=address,
                    address_type=address_type,  # type: ignore[arg-type]
                    hostnames=sorted(hostnames),
                    state=status,
                    state_reason=reason,
                )
            )
            continue

        services: list[NetworkService] = []
        for port in host.findall("./ports/port"):
            try:
                port_number = int(port.attrib["portid"])
            except (KeyError, ValueError):
                continue
            state_node = port.find("state")
            service_node = port.find("service")
            services.append(
                NetworkService(
                    port=port_number,
                    protocol=port.attrib.get("protocol", "unknown"),
                    state=_text(state_node, "state") or "unknown",
                    service=_text(service_node, "name"),
                    product=_text(service_node, "product"),
                    version=_text(service_node, "version"),
                    extra_info=_text(service_node, "extrainfo"),
                    tunnel=_text(service_node, "tunnel"),
                    cpe=sorted(
                        value
                        for cpe in port.findall("./service/cpe")
                        if (value := _text(cpe))
                    ),
                )
            )
        service_hosts.append(
            NmapServiceHost(
                address=address,
                address_type=address_type,
                hostnames=sorted(hostnames),
                state=status,
                services=sorted(services, key=lambda item: (item.protocol, item.port)),
            )
        )

    if profile == "host-discovery":
        return NmapHostDiscoveryResult(
            target=target,
            profile="host-discovery",
            hosts=sorted(hosts, key=lambda item: (item.address, item.hostnames)),
        )
    return NmapServiceDiscoveryResult(
        target=target,
        profile=profile,  # type: ignore[arg-type]
        requested_ports=ports or [],
        hosts=sorted(service_hosts, key=lambda item: (item.address, item.hostnames)),
    )


async def _default_runner(argv: list[str], timeout: float) -> tuple[int, bytes, bytes]:
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise ToolError("E_TOOL_UNAVAILABLE", "Nmap executable is not available") from exc
    except OSError as exc:
        raise ToolError("E_TOOL_UNAVAILABLE", "Nmap executable could not be started") from exc
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.communicate()
        raise ToolError("E_TIMEOUT", "Nmap execution timed out") from exc
    except asyncio.CancelledError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.communicate()
        raise
    return process.returncode or 0, stdout, stderr


def _profile_args(
    target: str, profile: str, ports: Sequence[int] | None
) -> tuple[list[str], list[int]]:
    if profile == "host-discovery":
        if ports is not None:
            raise ToolError("E_INVALID_ARGUMENT", "ports is not valid for host-discovery")
        return ["-sn", "-n", "-oX", "-", target], []
    if profile == "service-top-100":
        if ports is not None:
            raise ToolError("E_INVALID_ARGUMENT", "ports is only valid for service-explicit-ports")
        return ["-sV", "-n", "--top-ports", "100", "-oX", "-", target], []
    if profile == "service-explicit-ports":
        if not ports:
            raise ToolError("E_INVALID_ARGUMENT", "ports is required for service-explicit-ports")
        normalized = sorted(set(ports))
        invalid = any(
            isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            for port in normalized
        )
        if len(normalized) > MAX_PORTS or invalid:
            raise ToolError(
                "E_INVALID_ARGUMENT",
                f"ports must contain at most {MAX_PORTS} values from 1 to 65535",
            )
        return ["-sV", "-n", "-p", ",".join(map(str, normalized)), "-oX", "-", target], normalized
    raise ToolError("E_INVALID_ARGUMENT", "unsupported Nmap profile")


async def _run_profile(
    target: str,
    profile: str,
    ports: Sequence[int] | None = None,
    *,
    runner: Runner | None = None,
    executable: str | None = None,
) -> tuple[BaseModel, bool]:
    _validate_target(target)
    args, normalized_ports = _profile_args(target, profile, ports)
    argv = [executable or os.getenv("WEBSEC_NMAP_PATH", NMAP_EXECUTABLE), *args]
    try:
        result = await (runner or _default_runner)(argv, NMAP_TIMEOUT_SECONDS)
    except ToolError:
        raise
    except TimeoutError as exc:
        raise ToolError("E_TIMEOUT", "Nmap execution timed out") from exc
    except OSError as exc:
        raise ToolError("E_TOOL_UNAVAILABLE", "Nmap executable could not be started") from exc
    except Exception as exc:
        raise ToolError("E_TOOL_FAILED", "Nmap execution failed") from exc
    returncode, stdout, _stderr = result
    if returncode != 0:
        raise ToolError("E_TOOL_FAILED", f"Nmap exited with code {returncode}")
    parsed = parse_nmap_xml(stdout, target=target, profile=profile, ports=normalized_ports)
    artifact = {
        "artifact_ref": f"nmap-xml-{hashlib.sha256(stdout).hexdigest()[:16]}",
        "artifact_type": "NETWORK_SCAN_RESULT",
        "content": stdout.decode("utf-8", errors="replace"),
        "media_type": "application/xml",
        "redaction_applied": True,
    }
    parsed = parsed.model_copy(update={"artifact_manifests": [artifact]})
    if isinstance(parsed, NmapHostDiscoveryResult):
        truncated = len(parsed.hosts) > MAX_HOSTS
        if truncated:
            parsed = parsed.model_copy(update={"hosts": parsed.hosts[:MAX_HOSTS]})
        return parsed, truncated
    truncated = len(parsed.hosts) > MAX_HOSTS
    if truncated:
        parsed = parsed.model_copy(update={"hosts": parsed.hosts[:MAX_HOSTS]})
    return parsed, truncated


async def discover_hosts(
    target: str,
    *,
    runner: Runner | None = None,
    executable: str | None = None,
) -> dict[str, Any]:
    parsed, truncated = await _run_profile(
        target, "host-discovery", runner=runner, executable=executable
    )
    result = NmapHostDiscoveryResult.model_validate(parsed)
    return envelope(
        f"Nmap discovered {len(result.hosts)} hosts for {target}",
        result.model_dump(mode="json"),
        truncated,
    )


async def discover_services(
    target: str,
    profile: Literal["service-top-100", "service-explicit-ports"] = "service-top-100",
    ports: list[int] | None = None,
    *,
    runner: Runner | None = None,
    executable: str | None = None,
) -> dict[str, Any]:
    parsed, truncated = await _run_profile(
        target, profile, ports, runner=runner, executable=executable
    )
    result = NmapServiceDiscoveryResult.model_validate(parsed)
    services = sum(len(host.services) for host in result.hosts)
    return envelope(
        f"Nmap discovered {len(result.hosts)} hosts and {services} services for {target}",
        result.model_dump(mode="json"),
        truncated,
    )
