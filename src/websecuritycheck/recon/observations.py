"""Deterministic, cohesive observation extraction from L6 JSON results."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from websecuritycheck.domain import (
    AuthenticationObservationPayload,
    BrowserBehaviorObservationPayload,
    EndpointObservationPayload,
    EvidenceArtifactRecord,
    InputLocation,
    NetworkHostObservationPayload,
    NetworkServiceObservationPayload,
    ObservationRecord,
    ObservationSource,
    ObservationType,
    ObservedParameter,
    RedirectObservationPayload,
    TechnologyCategory,
    TechnologyObservationPayload,
    ToolExecutionResult,
)

from .evidence import RecordIdAllocator, evidence_refs


def _data(execution: ToolExecutionResult) -> dict[str, Any]:
    data = execution.result_data
    if isinstance(data.get("data"), dict):
        return data["data"]
    return data


def _now(execution: ToolExecutionResult) -> datetime:
    return execution.finished_at or execution.started_at or datetime.now(UTC)


def _url_parts(url: str) -> tuple[str, str]:
    parsed = urlsplit(url)
    origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    return origin, parsed.path or "/"


def _parameters_from_query(url: str, refs: list[str]) -> list[ObservedParameter]:
    parsed = urlsplit(url)
    return [
        ObservedParameter(name=name, location=InputLocation.QUERY, evidence_refs=refs)
        for name, _value in sorted(set(parse_qsl(parsed.query, keep_blank_values=True)))
    ]


def _record(
    execution: ToolExecutionResult,
    allocator: RecordIdAllocator,
    observation_type: ObservationType,
    payload: Any,
    refs: list[str],
    locator: str | None = None,
) -> ObservationRecord:
    return ObservationRecord(
        observation_id=allocator.new("OBS"),
        assessment_id=execution.assessment_id,
        observation_type=observation_type,
        payload=payload,
        source_type=_source(execution.result_type),
        source_tool_id=execution.tool_id,
        execution_ref=execution.execution_id,
        evidence_refs=refs,
        source_locator=locator,
        observed_at=_now(execution),
    )


def _source(result_type: str) -> ObservationSource:
    value = result_type.upper()
    if "OPENAPI" in value or "API_SPEC" in value or "APISPEC" in value:
        return ObservationSource.API_SPEC
    if value == "ZAP_PROXY_TRAFFIC":
        return ObservationSource.ZAP_PROXY
    if "ZAP" in value or "CRAWL" in value:
        return ObservationSource.ZAP
    if "WHATWEB" in value or "FINGERPRINT" in value:
        return ObservationSource.WHATWEB
    if "BROWSER" in value or "PLAYWRIGHT" in value:
        return ObservationSource.BROWSER
    if "NMAP" in value:
        return ObservationSource.NMAP
    return ObservationSource.HTTP_OBSERVATION


def _http(
    execution: ToolExecutionResult, allocator: RecordIdAllocator, refs: list[str]
) -> list[ObservationRecord]:
    data = _data(execution)
    url = str(data.get("url") or data.get("final_url") or execution.target or "")
    if not url:
        return []
    origin, path = _url_parts(url)
    method = str(data.get("method") or "GET").upper()
    request_types = [str(data["request_content_type"])] if data.get("request_content_type") else []
    response_type = data.get("response_content_type") or data.get("content_type")
    response_types = [str(response_type)] if response_type else []
    params = list(data.get("parameters") or [])
    if not params:
        params = _parameters_from_query(url, refs)
    body_location = (
        InputLocation.JSON_BODY
        if "json" in str(data.get("request_content_type") or "").lower()
        else InputLocation.FORM
    )
    params.extend(
        ObservedParameter(name=str(name), location=body_location, evidence_refs=refs)
        for name in data.get("request_parameter_names", [])
        if not any(getattr(item, "name", None) == str(name) for item in params)
    )
    payload = EndpointObservationPayload(
        origin=origin,
        path=path,
        method=method,
        request_content_types=request_types,
        response_content_types=response_types,
        parameters=params,
        status=data.get("status"),
        response_headers=dict(data.get("headers") or {}),
    )
    result = [_record(execution, allocator, ObservationType.ENDPOINT, payload, refs)]
    for index, redirect in enumerate(data.get("redirects") or []):
        result.append(
            _record(
                execution,
                allocator,
                ObservationType.HTTP_METADATA,
                RedirectObservationPayload(
                    from_url=str(redirect.get("from") or redirect.get("from_url")),
                    to_url=str(redirect.get("to") or redirect.get("to_url")),
                    status=int(redirect.get("status", 302)),
                    followed=True,
                ),
                refs,
                f"redirects[{index}]",
            )
        )
    if data.get("cookies") or data.get("session_present") is not None:
        result.append(
            _record(
                execution,
                allocator,
                ObservationType.AUTHENTICATION,
                AuthenticationObservationPayload(
                    subject=url,
                    session_present=data.get("session_present"),
                    cookie_names=[
                        str(item.get("name"))
                        for item in data.get("cookies", [])
                        if isinstance(item, dict)
                    ],
                ),
                refs,
            )
        )
    return result


def _zap_items(
    execution: ToolExecutionResult,
    allocator: RecordIdAllocator,
    refs: list[str],
    items: list[Any],
    locator_name: str,
) -> list[ObservationRecord]:
    records: list[ObservationRecord] = []
    for index, endpoint in enumerate(items):
        if not isinstance(endpoint, dict):
            continue
        url = str(endpoint.get("url") or "")
        if not url:
            continue
        origin, path = _url_parts(url)
        parameters = [
            ObservedParameter(name=str(name), location=InputLocation.QUERY, evidence_refs=refs)
            for name in endpoint.get("query_parameter_names", [])
        ]
        parameters.extend(
            ObservedParameter(name=str(name), location=InputLocation.JSON_BODY, evidence_refs=refs)
            for name in endpoint.get("body_parameter_names", [])
        )
        records.append(
            _record(
                execution,
                allocator,
                ObservationType.ENDPOINT,
                EndpointObservationPayload(
                    origin=origin,
                    path=path,
                    method=str(endpoint.get("method") or "GET").upper(),
                    parameters=parameters,
                    status=endpoint.get("status"),
                    response_content_types=[str(endpoint["content_type"])]
                    if endpoint.get("content_type")
                    else [],
                ),
                refs,
                f"{locator_name}[{index}]",
            )
        )
    return records


def _zap(
    execution: ToolExecutionResult, allocator: RecordIdAllocator, refs: list[str]
) -> list[ObservationRecord]:
    data = _data(execution)
    return _zap_items(execution, allocator, refs, data.get("endpoints") or [], "endpoints")


def _zap_proxy(
    execution: ToolExecutionResult, allocator: RecordIdAllocator, refs: list[str]
) -> list[ObservationRecord]:
    data = _data(execution)
    return _zap_items(execution, allocator, refs, data.get("messages") or [], "messages")


def _openapi(
    execution: ToolExecutionResult, allocator: RecordIdAllocator, refs: list[str]
) -> list[ObservationRecord]:
    data = _data(execution)
    records: list[ObservationRecord] = []
    source_origin = data.get("source_origin")
    if not source_origin and data.get("source_url"):
        source_origin, _source_path = _url_parts(str(data["source_url"]))
    if not source_origin and data.get("servers"):
        first_server = data["servers"][0]
        if isinstance(first_server, dict):
            source_origin = first_server.get("url")
    source_origin = str(source_origin or execution.target or "")
    for index, operation in enumerate(data.get("operations") or []):
        if not isinstance(operation, dict):
            continue
        params: list[ObservedParameter] = []
        for parameter in operation.get("parameters") or []:
            if not isinstance(parameter, dict):
                continue
            location = str(parameter.get("location") or parameter.get("in") or "").upper()
            location_map = {
                "QUERY": InputLocation.QUERY,
                "PATH": InputLocation.PATH,
                "HEADER": InputLocation.HEADER,
                "COOKIE": InputLocation.COOKIE,
                "FORMDATA": InputLocation.MULTIPART,
                "FORM": InputLocation.FORM,
            }
            if location not in location_map:
                continue
            params.append(
                ObservedParameter(
                    name=str(parameter.get("name")),
                    location=location_map[location],
                    data_type=parameter.get("schema_type"),
                    required=parameter.get("required"),
                    content_type=parameter.get("content_type"),
                    evidence_refs=refs,
                )
            )
        for body in operation.get("body_fields") or []:
            if isinstance(body, str):
                body_location = InputLocation.JSON_BODY
                if any(
                    "multipart" in str(item).lower()
                    for item in operation.get("request_content_types", [])
                ):
                    body_location = InputLocation.MULTIPART
                elif any(
                    "form-urlencoded" in str(item).lower()
                    for item in operation.get("request_content_types", [])
                ):
                    body_location = InputLocation.FORM
                params.append(
                    ObservedParameter(name=body, location=body_location, evidence_refs=refs)
                )
        records.append(
            _record(
                execution,
                allocator,
                ObservationType.ENDPOINT,
                EndpointObservationPayload(
                    origin=source_origin,
                    path=str(operation.get("path") or "/"),
                    method=str(operation.get("method") or "GET").upper(),
                    request_content_types=[
                        str(item) for item in operation.get("request_content_types", [])
                    ],
                    response_content_types=[
                        str(item) for item in operation.get("response_content_types", [])
                    ],
                    parameters=params,
                    declared_security=[
                        str(item.get("scheme_name"))
                        for item in operation.get("security", [])
                        if isinstance(item, dict)
                    ],
                ),
                refs,
                f"operations[{index}]",
            )
        )
    return records


def _whatweb(
    execution: ToolExecutionResult, allocator: RecordIdAllocator, refs: list[str]
) -> list[ObservationRecord]:
    records: list[ObservationRecord] = []
    for index, technology in enumerate(_data(execution).get("technologies") or []):
        if not isinstance(technology, dict):
            continue
        categories = technology.get("categories") or []
        category = str(
            technology.get("category") or (categories[0] if categories else "OTHER")
        ).upper()
        category_aliases = {
            "WEB SERVERS": "WEB_SERVER",
            "WEB SERVER": "WEB_SERVER",
            "FRAMEWORKS": "FRAMEWORK",
            "CMS": "CMS",
            "PLATFORMS": "PLATFORM",
            "RUNTIMES": "RUNTIME",
            "DATABASES": "DATABASE",
            "WAF": "WAF",
        }
        category = category_aliases.get(category, category)
        try:
            category_value = TechnologyCategory(category)
        except ValueError:
            category_value = TechnologyCategory.OTHER
        records.append(
            _record(
                execution,
                allocator,
                ObservationType.TECHNOLOGY,
                TechnologyObservationPayload(
                    name=str(technology.get("name") or "Unknown"),
                    category=category_value,
                    version=(
                        technology.get("version") or (technology.get("versions") or [None])[0]
                    ),
                    confidence=str(technology.get("confidence") or "UNKNOWN").upper(),
                ),
                refs,
                f"technologies[{index}]",
            )
        )
    return records


def _browser(
    execution: ToolExecutionResult, allocator: RecordIdAllocator, refs: list[str]
) -> list[ObservationRecord]:
    data = _data(execution)
    records: list[ObservationRecord] = []
    for index, event in enumerate(data.get("network_events") or []):
        if not isinstance(event, dict) or not event.get("url"):
            continue
        url = str(event["url"])
        origin, path = _url_parts(url)
        records.append(
            _record(
                execution,
                allocator,
                ObservationType.ENDPOINT,
                EndpointObservationPayload(
                    origin=origin,
                    path=path,
                    method=str(event.get("method") or "GET").upper(),
                    request_content_types=[str(event["request_content_type"])]
                    if event.get("request_content_type")
                    else [],
                    response_content_types=[str(event["response_content_type"])]
                    if event.get("response_content_type")
                    else [],
                    status=event.get("response_status"),
                    parameters=[
                        ObservedParameter(
                            name=str(name), location=InputLocation.QUERY, evidence_refs=refs
                        )
                        for name in event.get("query_parameter_names", [])
                    ],
                ),
                refs,
                f"network_events[{index}]",
            )
        )
    for index, action in enumerate(data.get("actions") or []):
        if isinstance(action, dict):
            records.append(
                _record(
                    execution,
                    allocator,
                    ObservationType.BROWSER_BEHAVIOR,
                    BrowserBehaviorObservationPayload(
                        action_id=action.get("action_id"),
                        event=str(action.get("kind") or action.get("event") or "action"),
                        url=action.get("url"),
                        related_network_event_ids=[
                            str(item) for item in action.get("network_event_ids", [])
                        ],
                    ),
                    refs,
                    f"actions[{index}]",
                )
            )
    return records


def _nmap(
    execution: ToolExecutionResult, allocator: RecordIdAllocator, refs: list[str]
) -> list[ObservationRecord]:
    data = _data(execution)
    records: list[ObservationRecord] = []
    for host_index, host in enumerate(data.get("hosts") or []):
        if not isinstance(host, dict):
            continue
        address = str(host.get("address") or "")
        records.append(
            _record(
                execution,
                allocator,
                ObservationType.NETWORK_HOST,
                NetworkHostObservationPayload(
                    address=address,
                    hostnames=list(host.get("hostnames") or []),
                    state=str(host.get("state") or "unknown"),
                ),
                refs,
                f"hosts[{host_index}]",
            )
        )
        for service_index, service in enumerate(host.get("services") or []):
            if isinstance(service, dict):
                records.append(
                    _record(
                        execution,
                        allocator,
                        ObservationType.NETWORK_SERVICE,
                        NetworkServiceObservationPayload(
                            address=address,
                            port=int(service.get("port")),
                            protocol=str(service.get("protocol") or "unknown"),
                            state=str(service.get("state") or "unknown"),
                            service=service.get("service"),
                            product=service.get("product"),
                            version=service.get("version"),
                        ),
                        refs,
                        f"hosts[{host_index}].services[{service_index}]",
                    )
                )
    return records


def extract_observations(
    execution: ToolExecutionResult,
    evidence: list[EvidenceArtifactRecord],
    *,
    allocator: RecordIdAllocator | None = None,
) -> list[ObservationRecord]:
    allocator = allocator or RecordIdAllocator()
    refs = evidence_refs(evidence)
    result_type = execution.result_type.upper()
    if result_type == "ZAP_PROXY_TRAFFIC":
        return _zap_proxy(execution, allocator, refs)
    if "ZAP" in result_type or "CRAWL" in result_type:
        return _zap(execution, allocator, refs)
    if "OPENAPI" in result_type or "API_SPEC" in result_type:
        return _openapi(execution, allocator, refs)
    if "WHATWEB" in result_type or "FINGERPRINT" in result_type:
        return _whatweb(execution, allocator, refs)
    if "BROWSER" in result_type or "PLAYWRIGHT" in result_type:
        return _browser(execution, allocator, refs)
    if "NMAP" in result_type:
        return _nmap(execution, allocator, refs)
    return _http(execution, allocator, refs)
