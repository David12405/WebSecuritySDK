"""Deterministic, cohesive observation extraction from L6 JSON results."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from websecuritycheck.domain import (
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

from .endpoints import normalize_origin
from .evidence import RecordIdAllocator, evidence_refs


def _body_input_location(content_type: str | None) -> InputLocation | None:
    """Map an explicit request Content-Type header to a canonical InputLocation.

    Returns None when Content-Type is missing or unrecognized rather than
    guessing a body encoding.
    """
    if not content_type:
        return None
    media_type = content_type.split(";", 1)[0].strip().casefold()
    if media_type in {"application/json", "text/json"} or media_type.endswith("+json"):
        return InputLocation.JSON_BODY
    if media_type == "application/x-www-form-urlencoded":
        return InputLocation.FORM
    if media_type == "multipart/form-data":
        return InputLocation.MULTIPART
    if media_type in {"application/xml", "text/xml"} or media_type.endswith("+xml"):
        return InputLocation.XML_BODY
    return None


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


_OBSERVATION_SOURCES = {
    "HTTPPROBERESULT": ObservationSource.HTTP_OBSERVATION,
    "ZAP_CRAWL": ObservationSource.ZAP,
    "ZAP_PASSIVE": ObservationSource.ZAP,
    "ZAP_PROXY_TRAFFIC": ObservationSource.ZAP_PROXY,
    "OPENAPI_SPEC": ObservationSource.API_SPEC,
    "APISPECRESULT": ObservationSource.API_SPEC,
    "WHATWEB_FINGERPRINT": ObservationSource.WHATWEB,
    "BROWSER_FLOW": ObservationSource.BROWSER,
    "NMAP_SCAN": ObservationSource.NMAP,
}


def _source(result_type: str) -> ObservationSource:
    value = result_type.upper()
    if value in _OBSERVATION_SOURCES:
        return _OBSERVATION_SOURCES[value]
    if "OPENAPI" in value or "API_SPEC" in value or "APISPEC" in value:
        return ObservationSource.API_SPEC
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
    raw_request_ct = data.get("request_content_type")
    request_content_type = str(raw_request_ct) if raw_request_ct else None
    request_types = [request_content_type] if request_content_type else []
    response_type = data.get("response_content_type") or data.get("content_type")
    response_types = [str(response_type)] if response_type else []
    params = list(data.get("parameters") or [])
    if not params:
        params = _parameters_from_query(url, refs)
    body_location = _body_input_location(request_content_type)
    if body_location is not None:
        params.extend(
            ObservedParameter(
                name=str(name),
                location=body_location,
                content_type=request_content_type,
                evidence_refs=refs,
            )
            for name in data.get("request_parameter_names", [])
            if str(name)
            and not any(
                getattr(item, "name", None) == str(name)
                and getattr(item, "location", None) == body_location
                for item in params
            )
        )
    payload = EndpointObservationPayload(
        origin=origin,
        path=path,
        method=method,
        request_content_types=request_types,
        response_content_types=response_types,
        parameters=params,
        status=data.get("status"),
        response_headers=dict(data.get("response_headers") or data.get("headers") or {}),
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
        request_content_type = (
            str(endpoint["request_content_type"]) if endpoint.get("request_content_type") else None
        )
        parameters = [
            ObservedParameter(name=str(name), location=InputLocation.QUERY, evidence_refs=refs)
            for name in endpoint.get("query_parameter_names", [])
            if str(name)
        ]
        body_location = _body_input_location(request_content_type)
        if body_location is not None:
            parameters.extend(
                ObservedParameter(
                    name=str(name),
                    location=body_location,
                    content_type=request_content_type,
                    evidence_refs=refs,
                )
                for name in endpoint.get("body_parameter_names", [])
                if str(name)
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
                    request_content_types=[request_content_type] if request_content_type else [],
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
                ),
                refs,
                f"technologies[{index}]",
            )
        )
    return records


def _browser_network_events(
    execution: ToolExecutionResult,
    allocator: RecordIdAllocator,
    refs: list[str],
    data: dict[str, Any],
) -> list[ObservationRecord]:
    records: list[ObservationRecord] = []
    for index, event in enumerate(data.get("network_events") or []):
        if not isinstance(event, dict) or event.get("blocked") or not event.get("url"):
            continue
        url = str(event["url"])
        origin, path = _url_parts(url)
        raw_req_ct = event.get("request_content_type")
        req_ct = str(raw_req_ct) if raw_req_ct else None
        parameters = [
            ObservedParameter(name=str(name), location=InputLocation.QUERY, evidence_refs=refs)
            for name in event.get("query_parameter_names", [])
            if str(name)
        ]
        body_location = _body_input_location(req_ct)
        if body_location is not None:
            parameters.extend(
                ObservedParameter(
                    name=str(name),
                    location=body_location,
                    content_type=req_ct,
                    evidence_refs=refs,
                )
                for name in event.get("request_body_field_names", [])
                if str(name)
            )
        records.append(
            _record(
                execution,
                allocator,
                ObservationType.ENDPOINT,
                EndpointObservationPayload(
                    origin=origin,
                    path=path,
                    method=str(event.get("method") or "GET").upper(),
                    request_content_types=[req_ct] if req_ct else [],
                    response_content_types=[str(event["response_content_type"])]
                    if event.get("response_content_type")
                    else [],
                    status=event.get("response_status"),
                    parameters=parameters,
                ),
                refs,
                f"network_events[{index}]",
            )
        )
    return records


def _same_origin_http_url(candidate: str, expected_origin: str) -> bool:
    parsed = urlsplit(candidate)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return False
    return not expected_origin or normalize_origin(candidate) == expected_origin


def _browser_forms(
    execution: ToolExecutionResult,
    allocator: RecordIdAllocator,
    refs: list[str],
    data: dict[str, Any],
    base_url: str,
    expected_origin: str,
) -> list[ObservationRecord]:
    records: list[ObservationRecord] = []
    for index, form in enumerate(data.get("forms") or []):
        if not isinstance(form, dict):
            continue
        form_base = str(form.get("page_url") or base_url)
        raw_action = form.get("action")
        form_url = (
            urljoin(form_base, str(raw_action))
            if raw_action and form_base
            else str(raw_action or form_base)
        )
        if not _same_origin_http_url(form_url, expected_origin):
            continue
        origin, path = _url_parts(form_url)
        method = str(form.get("method") or "GET").strip().upper() or "GET"
        raw_enctype = str(form.get("enctype") or "").split(";", 1)[0].strip().casefold()
        if method == "GET":
            ctrl_location: InputLocation | None = InputLocation.QUERY
            effective_enctype: str | None = None
            req_content_types: list[str] = []
        else:
            # Per HTML specification, an omitted form enctype defaults to form-urlencoded.
            effective_enctype = raw_enctype or "application/x-www-form-urlencoded"
            ctrl_location = _body_input_location(effective_enctype)
            req_content_types = [effective_enctype]
        form_params: list[ObservedParameter] = []
        if ctrl_location is not None:
            for ctrl in form.get("controls") or []:
                if not isinstance(ctrl, dict) or ctrl.get("disabled") is True:
                    continue
                ctrl_name = str(ctrl.get("name") or "").strip()
                if not ctrl_name:
                    continue
                required = ctrl.get("required") if isinstance(ctrl.get("required"), bool) else None
                form_params.append(
                    ObservedParameter(
                        name=ctrl_name,
                        location=ctrl_location,
                        required=required,
                        content_type=effective_enctype,
                        evidence_refs=refs,
                    )
                )
        records.append(
            _record(
                execution,
                allocator,
                ObservationType.ENDPOINT,
                EndpointObservationPayload(
                    origin=origin,
                    path=path,
                    method=method,
                    request_content_types=req_content_types,
                    parameters=form_params,
                ),
                refs,
                f"forms[{index}]",
            )
        )
    return records


def _browser_dom_inputs(
    execution: ToolExecutionResult,
    allocator: RecordIdAllocator,
    refs: list[str],
    data: dict[str, Any],
    base_url: str,
    expected_origin: str,
) -> list[ObservationRecord]:
    dom_inputs_by_page: dict[tuple[str, str], list[ObservedParameter]] = {}
    for item in data.get("dom_inputs") or []:
        if not isinstance(item, dict) or item.get("disabled") is True:
            continue
        input_name = str(item.get("name") or "").strip()
        if not input_name:
            continue
        page_url = str(item.get("page_url") or base_url)
        if not _same_origin_http_url(page_url, expected_origin):
            continue
        origin, path = _url_parts(page_url)
        required = item.get("required") if isinstance(item.get("required"), bool) else None
        dom_inputs_by_page.setdefault((origin, path), []).append(
            ObservedParameter(
                name=input_name,
                location=InputLocation.DOM,
                required=required,
                evidence_refs=refs,
            )
        )

    return [
        _record(
            execution,
            allocator,
            ObservationType.ENDPOINT,
            EndpointObservationPayload(
                origin=origin,
                path=path,
                method="GET",
                parameters=dom_params,
            ),
            refs,
            f"dom_inputs[{index}]",
        )
        for index, ((origin, path), dom_params) in enumerate(dom_inputs_by_page.items())
    ]


def _browser_redirects(
    execution: ToolExecutionResult,
    allocator: RecordIdAllocator,
    refs: list[str],
    data: dict[str, Any],
) -> list[ObservationRecord]:
    records: list[ObservationRecord] = []
    for index, redirect in enumerate(data.get("redirects") or []):
        if not isinstance(redirect, dict):
            continue
        from_url = redirect.get("from_url") or redirect.get("from")
        to_url = redirect.get("to_url") or redirect.get("to")
        raw_status = redirect.get("status")
        if not from_url or not to_url or not isinstance(raw_status, int):
            continue
        if not (300 <= raw_status <= 399):
            continue
        records.append(
            _record(
                execution,
                allocator,
                ObservationType.HTTP_METADATA,
                RedirectObservationPayload(
                    from_url=str(from_url),
                    to_url=str(to_url),
                    status=raw_status,
                    followed=bool(redirect.get("followed", True)),
                ),
                refs,
                f"redirects[{index}]",
            )
        )
    return records


def _browser_actions(
    execution: ToolExecutionResult,
    allocator: RecordIdAllocator,
    refs: list[str],
    data: dict[str, Any],
) -> list[ObservationRecord]:
    return [
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
        for index, action in enumerate(data.get("actions") or [])
        if isinstance(action, dict)
    ]


def _browser_gaps(
    execution: ToolExecutionResult,
    allocator: RecordIdAllocator,
    refs: list[str],
    data: dict[str, Any],
) -> list[ObservationRecord]:
    records: list[ObservationRecord] = []
    for index, gap in enumerate(data.get("recon_gaps") or []):
        if not isinstance(gap, dict) or not gap.get("reason"):
            continue
        reason = str(gap["reason"])
        status = str(gap.get("status") or "recorded")
        records.append(
            _record(
                execution,
                allocator,
                ObservationType.BROWSER_BEHAVIOR,
                BrowserBehaviorObservationPayload(
                    action_id=gap.get("gap_id"),
                    event=f"recon_gap:{reason}:{status}",
                    url=gap.get("url"),
                    related_network_event_ids=[],
                ),
                refs,
                f"recon_gaps[{index}]",
            )
        )
    return records


def _browser(
    execution: ToolExecutionResult, allocator: RecordIdAllocator, refs: list[str]
) -> list[ObservationRecord]:
    data = _data(execution)
    base_url = str(data.get("final_url") or execution.target or "")
    expected_origin = normalize_origin(base_url) if base_url else ""
    return [
        *_browser_network_events(execution, allocator, refs, data),
        *_browser_forms(execution, allocator, refs, data, base_url, expected_origin),
        *_browser_dom_inputs(execution, allocator, refs, data, base_url, expected_origin),
        *_browser_redirects(execution, allocator, refs, data),
        *_browser_actions(execution, allocator, refs, data),
        *_browser_gaps(execution, allocator, refs, data),
    ]


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


def _zap_passive(
    execution: ToolExecutionResult, allocator: RecordIdAllocator, refs: list[str]
) -> list[ObservationRecord]:
    return []


_OBSERVATION_EXTRACTORS = {
    "HTTPPROBERESULT": _http,
    "ZAP_CRAWL": _zap,
    "ZAP_PROXY_TRAFFIC": _zap_proxy,
    "ZAP_PASSIVE": _zap_passive,
    "OPENAPI_SPEC": _openapi,
    "APISPECRESULT": _openapi,
    "WHATWEB_FINGERPRINT": _whatweb,
    "BROWSER_FLOW": _browser,
    "NMAP_SCAN": _nmap,
}


def extract_observations(
    execution: ToolExecutionResult,
    evidence: list[EvidenceArtifactRecord],
    *,
    allocator: RecordIdAllocator | None = None,
) -> list[ObservationRecord]:
    allocator = allocator or RecordIdAllocator()
    refs = evidence_refs(evidence)
    result_type = execution.result_type.upper()
    extractor = _OBSERVATION_EXTRACTORS.get(result_type)
    if extractor is not None:
        return extractor(execution, allocator, refs)
    if "OPENAPI" in result_type or "API_SPEC" in result_type:
        return _openapi(execution, allocator, refs)
    if "ZAP" in result_type or "CRAWL" in result_type:
        return _zap(execution, allocator, refs)
    if "WHATWEB" in result_type or "FINGERPRINT" in result_type:
        return _whatweb(execution, allocator, refs)
    if "BROWSER" in result_type or "PLAYWRIGHT" in result_type:
        return _browser(execution, allocator, refs)
    if "NMAP" in result_type:
        return _nmap(execution, allocator, refs)
    return _http(execution, allocator, refs)
