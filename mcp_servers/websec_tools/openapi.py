"""Deterministic Swagger/OpenAPI discovery for Layer 6."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Literal
from urllib.parse import unquote

import httpx
import yaml
from pydantic import BaseModel, ConfigDict, Field

from .errors import ToolError, envelope
from .probes import _client_or_default, _fetch, _validate_target

MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
MAX_REF_DEPTH = 20
MAX_OPERATIONS = 2000
METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


class SpecificationInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    family: Literal["swagger", "openapi"]
    version: str


class ApiServer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    description: str | None = None


class SecurityScheme(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: str
    scheme: str | None = None
    bearer_format: str | None = None
    location: str | None = None


class ApiParameter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    location: str
    required: bool = False
    schema_type: str | None = None


class ApiResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    content_types: list[str] = Field(default_factory=list)


class ApiSecurityRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scheme_name: str
    scopes: list[str] = Field(default_factory=list)


class ApiOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    method: str
    operation_id: str | None = None
    summary: str | None = None
    parameters: list[ApiParameter] = Field(default_factory=list)
    request_content_types: list[str] = Field(default_factory=list)
    responses: list[ApiResponse] = Field(default_factory=list)
    security: list[ApiSecurityRequirement] = Field(default_factory=list)


class ApiSpecResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_url: str
    specification: SpecificationInfo
    title: str | None = None
    servers: list[ApiServer] = Field(default_factory=list)
    security_schemes: list[SecurityScheme] = Field(default_factory=list)
    operations: list[ApiOperation] = Field(default_factory=list)


def _as_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _strings(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return sorted({item for item in values if isinstance(item, str)})


def _resolve_ref(value: Any, document: Any, stack: tuple[str, ...] = (), depth: int = 0) -> Any:
    if depth > MAX_REF_DEPTH:
        raise ToolError("E_PARSE", "OpenAPI local reference depth exceeded the limit")
    if not isinstance(value, Mapping) or set(value) != {"$ref"}:
        return value
    reference = value.get("$ref")
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise ToolError("E_UNSUPPORTED_INPUT", "external OpenAPI references are not supported")
    if reference in stack:
        raise ToolError("E_PARSE", "OpenAPI local reference cycle detected")
    current: Any = document
    for token in reference[2:].split("/"):
        token = unquote(token).replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or token not in current:
            raise ToolError("E_PARSE", "OpenAPI local reference target was not found")
        current = current[token]
    return _resolve_ref(current, document, (*stack, reference), depth + 1)


def _resolve(value: Any, document: Any) -> Any:
    return _resolve_ref(value, document)


def _reject_external_refs(value: Any, seen: set[int] | None = None) -> None:
    """Reject external references even when the field is not extracted."""

    seen = seen or set()
    if id(value) in seen:
        return
    if isinstance(value, Mapping):
        seen.add(id(value))
        reference = value.get("$ref")
        if reference is not None and (
            not isinstance(reference, str) or not reference.startswith("#/")
        ):
            raise ToolError("E_UNSUPPORTED_INPUT", "external OpenAPI references are not supported")
        for child in value.values():
            _reject_external_refs(child, seen)
    elif isinstance(value, list):
        seen.add(id(value))
        for child in value:
            _reject_external_refs(child, seen)


def _schema_type(parameter: Mapping[str, Any]) -> str | None:
    schema = parameter.get("schema")
    if isinstance(schema, Mapping):
        value = schema.get("type")
        return value if isinstance(value, str) else None
    value = parameter.get("type")
    return value if isinstance(value, str) else None


def _parameters(values: Any, document: Mapping[str, Any]) -> list[ApiParameter]:
    output: list[ApiParameter] = []
    if not isinstance(values, list):
        return output
    for raw in values:
        parameter = _resolve(raw, document)
        if not isinstance(parameter, Mapping):
            continue
        name = _as_string(parameter.get("name"))
        location = _as_string(parameter.get("in"))
        if not name or not location:
            continue
        output.append(
            ApiParameter(
                name=name,
                location=location,
                required=bool(parameter.get("required", False)),
                schema_type=_schema_type(parameter),
            )
        )
    return sorted(output, key=lambda item: (item.location, item.name))


def _content_types(content: Any) -> list[str]:
    if not isinstance(content, Mapping):
        return []
    return sorted(key for key in content if isinstance(key, str))


def _responses(
    values: Any,
    document: Mapping[str, Any],
    default_content_types: list[str] | None = None,
) -> list[ApiResponse]:
    if not isinstance(values, Mapping):
        return []
    output: list[ApiResponse] = []
    for status, raw in values.items():
        if not isinstance(status, str):
            continue
        response = _resolve(raw, document)
        if not isinstance(response, Mapping):
            response = {}
        content_types = _content_types(response.get("content"))
        output.append(
            ApiResponse(
                status=status,
                content_types=content_types or (default_content_types or []),
            )
        )
    return sorted(output, key=lambda item: item.status)


def _security(values: Any) -> list[ApiSecurityRequirement]:
    if not isinstance(values, list):
        return []
    output: list[ApiSecurityRequirement] = []
    for requirement in values:
        if not isinstance(requirement, Mapping):
            continue
        for name, scopes in requirement.items():
            if isinstance(name, str):
                output.append(ApiSecurityRequirement(scheme_name=name, scopes=_strings(scopes)))
    return sorted(output, key=lambda item: (item.scheme_name, item.scopes))


def _servers(document: Mapping[str, Any], family: str) -> list[ApiServer]:
    if family == "openapi":
        values = document.get("servers")
        if isinstance(values, list):
            return sorted(
                [
                    ApiServer(url=item["url"], description=_as_string(item.get("description")))
                    for item in values
                    if isinstance(item, Mapping) and isinstance(item.get("url"), str)
                ],
                key=lambda item: item.url,
            )
        return []
    schemes = document.get("schemes") if isinstance(document.get("schemes"), list) else ["http"]
    host = document.get("host") or ""
    base_path = document.get("basePath") or ""
    return (
        [ApiServer(url=f"{scheme}://{host}{base_path}") for scheme in _strings(schemes)]
        if host
        else []
    )


def _security_schemes(document: Mapping[str, Any], family: str) -> list[SecurityScheme]:
    components = document.get("components")
    raw = (
        components.get("securitySchemes", {})
        if family == "openapi" and isinstance(components, Mapping)
        else document.get("securityDefinitions", {})
    )
    if not isinstance(raw, Mapping):
        return []
    output: list[SecurityScheme] = []
    for name, value in raw.items():
        if not isinstance(name, str) or not isinstance(value, Mapping):
            continue
        output.append(
            SecurityScheme(
                name=name,
                type=str(value.get("type", "unknown")),
                scheme=_as_string(value.get("scheme")),
                bearer_format=_as_string(value.get("bearerFormat")),
                location=_as_string(value.get("in")),
            )
        )
    return sorted(output, key=lambda item: item.name)


def parse_api_document(document: Any, *, source_url: str) -> ApiSpecResult:
    if isinstance(document, (bytes, bytearray)):
        if len(document) > MAX_DOCUMENT_BYTES:
            raise ToolError("E_PARSE", "OpenAPI document exceeded the size limit")
        try:
            document = json.loads(bytes(document).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            try:
                document = yaml.safe_load(bytes(document).decode("utf-8"))
            except (UnicodeDecodeError, yaml.YAMLError) as exc:
                raise ToolError("E_PARSE", "OpenAPI document could not be parsed") from exc
    elif isinstance(document, str):
        if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise ToolError("E_PARSE", "OpenAPI document exceeded the size limit")
        try:
            document = json.loads(document)
        except json.JSONDecodeError:
            try:
                document = yaml.safe_load(document)
            except yaml.YAMLError as exc:
                raise ToolError("E_PARSE", "OpenAPI document could not be parsed") from exc
    if not isinstance(document, Mapping):
        raise ToolError("E_PARSE", "OpenAPI root must be an object")
    _reject_external_refs(document)

    if isinstance(document.get("swagger"), str):
        family = "swagger"
        version = document["swagger"]
    elif isinstance(document.get("openapi"), str):
        family = "openapi"
        version = document["openapi"]
    else:
        raise ToolError("E_UNSUPPORTED_INPUT", "document is not Swagger or OpenAPI")
    if family == "openapi" and not (
        version.startswith("3.0.") or version.startswith("3.1.") or version.startswith("3.2.")
    ):
        raise ToolError("E_UNSUPPORTED_INPUT", f"unsupported OpenAPI version {version}")
    if family == "swagger" and not version.startswith("2."):
        raise ToolError("E_UNSUPPORTED_INPUT", f"unsupported Swagger version {version}")

    root_security = document.get("security", [])
    operations: list[ApiOperation] = []
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        paths = {}
    for path, path_item in sorted(paths.items(), key=lambda item: str(item[0])):
        if not isinstance(path, str):
            continue
        path_item = _resolve(path_item, document)
        if not isinstance(path_item, Mapping):
            continue
        path_parameters = path_item.get("parameters", [])
        for method in METHODS:
            raw_operation = path_item.get(method)
            if raw_operation is None:
                continue
            operation = _resolve(raw_operation, document)
            if not isinstance(operation, Mapping):
                continue
            operation_parameters = operation.get("parameters", [])
            if not isinstance(path_parameters, list):
                path_parameters = []
            if not isinstance(operation_parameters, list):
                operation_parameters = []
            params = _parameters([*path_parameters, *operation_parameters], document)
            request_types: list[str] = []
            if family == "openapi":
                body = operation.get("requestBody")
                if body is not None:
                    body = _resolve(body, document)
                if isinstance(body, Mapping):
                    request_types = _content_types(body.get("content"))
            else:
                request_types = _strings(operation.get("consumes", document.get("consumes", [])))
            response_types = (
                _strings(operation.get("produces", document.get("produces", [])))
                if family == "swagger"
                else None
            )
            responses = _responses(operation.get("responses", {}), document, response_types)
            security = _security(operation.get("security", root_security))
            operations.append(
                ApiOperation(
                    path=path,
                    method=method.upper(),
                    operation_id=_as_string(operation.get("operationId")),
                    summary=_as_string(operation.get("summary")),
                    parameters=params,
                    request_content_types=request_types,
                    responses=responses,
                    security=security,
                )
            )
    operations = operations[:MAX_OPERATIONS]
    return ApiSpecResult(
        source_url=source_url,
        specification=SpecificationInfo(family=family, version=version),
        title=(
            _as_string(document.get("info", {}).get("title"))
            if isinstance(document.get("info"), Mapping)
            else None
        ),
        servers=_servers(document, family),
        security_schemes=_security_schemes(document, family),
        operations=operations,
    )


async def parse_api_spec(
    target: str,
    *,
    client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    _validate_target(target)
    http, owned = _client_or_default(client)
    try:
        response, _redirects = await _fetch(http, target)
        if response.status_code < 200 or response.status_code >= 300:
            raise ToolError("E_HTTP", f"OpenAPI fetch returned HTTP {response.status_code}")
        result = parse_api_document(response.content, source_url=str(response.url))
    finally:
        if owned:
            await http.aclose()
    return envelope(
        f"Parsed {len(result.operations)} API operations from {result.source_url}",
        result.model_dump(mode="json"),
        len(result.operations) >= MAX_OPERATIONS,
    )
