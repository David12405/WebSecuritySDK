from datetime import UTC, datetime, timedelta

import pytest

from websecuritycheck.domain import (
    ArtifactManifest,
    ArtifactType,
    DiscoverySource,
    InputLocation,
    ObservationSource,
    ObservationType,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from websecuritycheck.recon import process_tool_result
from websecuritycheck.recon.target_model import update_target_model


def _execution(data):
    return ToolExecutionResult(
        execution_id="EXEC-001",
        assessment_id="ASM-001",
        tool_id="http",
        target="https://example.com/api/users?id=1",
        result_type="HTTPProbeResult",
        result_data={"data": data},
        status=ToolExecutionStatus.COMPLETED,
        started_at=datetime.now(UTC),
    )


def test_http_result_builds_endpoint_with_query_parameter():
    result = process_tool_result(
        _execution(
            {
                "url": "https://example.com/api/users?id=1",
                "method": "GET",
                "status": 200,
                "response_content_type": "application/json",
            }
        )
    )
    assert result.updated_target_model is not None
    assert result.updated_target_model.revision == 1
    endpoint = result.updated_target_model.endpoints[0]
    assert endpoint.path == "/api/users"
    assert endpoint.observed_parameters[0].name == "id"


def test_api_spec_source_does_not_become_runtime_source():
    execution = ToolExecutionResult(
        execution_id="EXEC-002",
        assessment_id="ASM-001",
        tool_id="openapi",
        target="https://example.com/openapi.json",
        result_type="ApiSpecResult",
        result_data={
            "data": {
                "operations": [{"path": "/declared", "method": "POST", "request_content_types": []}]
            }
        },
        status=ToolExecutionStatus.COMPLETED,
        started_at=datetime.now(UTC),
    )
    result = process_tool_result(execution)
    sources = result.updated_target_model.endpoints[0].discovery_sources
    assert [source.value for source in sources] == ["API_SPEC"]


def test_same_endpoint_different_query_values_merge_on_update():
    first = process_tool_result(
        _execution({"url": "https://example.com/api/users?id=1", "method": "GET", "status": 200})
    )
    second_execution = _execution(
        {"url": "https://example.com/api/users?id=2", "method": "GET", "status": 200}
    ).model_copy(update={"execution_id": "EXEC-002"})
    second = process_tool_result(second_execution, current_target_model=first.updated_target_model)
    assert second.updated_target_model is not None
    assert len(second.updated_target_model.endpoints) == 1
    assert second.updated_target_model.revision == 2


def test_endpoint_identity_is_stable_hash_of_canonical_endpoint():
    first = process_tool_result(
        _execution({"url": "https://EXAMPLE.com/api/users?id=1", "method": "get", "status": 200})
    )
    second = process_tool_result(
        _execution({"url": "https://example.com/api/users?id=2", "method": "GET", "status": 200})
    )
    assert (
        first.updated_target_model.endpoints[0].endpoint_id
        == second.updated_target_model.endpoints[0].endpoint_id
    )
    assert len(first.updated_target_model.endpoints[0].endpoint_id) == 12


@pytest.mark.parametrize(
    ("result_type", "result_data", "expected_observations"),
    [
        (
            "ZAP_CRAWL",
            {"endpoints": [{"url": "https://example.com/zap", "method": "GET", "status": 200}]},
            1,
        ),
        (
            "BROWSER_FLOW",
            {
                "network_events": [
                    {"url": "https://example.com/xhr", "method": "POST", "response_status": 201}
                ],
                "actions": [{"kind": "click"}],
            },
            2,
        ),
        (
            "WHATWEB_FINGERPRINT",
            {
                "technologies": [
                    {
                        "name": "nginx",
                        "versions": ["1.25"],
                        "categories": ["Web servers"],
                        "confidence": "HIGH",
                    }
                ]
            },
            1,
        ),
        (
            "NMAP_SCAN",
            {
                "hosts": [
                    {
                        "address": "10.0.0.10",
                        "state": "up",
                        "services": [
                            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                        ],
                    }
                ]
            },
            2,
        ),
    ],
)
def test_all_deterministic_recon_result_types_reach_canonical_processing(
    result_type, result_data, expected_observations
):
    result = process_tool_result(
        _execution(result_data).model_copy(update={"result_type": result_type})
    )
    assert len(result.observation_records) == expected_observations
    assert result.updated_target_model is not None
    assert result.updated_target_model.revision == 1


def test_zap_proxy_traffic_has_explicit_runtime_provenance_not_crawler_provenance():
    execution = _execution(
        {
            "messages": [
                {
                    "url": "https://example.com/proxy-observed",
                    "scheme": "https",
                    "host": "example.com",
                    "path": "/proxy-observed",
                    "method": "POST",
                    "status": 201,
                    "query_parameter_names": ["id"],
                    "body_parameter_names": ["user.id"],
                    "source": "zap_proxy",
                }
            ]
        }
    ).model_copy(update={"result_type": "ZAP_PROXY_TRAFFIC", "tool_id": "zap"})

    result = process_tool_result(execution)

    assert len(result.observation_records) == 1
    assert result.observation_records[0].source_type is ObservationSource.ZAP_PROXY
    endpoint = result.updated_target_model.endpoints[0]
    assert endpoint.discovery_sources == [DiscoverySource.HTTP_OBSERVATION]
    assert DiscoverySource.CRAWLER not in endpoint.discovery_sources
    assert endpoint.runtime_observed is True


def test_evidence_identity_storage_and_metadata_are_preserved_without_secret_leakage():
    execution = _execution({"url": "https://example.com", "status": 200}).model_copy(
        update={
            "artifact_manifests": [
                ArtifactManifest(
                    artifact_ref="logical-http-001",
                    storage_uri="s3://lab-bucket/http/001.json",
                    artifact_type=ArtifactType.HTTP_RAW_EXCHANGE,
                    content="sanitized-by-wrapper",
                    media_type="application/json",
                    metadata={"Authorization": "secret-token", "nested": {"token": "secret"}},
                )
            ]
        }
    )
    result = process_tool_result(execution)
    evidence = result.evidence_records[0]
    assert evidence.evidence_id == "EVD-001"
    assert evidence.artifact_ref == "logical-http-001"
    assert evidence.storage_uri == "s3://lab-bucket/http/001.json"
    assert "secret-token" not in str(evidence.metadata)
    assert "secret" not in str(evidence.metadata)


def test_artifact_manifest_rejects_physical_artifact_references():
    with pytest.raises(ValueError, match="opaque logical reference"):
        ArtifactManifest(
            artifact_ref="C:/tmp/raw.json",
            artifact_type=ArtifactType.TOOL_RAW_OUTPUT,
        )


def test_api_spec_and_runtime_sources_derive_both_without_mutating_spec_provenance():
    declared = process_tool_result(
        _execution(
            {
                "source_origin": "https://example.com",
                "operations": [{"path": "/x", "method": "GET"}],
            }
        ).model_copy(
            update={"result_type": "OPENAPI_SPEC", "target": "https://example.com/openapi.json"}
        )
    )
    declared_endpoint = declared.updated_target_model.endpoints[0]
    assert declared_endpoint.discovery_status == "declared"
    assert not declared_endpoint.runtime_observed

    runtime = process_tool_result(
        _execution({"url": "https://example.com/x", "method": "GET", "status": 200}).model_copy(
            update={"execution_id": "EXEC-002", "result_type": "HTTPProbeResult"}
        ),
        current_target_model=declared.updated_target_model,
    )
    endpoint = runtime.updated_target_model.endpoints[0]
    assert endpoint.discovery_status == "both"
    assert endpoint.runtime_observed


def test_revision_noop_and_material_update_semantics():
    first = process_tool_result(_execution({"url": "https://example.com/x", "status": 200}))
    model = first.updated_target_model
    assert model is not None
    unchanged, changed = update_target_model(
        model,
        endpoint_updates=model.endpoints,
        now=model.last_updated + timedelta(seconds=30),
    )
    assert not changed
    assert unchanged.revision == model.revision
    assert unchanged.last_updated == model.last_updated


def test_processor_rejects_assessment_mismatch_without_touching_existing_model():
    first = process_tool_result(_execution({"url": "https://example.com/x", "status": 200}))
    with pytest.raises(ValueError, match="does not match"):
        process_tool_result(
            _execution({"url": "https://example.com/y", "status": 200}).model_copy(
                update={"assessment_id": "ASM-002", "execution_id": "EXEC-002"}
            ),
            current_target_model=first.updated_target_model,
        )


def test_processor_rejects_unknown_result_schema_version():
    with pytest.raises(ValueError, match="unsupported tool result schema version"):
        process_tool_result(
            _execution({"url": "https://example.com", "status": 200}).model_copy(
                update={"result_schema_version": "9.9"}
            )
        )


def test_passive_zap_result_stays_out_of_default_target_model():
    result = process_tool_result(
        _execution({"signals": [{"plugin_id": "10021", "url": "https://example.com"}]}).model_copy(
            update={"result_type": "ZAP_PASSIVE"}
        )
    )
    assert result.observation_records == []
    assert result.endpoint_updates == []
    assert result.technology_updates == []


def test_nmap_processing_creates_hosts_and_services_without_endpoints():
    result = process_tool_result(
        _execution(
            {
                "hosts": [
                    {
                        "address": "10.0.0.10",
                        "state": "up",
                        "services": [
                            {"port": 80, "protocol": "tcp", "state": "open", "service": "http"}
                        ],
                    }
                ]
            }
        ).model_copy(update={"result_type": "NMAP_SCAN"})
    )
    assert result.updated_target_model.endpoints == []
    assert result.observation_records[0].observation_type.value == "NETWORK_HOST"
    assert result.observation_records[1].observation_type.value == "NETWORK_SERVICE"


def test_http_preserves_response_headers_without_promoting_tech_or_cookie_auth():
    result = process_tool_result(
        _execution(
            {
                "url": "https://example.com/login",
                "method": "GET",
                "status": 200,
                "response_headers": {
                    "server": "nginx/1.25.0",
                    "x-powered-by": "Express",
                    "set-cookie": "<redacted>",
                },
                "cookies": [{"name": "prefs"}],
            }
        )
    )
    assert len(result.observation_records) == 1
    obs = result.observation_records[0]
    assert obs.observation_type is ObservationType.ENDPOINT
    assert obs.payload.response_headers == {
        "server": "nginx/1.25.0",
        "x-powered-by": "Express",
        "set-cookie": "<redacted>",
    }
    assert result.technology_updates == []
    assert result.updated_target_model.technologies == []


def test_unknown_request_content_type_never_guesses_form_or_json():
    http_unknown = process_tool_result(
        _execution(
            {
                "url": "https://example.com/raw",
                "method": "POST",
                "status": 200,
                "request_content_type": "text/plain",
                "request_parameter_names": ["payload"],
            }
        )
    )
    http_ep = http_unknown.updated_target_model.endpoints[0]
    assert http_ep.request_content_types == ["text/plain"]
    assert http_ep.observed_parameters == []

    proxy_form = process_tool_result(
        _execution(
            {
                "messages": [
                    {
                        "url": "https://example.com/submit",
                        "method": "POST",
                        "status": 200,
                        "request_content_type": "application/x-www-form-urlencoded",
                        "body_parameter_names": ["username"],
                    },
                    {
                        "url": "https://example.com/unknown",
                        "method": "POST",
                        "status": 200,
                        "body_parameter_names": ["opaque"],
                    },
                ]
            }
        ).model_copy(update={"result_type": "ZAP_PROXY_TRAFFIC"})
    )
    by_path = {ep.path: ep for ep in proxy_form.updated_target_model.endpoints}
    assert [(p.name, p.location) for p in by_path["/submit"].observed_parameters] == [
        ("username", InputLocation.FORM)
    ]
    assert by_path["/unknown"].observed_parameters == []


def test_browser_normalization_keeps_body_fields_and_forms_and_drops_blocked_events():
    result = process_tool_result(
        _execution(
            {
                "final_url": "https://example.com/",
                "network_events": [
                    {
                        "url": "https://example.com/api/items?page=1",
                        "method": "POST",
                        "request_content_type": "application/json",
                        "response_status": 201,
                        "query_parameter_names": ["page"],
                        "request_body_field_names": ["item", "item.name"],
                        "blocked": False,
                    },
                    {
                        "url": "https://outside.example/beacon?leak=1",
                        "method": "POST",
                        "blocked": True,
                        "blocked_reason": "out_of_scope",
                    },
                ],
                "forms": [
                    {
                        "action": "/search",
                        "method": "GET",
                        "controls": [
                            {"name": "q", "type": "text", "required": True, "disabled": False},
                            {"name": "ignored", "type": "text", "disabled": True},
                        ],
                    },
                    {
                        "action": "https://example.com/login",
                        "method": "POST",
                        "controls": [{"name": "username", "type": "text", "disabled": False}],
                    },
                    {
                        "action": "https://thirdparty.invalid/external",
                        "method": "POST",
                        "controls": [{"name": "q"}],
                    },
                ],
            }
        ).model_copy(update={"result_type": "BROWSER_FLOW"})
    )
    by_key = {(ep.origin, ep.path, ep.method): ep for ep in result.updated_target_model.endpoints}
    assert ("https://outside.example", "/beacon", "POST") not in by_key
    assert ("https://thirdparty.invalid", "/external", "POST") not in by_key

    api_ep = by_key[("https://example.com", "/api/items", "POST")]
    assert {(p.name, p.location) for p in api_ep.observed_parameters} == {
        ("page", InputLocation.QUERY),
        ("item", InputLocation.JSON_BODY),
        ("item.name", InputLocation.JSON_BODY),
    }

    search_ep = by_key[("https://example.com", "/search", "GET")]
    assert [(p.name, p.location, p.required) for p in search_ep.observed_parameters] == [
        ("q", InputLocation.QUERY, True)
    ]

    login_ep = by_key[("https://example.com", "/login", "POST")]
    assert [(p.name, p.location) for p in login_ep.observed_parameters] == [
        ("username", InputLocation.FORM)
    ]


def test_browser_normalization_maps_dom_inputs_redirects_gaps_and_feeds_module2():
    from websecuritycheck.analysis.inputs import extract_input_candidates
    from websecuritycheck.domain.analysis_models import Module2AnalysisRequest

    execution = _execution(
        {
            "final_url": "https://example.com/final",
            "network_events": [
                {
                    "url": "https://example.com/api/search?filter=books",
                    "method": "POST",
                    "request_content_type": "application/json",
                    "response_status": 200,
                    "query_parameter_names": ["filter"],
                    "request_body_field_names": ["keyword"],
                    "blocked": False,
                }
            ],
            "forms": [
                {
                    "page_url": "https://example.com/contact",
                    "action": "feedback",
                    "method": "POST",
                    "controls": [{"name": "comment", "type": "textarea", "disabled": False}],
                }
            ],
            "dom_inputs": [
                {
                    "page_url": "https://example.com/",
                    "name": "search-input",
                    "input_type": "text",
                    "required": False,
                    "disabled": False,
                },
                {
                    "page_url": "https://outside.example/",
                    "name": "ignored-ext",
                    "input_type": "text",
                    "disabled": False,
                },
            ],
            "redirects": [
                {
                    "from_url": "https://example.com/old",
                    "to_url": "https://example.com/final",
                    "status": 302,
                    "followed": True,
                }
            ],
            "recon_gaps": [
                {
                    "gap_id": "GAP-001",
                    "url": "https://example.com/protected",
                    "reason": "auth_required",
                    "status": "blocked",
                    "element": None,
                    "detail": "HTTP 401 auth barrier",
                }
            ],
            "warnings": [
                "recon_gap:auth_required:blocked url=https://example.com/protected element=-"
            ],
        }
    ).model_copy(
        update={
            "tool_id": "explore_browser",
            "result_type": "BROWSER_FLOW",
            "target": "https://example.com/",
            "artifact_manifests": [
                ArtifactManifest(
                    artifact_ref="browser-trace-1234",
                    artifact_type=ArtifactType.BROWSER_TRACE,
                    media_type="application/json",
                    redaction_applied=True,
                    metadata={"gap_count": 1},
                )
            ],
        }
    )

    processed = process_tool_result(execution)
    assert processed.warnings == [
        "recon_gap:auth_required:blocked url=https://example.com/protected element=-"
    ]
    assert any(
        obs.observation_type is ObservationType.HTTP_METADATA
        and obs.payload.kind == "redirect"
        and obs.payload.to_url == "https://example.com/final"
        for obs in processed.observation_records
    )
    assert any(
        obs.observation_type is ObservationType.BROWSER_BEHAVIOR
        and obs.payload.event == "recon_gap:auth_required:blocked"
        and obs.payload.action_id == "GAP-001"
        for obs in processed.observation_records
    )

    model = processed.updated_target_model
    by_key = {(ep.origin, ep.path, ep.method): ep for ep in model.endpoints}
    assert ("https://example.com", "/feedback", "POST") in by_key
    root_ep = by_key[("https://example.com", "/", "GET")]
    assert [(p.name, p.location) for p in root_ep.observed_parameters] == [
        ("search-input", InputLocation.DOM)
    ]
    assert root_ep.discovery_sources == [DiscoverySource.BROWSER]

    m2_request = Module2AnalysisRequest(
        target_model=processed.updated_target_model,
        evidence_records=processed.evidence_records,
        observations=processed.observation_records,
    )
    m2_inputs = extract_input_candidates(m2_request)
    extracted = {(item.parameter_name, item.location) for item in m2_inputs.inputs}
    assert ("search-input", InputLocation.DOM) in extracted
    assert ("keyword", InputLocation.JSON_BODY) in extracted
    assert ("filter", InputLocation.QUERY) in extracted
    assert ("comment", InputLocation.FORM) in extracted


def test_observation_dispatch_handles_known_and_custom_result_types():
    known_passive = process_tool_result(
        _execution({"signals": [{"plugin_id": "100"}]}).model_copy(
            update={"result_type": "ZAP_PASSIVE"}
        )
    )
    assert known_passive.observation_records == []

    custom_fallback = process_tool_result(
        _execution(
            {"endpoints": [{"url": "https://example.com/custom", "method": "GET"}]}
        ).model_copy(update={"result_type": "CUSTOM_CRAWL_V2"})
    )
    assert len(custom_fallback.observation_records) == 1
    assert custom_fallback.observation_records[0].source_type is ObservationSource.ZAP

