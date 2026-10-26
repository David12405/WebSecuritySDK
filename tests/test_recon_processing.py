from datetime import UTC, datetime

from websecuritycheck.domain import ToolExecutionResult, ToolExecutionStatus
from websecuritycheck.recon import process_tool_result


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
                "operations": [
                    {"path": "/declared", "method": "POST", "request_content_types": []}
                ]
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
