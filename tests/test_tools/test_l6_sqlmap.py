"""Offline unit and security contract tests for Layer 6 SQLMap tool."""

from __future__ import annotations

import asyncio
from functools import wraps
from pathlib import Path

import pytest

from mcp_servers.websec_tools import server
from mcp_servers.websec_tools.errors import ToolError
from mcp_servers.websec_tools.validation import sqlmap


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


_SAMPLE_BOOLEAN_AND_ERROR_STDOUT = """\
[INFO] testing connection to the target URL
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (SQLite)
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 4567=4567

    Type: error-based
    Title: SQLite OR error-based - WHERE or HAVING clause
    Payload: id=1' AND 1=CAST((SELECT 1) AS INT)-- -
---
[INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
"""


@async_test
async def test_detect_sqli_query_location_builds_safe_argv_and_parses_findings():
    captured_argv: list[str] = []
    captured_req_text = ""

    async def fake_runner(argv: list[str], timeout: float) -> tuple[int, bytes, bytes]:
        nonlocal captured_req_text
        captured_argv.extend(argv)
        req_path = Path(argv[argv.index("-r") + 1])
        captured_req_text = req_path.read_text(encoding="utf-8")
        return 0, _SAMPLE_BOOLEAN_AND_ERROR_STDOUT.encode("utf-8"), b""

    res = await sqlmap.detect_sqli(
        "https://api.example.com/items?id=1",
        "id",
        parameter_location="QUERY",
        method="GET",
        techniques=["ERROR", "BOOLEAN", "UNION"],
        headers={"Authorization": "Bearer super-secret-jwt"},
        cookies={"session": "secret-session-cookie"},
        runner=fake_runner,
    )

    assert "--batch" in captured_argv
    assert "--risk=1" in captured_argv
    assert "--level=1" in captured_argv
    assert "--technique=EBU" in captured_argv
    assert "--force-ssl" in captured_argv
    assert "--flush-session" in captured_argv
    assert captured_argv[captured_argv.index("-p") + 1] == "id"
    # Temporary request file should have been cleaned up after TemporaryDirectory exits
    assert not Path(captured_argv[captured_argv.index("-r") + 1]).exists()
    # Secrets present in the ephemeral request file, never leaked in artifact manifest
    assert "Authorization: Bearer super-secret-jwt" in captured_req_text
    assert "GET /items?id=1 HTTP/1.1" in captured_req_text

    data = res["data"]
    assert data["dbms_identified"] == "SQLite"
    assert data["heuristic_signal_detected"] is True
    assert [f["technique"] for f in data["findings"]] == ["BOOLEAN", "ERROR"]
    manifest_content = data["artifact_manifests"][0]["content"]
    assert data["artifact_manifests"][0]["redaction_applied"] is True
    assert "super-secret-jwt" not in manifest_content
    assert "secret-session-cookie" not in manifest_content


@async_test
async def test_detect_sqli_maps_all_supported_input_locations():
    observed: dict[str, tuple[list[str], str]] = {}

    def make_runner(label: str):
        async def runner(argv: list[str], timeout: float) -> tuple[int, bytes, bytes]:
            req_path = Path(argv[argv.index("-r") + 1])
            observed[label] = (list(argv), req_path.read_text(encoding="utf-8"))
            return 0, b"[INFO] parameter does not appear to be injectable", b""

        return runner

    await sqlmap.detect_sqli(
        "http://example.com/search",
        "q",
        parameter_location="FORM",
        method="POST",
        runner=make_runner("FORM"),
    )
    assert "--level=1" in observed["FORM"][0]
    assert observed["FORM"][0][observed["FORM"][0].index("-p") + 1] == "q"
    assert "q=1" in observed["FORM"][1]

    await sqlmap.detect_sqli(
        "http://example.com/api/filter",
        "filters.category",
        parameter_location="JSON_BODY",
        method="POST",
        body='{"filters":{"category":"books"}}',
        runner=make_runner("JSON_BODY"),
    )
    assert "-p" not in observed["JSON_BODY"][0]
    assert '"category":"books*"' in observed["JSON_BODY"][1]

    await sqlmap.detect_sqli(
        "http://example.com/profile",
        "pref_id",
        parameter_location="COOKIE",
        method="GET",
        runner=make_runner("COOKIE"),
    )
    assert "--level=2" in observed["COOKIE"][0]
    assert observed["COOKIE"][0][observed["COOKIE"][0].index("-p") + 1] == "pref_id"
    assert "Cookie: pref_id=1" in observed["COOKIE"][1]

    await sqlmap.detect_sqli(
        "http://example.com/tenant",
        "X-Tenant-Id",
        parameter_location="HEADER",
        method="GET",
        headers={"X-Tenant-Id": "acme"},
        runner=make_runner("CUSTOM_HEADER"),
    )
    assert "--level=1" in observed["CUSTOM_HEADER"][0]
    assert "-p" not in observed["CUSTOM_HEADER"][0]
    assert "X-Tenant-Id: acme*" in observed["CUSTOM_HEADER"][1]

    await sqlmap.detect_sqli(
        "http://example.com/home",
        "User-Agent",
        parameter_location="HEADER",
        method="GET",
        runner=make_runner("UA_HEADER"),
    )
    assert "--level=3" in observed["UA_HEADER"][0]
    assert observed["UA_HEADER"][0][observed["UA_HEADER"][0].index("-p") + 1] == "User-Agent"


@pytest.mark.parametrize(
    ("kwargs", "expected_code"),
    [
        ({"techniques": ["S"]}, "E_INVALID_ARGUMENT"),
        ({"techniques": ["ERROR", "STACKED"]}, "E_INVALID_ARGUMENT"),
        ({"risk_profile": "HIGH"}, "E_INVALID_ARGUMENT"),
        ({"parameter_location": "DOM"}, "E_UNSUPPORTED_INPUT"),
        ({"parameter_name": "--dump"}, "E_INVALID_ARGUMENT"),
        ({"executable": "--os-shell"}, "E_TOOL_UNAVAILABLE"),
        ({"method": "TRACE"}, "E_INVALID_ARGUMENT"),
    ],
)
@async_test
async def test_detect_sqli_rejects_forbidden_inputs(kwargs, expected_code):
    base = {
        "target": "https://example.com/item?id=1",
        "parameter_name": "id",
        "parameter_location": "QUERY",
        "method": "GET",
    }
    base.update(kwargs)
    with pytest.raises(ToolError) as exc_info:
        await sqlmap.detect_sqli(**base)
    assert exc_info.value.code == expected_code


def test_assert_safe_argv_blocks_dangerous_flags():
    with pytest.raises(ToolError) as exc_info:
        sqlmap._assert_safe_argv(
            [
                "sqlmap",
                "-u",
                "https://example.com",
                "--batch",
                "--risk=1",
                "--technique=E",
                "--flush-session",
                "--dump",
            ]
        )
    assert exc_info.value.code == "E_INVALID_ARGUMENT"

    with pytest.raises(ToolError):
        sqlmap._assert_safe_argv(
            [
                "sqlmap",
                "-u",
                "https://example.com",
                "--batch",
                "--risk=2",
                "--technique=E",
                "--flush-session",
            ]
        )

    with pytest.raises(ToolError):
        sqlmap._assert_safe_argv(
            [
                "sqlmap",
                "-u",
                "https://example.com",
                "--batch",
                "--risk=1",
                "--technique=ES",
                "--flush-session",
            ]
        )


def test_parse_sqlmap_output_redacts_secrets_and_detects_anomalies():
    stdout = (
        "Authorization: Bearer top-secret-token\n"
        "Cookie: sid=my-secret-cookie\n"
        "[WARNING] target URL content is not stable\n"
        "[CRITICAL] WAF/IPS identified\n"
        "[WARNING] HTTP error codes detected during run:\n429 (Too Many Requests) - 3 times\n"
    )
    parsed = sqlmap.parse_sqlmap_output(
        stdout_text=stdout,
        stderr_text="",
        session_log_text="",
        target="https://example.com/search?q=1",
        method="GET",
        parameter_name="q",
        parameter_location="QUERY",
        requested_techniques=["BOOLEAN"],
    )
    assert parsed.target_stable is False
    assert parsed.waf_or_filter_detected is True
    assert parsed.rate_limited is True
    content = parsed.artifact_manifests[0]["content"]
    assert "top-secret-token" not in content
    assert "my-secret-cookie" not in content
    assert "[REDACTED]" in content


def test_detect_sqli_is_registered_on_mcp_server():
    assert server.detect_sqli in server.TOOLS
