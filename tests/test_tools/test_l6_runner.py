import asyncio
import importlib.util
import json
from collections.abc import Callable
from functools import wraps
from pathlib import Path

import pytest

from mcp_servers.websec_tools.errors import ToolError

_runner_spec = importlib.util.spec_from_file_location(
    "l6_probe_target", Path(__file__).parents[2] / "examples" / "probe_target.py"
)
runner = importlib.util.module_from_spec(_runner_spec)
assert _runner_spec.loader is not None
_runner_spec.loader.exec_module(runner)


def async_test(function: Callable):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


def envelope(data):
    return {"summary": "ok", "data": data, "truncated": False}


def service_envelope(address="192.168.56.10"):
    return envelope(
        {
            "target": address,
            "profile": "service-top-100",
            "requested_ports": [],
            "hosts": [
                {
                    "address": address,
                    "address_type": "ipv4",
                    "hostnames": [],
                    "state": "up",
                    "services": [
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                            "product": None,
                            "version": None,
                            "extra_info": None,
                            "tunnel": None,
                            "cpe": [],
                        },
                        {
                            "port": 443,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "https",
                            "product": None,
                            "version": None,
                            "extra_info": None,
                            "tunnel": "ssl",
                            "cpe": [],
                        },
                    ],
                }
            ],
        }
    )


def success_tools(calls, service_result=None):
    async def discover_hosts(target):
        calls.append(("discover_hosts", target))
        return envelope({"hosts": []})

    async def discover_services(target):
        calls.append(("discover_services", target))
        return service_result or service_envelope()

    async def generic(name, target):
        calls.append((name, target))
        return envelope({"target": target})

    return {
        "discover_hosts": discover_hosts,
        "discover_services": discover_services,
        "get_response_headers": lambda target: generic("get_response_headers", target),
        "get_cookies": lambda target: generic("get_cookies", target),
        "get_tls_info": lambda target: generic("get_tls_info", target),
        "get_cors_policy": lambda target: generic("get_cors_policy", target),
        "fingerprint_web": lambda target: generic("fingerprint_web", target),
        "crawl_web": lambda target: generic("crawl_web", target),
        "passive_web_analysis": lambda target: generic("passive_web_analysis", target),
        "parse_api_spec": lambda target: generic("parse_api_spec", target),
    }


def test_target_classification_covers_url_host_ip_ipv6_and_cidr():
    assert runner._classify_target("https://example.com/app") == "url"
    assert runner._classify_target("example.com") == "network"
    assert runner._classify_target("192.168.56.10") == "network"
    assert runner._classify_target("2001:db8::10") == "network"
    assert runner._classify_target("192.168.56.0/24") == "network"


def test_service_derivation_normalizes_ports_brackets_and_caps_targets():
    services = {
        "data": {
            "hosts": [
                {
                    "address": "2001:db8::10",
                    "services": [
                        {"port": 80, "state": "open", "service": "http"},
                        {"port": 443, "state": "open", "service": "https"},
                        {"port": 8443, "state": "open", "service": "ssl/http"},
                    ],
                }
            ]
        }
    }
    assert runner._derive_web_targets(services) == [
        "http://[2001:db8::10]/",
        "https://[2001:db8::10]/",
        "https://[2001:db8::10]:8443/",
    ]


def test_web_target_cap_keeps_pinned_url_and_sorts_remaining_targets():
    pinned = "https://example.com/app"
    targets = [pinned, *(f"http://host-{index}.test/" for index in range(20))]
    limited = runner._limit_web_targets(targets, pinned=pinned)
    assert len(limited) == 10
    assert pinned in limited
    assert limited == sorted(limited)


def test_openapi_candidates_use_origin_and_fixed_order():
    candidates = runner._openapi_candidates(
        ["https://example.com/app/login"], "https://example.com/app/login"
    )
    assert candidates == [
        "https://example.com/openapi.json",
        "https://example.com/openapi.yaml",
        "https://example.com/swagger.json",
        "https://example.com/swagger.yaml",
        "https://example.com/v3/api-docs",
    ]
    spec_candidates = runner._openapi_candidates(
        ["https://example.com/app"], "https://example.com/docs/openapi.json"
    )
    assert spec_candidates[0] == "https://example.com/docs/openapi.json"


@async_test
async def test_all_mode_runs_discovery_and_all_applicable_tools(monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "_tool_calls", lambda: success_tools(calls))

    report, exit_code = await runner.run_recon("192.168.56.10")

    assert exit_code == 0
    assert report["web_targets"] == [
        "http://192.168.56.10/",
        "https://192.168.56.10/",
    ]
    assert calls[:2] == [
        ("discover_hosts", "192.168.56.10"),
        ("discover_services", "192.168.56.10"),
    ]
    assert sum(name == "crawl_web" for name, _target in calls) == 2
    assert sum(name == "passive_web_analysis" for name, _target in calls) == 2
    assert report["results"]["parse_api_spec"]["status"] == "success"


@async_test
async def test_explicit_tool_does_not_run_hidden_nmap(monkeypatch):
    calls = []
    tools = success_tools(calls)
    monkeypatch.setattr(runner, "_tool_calls", lambda: tools)

    report, exit_code = await runner.run_recon("192.168.56.10", ("get_response_headers",))

    assert exit_code == 0
    assert calls == [("get_response_headers", "192.168.56.10")]
    assert report["results"]["get_response_headers"]["status"] == "success"


@async_test
async def test_explicit_raw_ip_web_tool_is_error_without_nmap(monkeypatch):
    calls = []

    async def headers(target):
        calls.append(target)
        raise ToolError("E_INVALID_TARGET", "target must be an absolute HTTP(S) URL")

    monkeypatch.setattr(
        runner,
        "_tool_calls",
        lambda: {**success_tools([]), "get_response_headers": headers},
    )
    report, exit_code = await runner.run_recon("192.168.56.10", ("get_response_headers",))

    assert exit_code == 1
    assert calls == ["192.168.56.10"]
    assert report["results"]["get_response_headers"]["status"] == "error"


@async_test
async def test_url_is_retained_when_nmap_unavailable(monkeypatch):
    calls = []
    tools = success_tools(calls)

    async def unavailable(target):
        calls.append(("nmap", target))
        raise ToolError("E_TOOL_UNAVAILABLE", "Nmap executable is not available")

    tools["discover_hosts"] = unavailable
    tools["discover_services"] = unavailable
    monkeypatch.setattr(runner, "_tool_calls", lambda: tools)

    report, exit_code = await runner.run_recon("https://example.com/app")

    assert exit_code == 1
    assert report["web_targets"] == ["https://example.com/app"]
    assert report["results"]["get_response_headers"]["status"] == "success"


@async_test
async def test_external_tool_failures_are_isolated(monkeypatch):
    calls = []
    tools = success_tools(calls)

    async def unavailable(target):
        calls.append(("unavailable", target))
        raise ToolError("E_TOOL_UNAVAILABLE", "external tool is unavailable")

    tools["fingerprint_web"] = unavailable
    tools["crawl_web"] = unavailable
    tools["passive_web_analysis"] = unavailable
    monkeypatch.setattr(runner, "_tool_calls", lambda: tools)

    report, exit_code = await runner.run_recon("https://example.com")

    assert exit_code == 1
    assert report["results"]["fingerprint_web"]["status"] == "error"
    assert report["results"]["crawl_web"]["status"] == "error"
    assert report["results"]["passive_web_analysis"]["status"] == "error"
    assert report["results"]["get_response_headers"]["status"] == "success"


@async_test
async def test_openapi_candidate_probe_stops_at_first_valid_spec(monkeypatch):
    calls = []

    async def parse(target):
        calls.append(target)
        if target.endswith("openapi.json"):
            raise ToolError("E_PARSE", "not a valid specification")
        return envelope({"source_url": target, "operations": []})

    tools = success_tools([])
    tools["parse_api_spec"] = parse
    result = await runner._run_openapi_candidates(
        ["https://example.com/openapi.json", "https://example.com/openapi.yaml"], tools
    )

    assert result["status"] == "success"
    assert calls == ["https://example.com/openapi.json", "https://example.com/openapi.yaml"]


@async_test
async def test_openapi_not_found_is_skipped_without_failure(monkeypatch):
    async def parse(_target):
        raise ToolError("E_HTTP", "OpenAPI fetch returned HTTP 404")

    tools = success_tools([])
    tools["parse_api_spec"] = parse
    monkeypatch.setattr(runner, "_tool_calls", lambda: tools)
    report, exit_code = await runner.run_recon("https://example.com")

    assert exit_code == 0
    assert report["results"]["parse_api_spec"] == {
        "status": "skipped",
        "invocations": [],
        "reason": "no OpenAPI specification discovered",
    }


@async_test
async def test_explicit_openapi_does_not_probe_candidates(monkeypatch):
    calls = []

    async def parse(target):
        calls.append(target)
        return envelope({"source_url": target, "operations": []})

    tools = success_tools([])
    tools["parse_api_spec"] = parse
    monkeypatch.setattr(runner, "_tool_calls", lambda: tools)
    report, exit_code = await runner.run_recon("https://example.com/app/login", ("parse_api_spec",))

    assert exit_code == 0
    assert calls == ["https://example.com/app/login"]
    assert report["results"]["parse_api_spec"]["status"] == "success"


def test_main_rejects_mixed_all_mode():
    with pytest.raises(SystemExit) as error:
        runner.main(["example.com", "--tool", "all", "--tool", "discover_hosts"])
    assert error.value.code == 2


def test_main_writes_the_same_deterministic_json_to_stdout_and_file(monkeypatch, capsys, tmp_path):
    async def fake_run_recon(_target, _selected):
        return {
            "target": "example.com",
            "web_targets": [],
            "results": {},
        }, 0

    monkeypatch.setattr(runner, "run_recon", fake_run_recon)
    output_path = tmp_path / "report.json"
    assert runner.main(["example.com", "--tool", "discover_hosts", "--json", str(output_path)]) == 0
    stdout_report = json.loads(capsys.readouterr().out)
    file_report = json.loads(output_path.read_text(encoding="utf-8"))
    assert stdout_report == file_report


@async_test
async def test_report_serialization_is_deterministic(monkeypatch):
    tools = success_tools([])
    monkeypatch.setattr(runner, "_tool_calls", lambda: tools)
    report, _exit_code = await runner.run_recon("192.168.56.10", ("discover_hosts",))
    first = json.dumps(report, ensure_ascii=False, sort_keys=True)
    second = json.dumps(report, ensure_ascii=False, sort_keys=True)
    assert first == second


def test_runner_has_no_agent_or_partner_imports():
    assert "websecuritycheck" not in runner.__dict__
    assert "strands" not in runner.__dict__
