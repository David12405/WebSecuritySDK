import asyncio
import json
from pathlib import Path

import pytest

from mcp_servers.websec_tools import server
from mcp_servers.websec_tools.analysis import semgrep, source
from mcp_servers.websec_tools.errors import ToolError


def run(coro):
    return asyncio.run(coro)


def test_source_tools_are_bounded_and_repository_relative(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("first\nCursor.execute(value)\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("TOKEN=secret\n", encoding="utf-8")

    tree = run(source.inspect_source_tree(str(tmp_path)))
    assert tree["data"]["path"] == "."
    assert [item["path"] for item in tree["data"]["files"]] == ["app/main.py", "pyproject.toml"]
    assert tree["data"]["manifests"] == ["pyproject.toml"]

    read = run(source.read_source_file(str(tmp_path), "app/main.py"))
    assert read["data"]["content"].startswith("first")
    assert read["truncated"] is False

    matches = run(source.search_source(str(tmp_path), "cursor.execute"))
    assert matches["data"]["matches"][0]["line"] == 2
    assert matches["data"]["matches"][0]["column"] == 1
    assert all(not Path(item["path"]).is_absolute() for item in matches["data"]["matches"])


def test_source_paths_and_sensitive_content_are_rejected(tmp_path: Path):
    (tmp_path / "secret.pem").write_text("PRIVATE KEY", encoding="utf-8")
    with pytest.raises(ToolError) as error:
        run(source.read_source_file(str(tmp_path), "../secret.pem"))
    assert error.value.code == "E_INVALID_ARGUMENT"
    with pytest.raises(ToolError) as error:
        run(source.read_source_file(str(tmp_path), "secret.pem"))
    assert error.value.code == "E_UNSUPPORTED_INPUT"


def test_semgrep_parser_uses_authoritative_scanned_paths_and_redacts(tmp_path: Path):
    (tmp_path / ".env.production").write_text("TOKEN=secret", encoding="utf-8")

    async def fake_runner(argv, cwd, output_path, stderr_path):
        Path(output_path).write_text(
            json.dumps(
                {
                    "version": "1.0",
                    "paths": {"scanned": [".env.production"]},
                    "results": [
                        {
                            "check_id": "secret.rule",
                            "path": ".env.production",
                            "start": {"line": 1, "col": 1},
                            "end": {"line": 1, "col": 5},
                            "extra": {
                                "message": "secret",
                                "severity": "WARNING",
                                "lines": "TOKEN=secret",
                                "metavars": {"$X": {"abstract_content": "secret"}},
                            },
                        }
                    ],
                    "errors": [],
                }
            ),
            encoding="utf-8",
        )
        return 0

    result = run(semgrep.analyze_source(str(tmp_path), runner=fake_runner))
    finding = result["data"]["findings"][0]
    assert result["data"]["files_scanned"] == 1
    assert result["data"]["scanned_files"] == [".env.production"]
    assert finding["file"] == ".env.production"
    assert finding["snippet"] is None
    assert finding["dataflow_trace"] is None
    assert finding["metavariables"] == {}


def test_semgrep_missing_scanned_paths_is_null(tmp_path: Path):
    (tmp_path / "main.py").write_text("x = 1", encoding="utf-8")

    async def fake_runner(argv, cwd, output_path, stderr_path):
        assert "--no-git-ignore" in argv
        assert "--no-rewrite-rule-ids" in argv
        assert "--exclude=.env*" in argv
        assert "--exclude=*.pem" in argv
        assert "--exclude=credentials.json" in argv
        Path(output_path).write_text(json.dumps({"results": [], "errors": []}), encoding="utf-8")
        return 0

    result = run(semgrep.analyze_source(str(tmp_path), runner=fake_runner))
    assert result["data"]["files_scanned"] is None
    assert result["data"]["scanned_files"] == []
    assert result["data"]["findings"] == []


def test_semgrep_nested_root_uses_git_root_and_normalizes_scanned_files(tmp_path: Path):
    repo = tmp_path / "repo"
    approved = repo / "nested" / "approved"
    approved.mkdir(parents=True)
    (repo / ".git").mkdir()
    source_file = approved / "main.py"
    source_file.write_text("print('ok')", encoding="utf-8")

    async def fake_runner(argv, cwd, output_path, stderr_path):
        assert cwd == repo
        assert argv[-1] == "nested/approved"
        output_path.write_text(
            json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": ["nested/approved/main.py"]},
                }
            ),
            encoding="utf-8",
        )
        return 0

    result = run(semgrep.analyze_source(str(approved), runner=fake_runner))
    assert result["data"]["files_scanned"] == 1
    assert result["data"]["scanned_files"] == ["main.py"]


def test_semgrep_explicit_nested_file_is_the_command_target(tmp_path: Path):
    repo = tmp_path / "repo"
    approved = repo / "tests" / "fixture"
    source_file = approved / "positive" / "worker.js"
    source_file.parent.mkdir(parents=True)
    (repo / ".git").mkdir()
    source_file.write_text("eval(input)", encoding="utf-8")

    async def fake_runner(argv, cwd, output_path, stderr_path):
        assert cwd == repo
        assert argv[-1] == "tests/fixture/positive/worker.js"
        output_path.write_text(
            json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": ["tests/fixture/positive/worker.js"]},
                }
            ),
            encoding="utf-8",
        )
        return 0

    result = run(
        semgrep.analyze_source(
            str(approved), path="positive/worker.js", runner=fake_runner
        )
    )
    assert result["data"]["files_scanned"] == 1
    assert result["data"]["scanned_files"] == ["positive/worker.js"]


def test_semgrep_rejects_out_of_scope_scanned_path(tmp_path: Path):
    approved = tmp_path / "approved"
    approved.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')", encoding="utf-8")

    async def fake_runner(argv, cwd, output_path, stderr_path):
        output_path.write_text(
            json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": ["../outside.py"]},
                }
            ),
            encoding="utf-8",
        )
        return 0

    with pytest.raises(ToolError, match=r"invalid|out-of-scope"):
        run(semgrep.analyze_source(str(approved), runner=fake_runner))


def test_mcp_registration_is_backward_compatible():
    names = {tool.__name__ for tool in server.TOOLS}
    assert {
        "get_response_headers", "get_cookies", "get_tls_info", "get_cors_policy",
        "discover_hosts", "discover_services", "crawl_web", "passive_web_analysis",
        "fingerprint_web", "parse_api_spec",
    } <= names
    assert {"inspect_source_tree", "read_source_file", "search_source", "analyze_source"} <= names
