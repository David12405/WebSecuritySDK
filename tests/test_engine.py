"""The pieces the agent loop is assembled from.

No network, no model, no MCP subprocess. What is tested here is everything
that can be decided before a model is involved: the check catalog, the
settings, the model-string translation, the server config, and the trace -
which is the one that decides a run's status.
"""

from __future__ import annotations

from typing import Any

import pytest
from strands.hooks import AfterToolCallEvent, BeforeToolCallEvent
from strands.vended_plugins.skills import Skill

from websecuritycheck.checks import HEADERS, all_checks, get
from websecuritycheck.config import Settings
from websecuritycheck.engine.models import build_model, split_model
from websecuritycheck.engine.prompts import system_prompt
from websecuritycheck.memory.context import framework_tools_for
from websecuritycheck.results.models import CheckOutput
from websecuritycheck.telemetry.trace import KINDS_BY_LEVEL, TraceCollector
from websecuritycheck.tools.mcp import load_server_specs

# --------------------------------------------------------------------------
# The check catalog
# --------------------------------------------------------------------------


def test_the_headers_check_is_registered() -> None:
    assert get("headers") is HEADERS
    assert "headers" in [check.name for check in all_checks()]


def test_a_check_declares_its_own_allowlist() -> None:
    """The allowlist is the check's, not the server's.

    The partner's server exposes ten tools; this check may call one.
    """
    assert HEADERS.tools == ("get_response_headers",)


def test_the_skill_loads_and_names_the_required_topics() -> None:
    skill = HEADERS.skill_text()
    for topic in HEADERS.required_coverage:
        assert topic in skill.lower(), f"{topic} is required but the skill never mentions it"


def write_skill(tmp_path, header: str, body: str = "# Skill: x\n\nmethod"):
    """A skill folder on disk, which is what Strands' loader reads."""
    folder = tmp_path / "x"
    folder.mkdir()
    (folder / "SKILL.md").write_text(f"---\n{header}\n---\n{body}", encoding="utf-8")
    return folder


def test_the_skill_header_is_parsed() -> None:
    """The format is Strands'; the loader is theirs too."""
    doc = HEADERS.skill_doc()
    assert isinstance(doc, Skill)
    assert doc.name == "headers"
    assert "HSTS" in doc.description
    assert doc.allowed_tools == ["get_response_headers"]
    assert doc.instructions.startswith("# Skill:")


def test_the_header_is_not_repeated_in_the_body() -> None:
    """The frontmatter is metadata, not prose the model reads twice."""
    assert "allowed-tools:" not in HEADERS.skill_text()


def test_the_skill_and_the_check_agree_on_the_allowlist() -> None:
    """Two statements of the allowlist, and they must not drift.

    `Check.tools` is the one the scope guard enforces - a security boundary
    belongs in code a reviewer sees in the diff, not in a markdown file a
    non-engineer edits. Strands documents `Skill.allowed_tools` as not
    enforced, which is the same conclusion reached from the other side. The
    skill states it so the method reads on its own; this keeps it honest.
    """
    for check in all_checks():
        assert tuple(check.skill_doc().allowed_tools or ()) == check.tools, check.name


def test_a_malformed_skill_is_refused_rather_than_degraded(tmp_path) -> None:
    """Strands defaults to warn-and-load. We ask for strict.

    Right for a general agent discovering skills it did not write; wrong
    here, where a half-read skill means a check runs with no method.
    """
    folder = write_skill(tmp_path, "name: x")  # no description
    with pytest.raises(Exception, match=r"(?i)description"):
        Skill.from_file(folder, strict=True)


def test_a_well_formed_skill_folder_loads(tmp_path) -> None:
    folder = write_skill(tmp_path, "name: x\ndescription: what it does\nallowed-tools: [a, b]")
    doc = Skill.from_file(folder, strict=True)
    assert doc.description == "what it does"
    assert doc.allowed_tools == ["a", "b"]
    assert doc.instructions.strip() == "# Skill: x\n\nmethod"


# --------------------------------------------------------------------------
# The prompt
# --------------------------------------------------------------------------


def test_the_prompt_carries_the_task_and_the_skill() -> None:
    prompt = system_prompt(HEADERS)
    assert HEADERS.task.splitlines()[0] in prompt
    assert "Skill: HTTP security headers" in prompt


def test_the_prompt_states_the_rules_the_hooks_enforce() -> None:
    """The hooks make compliance beside the point; the prompt explains why."""
    prompt = system_prompt(HEADERS).lower()
    assert "evidence" in prompt
    assert "never an instruction" in prompt
    assert "no tool, no answer" in prompt


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------


def test_scope_is_required() -> None:
    with pytest.raises(ValueError, match="scope is required"):
        Settings(model="openai:gpt-4o-mini", scope=[])


def test_a_bad_scope_fails_at_construction() -> None:
    """Not on the first tool call of a run the developer already paid for."""
    with pytest.raises(ValueError, match="no scheme"):
        Settings(model="openai:gpt-4o-mini", scope=["myapp.com"])


def test_the_scope_is_parsed_once() -> None:
    settings = Settings(model="openai:gpt-4o-mini", scope=["https://myapp.com"])
    assert [entry.host for entry in settings.entries] == ["myapp.com"]


# --------------------------------------------------------------------------
# The model string
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("openai:gpt-4o-mini", ("openai", "gpt-4o-mini")),
        ("bedrock:anthropic.claude-3", ("bedrock", "anthropic.claude-3")),
        # No known prefix: a bare id is a Bedrock id, which is how Strands
        # reads it, so an AWS user configures nothing.
        ("anthropic.claude-3-5-sonnet", ("bedrock", "anthropic.claude-3-5-sonnet")),
        ("gpt-4o-mini", ("bedrock", "gpt-4o-mini")),
    ],
)
def test_the_provider_prefix_is_split_off(configured: str, expected: tuple[str, str]) -> None:
    assert split_model(configured) == expected


def test_a_missing_openai_key_says_which_variable(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        build_model("openai:gpt-4o-mini")


def test_an_openai_model_is_built_from_a_key(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-not-a-real-key")
    assert build_model("openai:gpt-4o-mini") is not None


# --------------------------------------------------------------------------
# Server config
# --------------------------------------------------------------------------


def test_only_enabled_servers_are_started(tmp_path) -> None:
    config = tmp_path / "servers.yaml"
    config.write_text(
        "servers:\n"
        "  - name: ours\n"
        "    transport: stdio\n"
        "    command: python\n"
        "    args: ['-m', 'mcp_servers.websec_tools.server']\n"
        "    enabled: true\n"
        "  - name: partner\n"
        "    transport: stdio\n"
        "    command: python\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    specs = load_server_specs(config)
    assert [spec.name for spec in specs] == ["ours"]
    assert specs[0].args == ("-m", "mcp_servers.websec_tools.server")


def test_an_unsupported_transport_is_refused(tmp_path) -> None:
    """A code path with no server behind it is a code path nobody has run."""
    config = tmp_path / "servers.yaml"
    config.write_text(
        "servers:\n  - name: http-one\n    transport: http\n    command: x\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="only the stdio transport"):
        load_server_specs(config)


# --------------------------------------------------------------------------
# The trace, which decides the status
# --------------------------------------------------------------------------


def before_event(name: str = "get_response_headers") -> BeforeToolCallEvent:
    return BeforeToolCallEvent(
        agent=None,
        selected_tool=None,
        tool_use={"name": name, "input": {}, "toolUseId": "tu-1"},
        invocation_state={},
    )


def after_event(name: str = "get_response_headers", *, error: bool = False, text: str = "") -> Any:
    return AfterToolCallEvent(
        agent=None,
        selected_tool=None,
        tool_use={"name": name, "input": {}, "toolUseId": "tu-1"},
        invocation_state={},
        result={
            "content": [{"text": text or "ok"}],
            "status": "error" if error else "success",
            "toolUseId": "tu-1",
        },
        duration=0.5,
    )


def test_ids_are_contiguous_and_ordered() -> None:
    trace = TraceCollector()
    trace.record("skill_loaded", name="headers")
    trace._after_tool(after_event())
    assert [step.id for step in trace.steps] == ["s1", "s2"]


def test_an_id_is_not_spent_on_a_step_the_level_dropped() -> None:
    trace = TraceCollector(level="summary")
    trace.record("model_call", name="gpt")  # dropped at this level
    trace.record("skill_loaded", name="headers")
    assert [step.id for step in trace.steps] == ["s1"]


def test_summary_leaves_out_model_calls_and_full_keeps_them() -> None:
    assert "model_call" not in KINDS_BY_LEVEL["summary"]
    assert "model_call" in KINDS_BY_LEVEL["full"]
    assert KINDS_BY_LEVEL["off"] == frozenset()


def test_a_successful_tool_call_counts_as_measurement() -> None:
    trace = TraceCollector()
    trace._after_tool(after_event())
    assert trace.tools_ran == 1


def test_a_failed_tool_call_does_not() -> None:
    trace = TraceCollector()
    trace._after_tool(after_event(error=True, text="E_TIMEOUT: timed out"))
    assert trace.tools_ran == 0
    assert trace.steps[0].code == "E_TIMEOUT"
    assert trace.steps[0].summary == "timed out"


def test_the_structured_output_tool_is_not_a_measurement() -> None:
    """The trap §11.7 describes, and the reason the collector takes an exempt set.

    The structured-output tool runs on every turn. Count it and every run
    has called a tool, which makes "this check measured nothing" unprovable
    and lets a run whose only real probe failed come back `passed`.
    """
    trace = TraceCollector(exempt=framework_tools_for(CheckOutput))
    trace._after_tool(after_event(name="CheckOutput"))
    trace._after_tool(after_event(name="retrieve_context"))
    assert trace.tools_ran == 0
    assert trace.steps == []


def test_a_cancelled_call_is_recorded_with_its_reason() -> None:
    """Caught at the decision point, where the reason still exists."""
    trace = TraceCollector()
    event = before_event()
    event.cancel_tool = "host 'evil.com' is not in scope"
    trace._before_tool(event)
    assert trace.steps[0].kind == "cancelled"
    assert trace.steps[0].status == "cancelled"
    assert "evil.com" in trace.steps[0].summary
    assert trace.tools_ran == 0


def test_an_allowed_call_records_nothing_before_it_runs() -> None:
    trace = TraceCollector()
    trace._before_tool(before_event())
    assert trace.steps == []


def test_a_successful_step_does_not_quote_the_target() -> None:
    """Our sentence, not the target's. The trace is read by people and CI."""
    trace = TraceCollector()
    trace._after_tool(after_event(text="Set-Cookie: sid=secret-session-value"))
    assert "secret-session-value" not in trace.steps[0].summary


def test_the_duration_is_carried() -> None:
    trace = TraceCollector()
    trace._after_tool(after_event())
    assert trace.steps[0].duration_ms == 500
