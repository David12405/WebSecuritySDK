"""Tests for deterministic hypothesis generation and the tier-3 guard.

Two halves. The first runs against `envelope_api.json`, a real Module 2
envelope captured from the authorized lab, so the generator is exercised on
data nobody wrote to make it pass. The second builds relations by hand to
reach the shapes that capture did not contain - a traced flow, a CVE, a
relation with no category - and to prove the guard refuses the things the
schema and the handoff validator let through.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from websecuritycheck.analysis.correlation import (
    CorrelationKind,
    CorrelationRecord,
    CorrelationResult,
    CorrelationStatus,
    IndependenceAssessment,
    IndependenceStatus,
)
from websecuritycheck.analysis.cve import InjectionSubtype
from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    Module2Output,
    SinkRelationship,
    TechnologyTargetRef,
    ValidationCapability,
    VulnerabilityCategory,
)
from websecuritycheck.domain.enums import TechnologyCategory
from websecuritycheck.hypothesis import (
    HypothesisGuardError,
    InputChoice,
    SelectionRequest,
    check_hypotheses,
    enforce,
    generate_hypotheses,
    heuristic_selector,
)

CAPTURED = (
    Path(__file__).resolve().parent
    / "test_analysis"
    / "captured_envelopes"
    / "envelope_api.json"
)


def _record(**overrides) -> CorrelationRecord:
    """A VERIFIED INPUT_SINK relation, with fields overridable per test."""
    base = {
        "correlation_id": "COR-" + "a" * 16,
        "kind": CorrelationKind.INPUT_SINK,
        "status": CorrelationStatus.VERIFIED,
        "confidence": ConfidenceLevel.HIGH,
        "injection_subtype": InjectionSubtype.SQL_INJECTION,
        "vulnerability_category": VulnerabilityCategory.SQL_INJECTION,
        "endpoint_id": "a" * 12,
        "input_ref": "INP-001",
        "sink_ref": "SNK-001",
        "sink_relationship": SinkRelationship.STATIC_TAINT_FLOW_FOUND,
        "relation_evidence_refs": ["EVD-004"],
        "independent_relation_source_count": 2,
        "independence": IndependenceAssessment(
            status=IndependenceStatus.INDEPENDENT, distinct_execution_count=2
        ),
        "rationale": "Parameter flows into a raw SQL string.",
    }
    base.update(overrides)
    return CorrelationRecord(**base)


# --------------------------------------------------------------------------- #
# Against the real captured envelope
# --------------------------------------------------------------------------- #


@pytest.fixture
def captured() -> tuple[Module2Output, CorrelationResult]:
    if not CAPTURED.is_file():
        pytest.skip(f"no captured envelope at {CAPTURED}; run the live capture first")
    data = json.loads(CAPTURED.read_text(encoding="utf-8"))
    return (
        Module2Output.model_validate(data["output"]),
        CorrelationResult.model_validate(data["correlation"]),
    )


def test_real_envelope_generates_guarded_hypotheses(captured):
    output, correlation = captured
    result = generate_hypotheses(output, correlation.records)

    assert result.hypotheses, "the captured relations should yield hypotheses"
    # Nothing may be asserted as confirmed, and every hypothesis must trace
    # back to the relation it came from.
    for hypothesis in result.hypotheses:
        assert hypothesis.hypothesis_id in result.provenance
        assert hypothesis.validation_proposals, "each hypothesis carries a proposal"

    # The guard is the point: real data must pass it with nothing to report.
    assert check_hypotheses(
        result.hypotheses, output, correlation.records, result.provenance
    ) == []


def test_real_envelope_traced_flows_are_verified_and_capped(captured):
    output, correlation = captured
    result = generate_hypotheses(output, correlation.records)

    # The captured relations are traced INPUT_SINK flows: AST taint named the
    # parameter that reaches the sink, so each hypothesis claims a verified flow,
    # carries the relation's MEDIUM confidence (not promoted, not dropped to LOW),
    # and has no "parameter was not traced" note. The untraced ENDPOINT_SINK case
    # is covered by test_selected_parameter_is_capped_at_low_however_strong_the_relation.
    assert result.hypotheses, "the captured relations should yield hypotheses"
    for hypothesis in result.hypotheses:
        assert hypothesis.sink_relationship == SinkRelationship.STATIC_TAINT_FLOW_FOUND
        assert hypothesis.confidence == ConfidenceLevel.MEDIUM
        assert not any("dataflow" in item.lower() for item in hypothesis.missing_evidence)


def test_real_envelope_traced_flows_bind_one_input_per_endpoint(captured):
    output, correlation = captured
    result = generate_hypotheses(output, correlation.records)

    # Every captured relation names its own traced input, so the selector never
    # runs and each endpoint yields exactly one candidate - there is no
    # multi-candidate tie for priority to break in this data. The tie-breaking
    # itself is covered by the hand-built selector tests below.
    by_endpoint: dict[str, list[int]] = {}
    for hypothesis in result.hypotheses:
        priority = hypothesis.validation_proposals[0].priority
        by_endpoint.setdefault(hypothesis.target_endpoint_id, []).append(priority)

    assert by_endpoint, "the captured relations should yield endpoint-scoped hypotheses"
    for endpoint, priorities in by_endpoint.items():
        assert len(priorities) == 1, f"a traced flow should bind one input on {endpoint}"
        assert 1 <= priorities[0] <= 10


# --------------------------------------------------------------------------- #
# Shapes the capture did not contain
# --------------------------------------------------------------------------- #


def test_traced_flow_uses_the_recorded_input_not_the_selector():
    output = Module2Output.model_validate(_minimal_output())

    def never_called(request: SelectionRequest):  # pragma: no cover - must not run
        raise AssertionError("a traced relation already names its input")

    result = generate_hypotheses(
        output, [_record()], select_inputs=never_called
    )

    assert len(result.hypotheses) == 1
    hypothesis = result.hypotheses[0]
    assert hypothesis.input_ref == "INP-001"
    assert hypothesis.sink_relationship == SinkRelationship.STATIC_TAINT_FLOW_FOUND
    assert hypothesis.confidence == ConfidenceLevel.HIGH


def test_cve_relation_becomes_known_cve_without_endpoint_or_sink():
    output = Module2Output.model_validate(_minimal_output())
    technology = TechnologyTargetRef(
        category=TechnologyCategory.WEB_SERVER, name="Apache", version="2.4.49"
    )
    record = _record(
        kind=CorrelationKind.CVE_TECHNOLOGY,
        vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
        cve_candidate_ref="CVC-001",
        target_technology=technology,
        endpoint_id=None,
        input_ref=None,
        sink_ref=None,
        sink_relationship=SinkRelationship.UNKNOWN,
    )

    result = generate_hypotheses(output, [record])

    assert len(result.hypotheses) == 1
    hypothesis = result.hypotheses[0]
    assert hypothesis.vulnerability_category == VulnerabilityCategory.KNOWN_CVE
    assert hypothesis.cve_candidate_ref == "CVC-001"
    # A KNOWN_CVE claim is about a component, not a parameter.
    assert hypothesis.input_ref is None and hypothesis.sink_ref is None
    proposal = hypothesis.validation_proposals[0]
    assert proposal.suggested_capability == ValidationCapability.CVE_SAFE_CHECK


def test_sink_cve_supports_but_does_not_claim():
    output = Module2Output.model_validate(_minimal_output())
    # Module 2 constrains SINK_CVE tightly - PARTIAL, no endpoint or input,
    # and a component link back to the CVE_TECHNOLOGY record - so the relation
    # has to be built the way it really arrives.
    record = _record(
        kind=CorrelationKind.SINK_CVE,
        status=CorrelationStatus.PARTIAL,
        confidence=ConfidenceLevel.MEDIUM,
        endpoint_id=None,
        input_ref=None,
        sink_relationship=SinkRelationship.UNVERIFIED_STATIC_SINK,
        cve_candidate_ref="CVC-001",
        target_technology=TechnologyTargetRef(
            category=TechnologyCategory.WEB_SERVER, name="Apache", version="2.4.49"
        ),
        component_refs=["COR-" + "b" * 16],
    )

    result = generate_hypotheses(output, [record])

    # The relation strengthens a CVE hypothesis; it is not a separate weakness.
    assert result.hypotheses == []
    assert result.limitations == []


def test_relation_without_category_is_reported_not_dropped():
    output = Module2Output.model_validate(_minimal_output())
    record = _record(vulnerability_category=None, injection_subtype=InjectionSubtype.CODE_INJECTION)

    result = generate_hypotheses(output, [record])

    assert result.hypotheses == []
    assert any("no vulnerability_category" in item for item in result.limitations)


def test_confidence_never_rises_above_the_relation():
    output = Module2Output.model_validate(_minimal_output())
    # A traced relation Module 2 scored MEDIUM must not become a HIGH claim:
    # the hypothesis inherits the ceiling, it does not set its own.
    record = _record(confidence=ConfidenceLevel.MEDIUM)

    result = generate_hypotheses(output, [record])

    assert result.hypotheses[0].confidence == ConfidenceLevel.MEDIUM


def test_selected_parameter_is_capped_at_low_however_strong_the_relation():
    output = Module2Output.model_validate(_minimal_output())
    # The sink sits in the handler and the relation scored MEDIUM, but the
    # parameter was chosen rather than traced: that is weaker than anything
    # Module 2 verified, and the hypothesis has to say so.
    record = _record(
        kind=CorrelationKind.ENDPOINT_SINK,
        status=CorrelationStatus.PARTIAL,
        confidence=ConfidenceLevel.MEDIUM,
        input_ref=None,
        sink_relationship=SinkRelationship.UNVERIFIED_STATIC_SINK,
    )

    result = generate_hypotheses(output, [record])

    assert result.hypotheses[0].confidence == ConfidenceLevel.LOW


# --------------------------------------------------------------------------- #
# The selector contract
# --------------------------------------------------------------------------- #


def test_heuristic_skips_containers_and_numerics():
    request = SelectionRequest(
        endpoint_id="a" * 12,
        sink_id="SNK-001",
        sink_kind="SQL_INJECTION",
        vulnerability_category="SQL_INJECTION",
        rationale="",
        candidates=(
            InputChoice(0, "INP-001", "filters", "JSON_BODY", None),
            InputChoice(1, "INP-002", "filters.category", "JSON_BODY", "string"),
            InputChoice(2, "INP-003", "filters.minPrice", "JSON_BODY", "integer"),
            InputChoice(3, "INP-004", "keyword", "JSON_BODY", "string"),
        ),
        limit=3,
    )

    picks = heuristic_selector(request)

    assert 0 not in picks, "'filters' is only a container for other parameters"
    assert 2 not in picks, "a numeric parameter is a weaker concatenation candidate"
    assert set(picks) == {1, 3}


def test_selector_cannot_smuggle_in_an_unknown_input():
    """A selector answers with positions, so an invented id has nowhere to go."""
    output = Module2Output.model_validate(_minimal_output())
    record = _record(
        kind=CorrelationKind.ENDPOINT_SINK,
        status=CorrelationStatus.PARTIAL,
        confidence=ConfidenceLevel.LOW,
        input_ref=None,
        sink_relationship=SinkRelationship.UNVERIFIED_STATIC_SINK,
    )

    result = generate_hypotheses(
        output, [record], select_inputs=lambda request: [99, -1, 0, 0]
    )

    # Out-of-range and duplicate positions are discarded; only the real one survives.
    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].input_ref == "INP-001"


# --------------------------------------------------------------------------- #
# The guard: what the schema and the handoff validator do not catch
# --------------------------------------------------------------------------- #


def test_guard_rejects_promoted_confidence():
    output = Module2Output.model_validate(_minimal_output())
    record = _record(confidence=ConfidenceLevel.LOW)
    result = generate_hypotheses(output, [record])
    promoted = result.hypotheses[0].model_copy(update={"confidence": ConfidenceLevel.HIGH})

    violations = check_hypotheses([promoted], output, [record], result.provenance)

    assert any("above LOW" in item for item in violations)


def test_guard_rejects_unresolvable_input_ref():
    output = Module2Output.model_validate(_minimal_output())
    record = _record()
    result = generate_hypotheses(output, [record])
    # INP-999 satisfies the id pattern and the handoff validator never looks
    # at input_ref, so only this layer can catch it.
    bogus = result.hypotheses[0].model_copy(update={"input_ref": "INP-999"})

    violations = check_hypotheses([bogus], output, [record], result.provenance)

    assert any("INP-999 is not an InputCandidate" in item for item in violations)


def test_guard_rejects_input_from_another_endpoint():
    output = Module2Output.model_validate(_minimal_output(extra_endpoint=True))
    record = _record()
    result = generate_hypotheses(output, [record])
    # INP-002 exists, but on a different endpoint than the hypothesis targets.
    crossed = result.hypotheses[0].model_copy(update={"input_ref": "INP-002"})

    violations = check_hypotheses([crossed], output, [record], result.provenance)

    assert any("not to the hypothesis endpoint" in item for item in violations)


def test_guard_rejects_borrowed_evidence():
    output = Module2Output.model_validate(_minimal_output())
    record = _record()
    result = generate_hypotheses(output, [record])
    borrowed = result.hypotheses[0].model_copy(
        update={"supporting_evidence_refs": ["EVD-004", "EVD-777"]}
    )

    violations = check_hypotheses([borrowed], output, [record], result.provenance)

    assert any("EVD-777 is not referenced by relation" in item for item in violations)


def test_guard_rejects_untraceable_hypothesis():
    output = Module2Output.model_validate(_minimal_output())
    record = _record()
    result = generate_hypotheses(output, [record])

    violations = check_hypotheses(result.hypotheses, output, [record], provenance={})

    assert any("not traceable to a correlation record" in item for item in violations)


def test_enforce_raises_with_every_violation_listed():
    output = Module2Output.model_validate(_minimal_output())
    record = _record(confidence=ConfidenceLevel.LOW)
    result = generate_hypotheses(output, [record])
    broken = result.hypotheses[0].model_copy(
        update={"confidence": ConfidenceLevel.HIGH, "input_ref": "INP-999"}
    )

    with pytest.raises(HypothesisGuardError) as caught:
        enforce([broken], output, [record], result.provenance)

    assert len(caught.value.violations) == 2


def test_enforce_passes_clean_generation():
    output = Module2Output.model_validate(_minimal_output())
    record = _record()
    result = generate_hypotheses(output, [record])

    enforce(result.hypotheses, output, [record], result.provenance)  # must not raise


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _minimal_output(*, extra_endpoint: bool = False) -> dict:
    """A Module2Output carrying one SQL sink and one or two inputs."""
    endpoint = "a" * 12
    other = "b" * 12
    inputs = [
        {
            "input_id": "INP-001",
            "endpoint_id": endpoint,
            "location": "QUERY",
            "parameter_name": "id",
            "evidence_refs": ["EVD-001"],
            "observation_refs": [],
        }
    ]
    if extra_endpoint:
        inputs.append(
            {
                "input_id": "INP-002",
                "endpoint_id": other,
                "location": "QUERY",
                "parameter_name": "name",
                "evidence_refs": ["EVD-001"],
                "observation_refs": [],
            }
        )
    return {
        "assessment_id": "ASM-001",
        "target_id": "TGT-001",
        "generated_at": "2026-11-10T00:00:00Z",
        "analysis_evidence_records": [],
        "inputs": inputs,
        "sink_candidates": [
            {
                "sink_id": "SNK-001",
                "sink_kind": "SQL_QUERY",
                "file_path": "src/index.js",
                "start_line": 42,
                "rule_id": "rule.sqli",
                "has_static_taint_flow": True,
                "dataflow_steps": [
                    "src/index.js:12 request.query.id",
                    "src/index.js:42 db.prepare(sql)",
                ],
                "confidence": "HIGH",
                "evidence_refs": ["EVD-004"],
                "observation_refs": [],
            }
        ],
        "cve_candidates": [],
        "hypotheses": [],
        "limitations": [],
        "warnings": [],
    }


# --------------------------------------------------------------------------- #
# The model-backed selector, exercised without a model
# --------------------------------------------------------------------------- #


def test_llm_selector_passes_model_choice_through():
    from websecuritycheck.hypothesis.llm import LLMInputSelector, SelectionAnswer

    selector = LLMInputSelector("openai:gpt-4o-mini")
    selector._agent = _FakeAgent(SelectionAnswer(picks=[3, 1], reason="free-text search term"))

    picks = selector(_selection_request())

    assert picks == [3, 1]
    assert selector.errors == []
    assert "free-text" in next(iter(selector.reasons.values()))


def test_llm_selector_falls_back_but_records_why():
    from websecuritycheck.hypothesis.llm import LLMInputSelector

    selector = LLMInputSelector("openai:gpt-4o-mini")
    selector._agent = _FakeAgent(boom=RuntimeError("no api key"))

    picks = selector(_selection_request())

    # The run continues on the deterministic selector, and says that it did.
    assert picks == heuristic_selector(_selection_request())
    assert any("no api key" in item for item in selector.errors)


def test_llm_selector_retries_once_then_gives_up():
    from websecuritycheck.hypothesis.llm import MAX_ATTEMPTS, LLMInputSelector

    selector = LLMInputSelector("openai:gpt-4o-mini")
    agent = _FakeAgent(boom=ValueError("not json"))
    selector._agent = agent

    selector(_selection_request())

    assert agent.calls == MAX_ATTEMPTS


def test_llm_selector_may_choose_nothing():
    from websecuritycheck.hypothesis.llm import LLMInputSelector, SelectionAnswer

    selector = LLMInputSelector("openai:gpt-4o-mini")
    selector._agent = _FakeAgent(SelectionAnswer(picks=[], reason="none reach a SQL sink"))

    # "None of these" is a real answer: a wrong guess costs Module 3 more
    # than a gap does.
    assert selector(_selection_request()) == []
    assert selector.errors == []


def test_llm_selector_cannot_raise_confidence_or_invent_an_input():
    """The model picks positions, so the generator's guarantees still hold."""
    from websecuritycheck.hypothesis.llm import LLMInputSelector, SelectionAnswer

    output = Module2Output.model_validate(_minimal_output())
    record = _record(
        kind=CorrelationKind.ENDPOINT_SINK,
        status=CorrelationStatus.PARTIAL,
        confidence=ConfidenceLevel.MEDIUM,
        input_ref=None,
        sink_relationship=SinkRelationship.UNVERIFIED_STATIC_SINK,
    )
    selector = LLMInputSelector("openai:gpt-4o-mini")
    selector._agent = _FakeAgent(SelectionAnswer(picks=[7, 0], reason="confident"))

    result = generate_hypotheses(output, [record], select_inputs=selector)

    assert len(result.hypotheses) == 1
    assert result.hypotheses[0].input_ref == "INP-001"  # position 7 had nowhere to land
    assert result.hypotheses[0].confidence == ConfidenceLevel.LOW
    assert check_hypotheses(result.hypotheses, output, [record], result.provenance) == []


def test_prompt_numbers_candidates_and_omits_ids():
    from websecuritycheck.hypothesis.llm import prompt_for

    text = prompt_for(_selection_request())

    assert "[3] 'keyword'" in text
    # The model must not be able to echo an id it was never shown.
    assert "INP-" not in text


def _selection_request() -> SelectionRequest:
    return SelectionRequest(
        endpoint_id="a" * 12,
        sink_id="SNK-001",
        sink_kind="SQL_INJECTION",
        vulnerability_category="SQL_INJECTION",
        rationale="sink in handler, no dataflow trace",
        candidates=(
            InputChoice(0, "INP-001", "filters", "JSON_BODY", None),
            InputChoice(1, "INP-002", "filters.category", "JSON_BODY", "string"),
            InputChoice(2, "INP-003", "filters.minPrice", "JSON_BODY", "integer"),
            InputChoice(3, "INP-004", "keyword", "JSON_BODY", "string"),
        ),
        limit=3,
    )


class _FakeAgent:
    """Stands in for a Strands agent: answers, or fails, without a provider."""

    def __init__(self, answer=None, *, boom: Exception | None = None) -> None:
        self.answer = answer
        self.boom = boom
        self.calls = 0

    def structured_output(self, output_model, prompt):
        self.calls += 1
        if self.boom is not None:
            raise self.boom
        return self.answer


# --------------------------------------------------------------------------- #
# Endpoint labels: hashes said out loud
# --------------------------------------------------------------------------- #


def test_labels_turn_endpoint_ids_into_paths():
    from test_analysis.fixtures import make_endpoint

    from websecuritycheck.hypothesis.labels import describe, endpoint_labels, label_for

    endpoint = make_endpoint(origin="https://shop.lab.local", path="/api/search", method="POST")
    labels = endpoint_labels([endpoint])

    assert labels[endpoint.endpoint_id] == "POST /api/search"
    assert label_for(endpoint.endpoint_id, labels) == "POST /api/search"
    # The id stays beside the path: a reader needs one, anyone cross-checking
    # Module 2 or Module 3 needs the other.
    assert describe(endpoint.endpoint_id, labels) == (
        f"POST /api/search ({endpoint.endpoint_id})"
    )


def test_labels_degrade_to_the_id_when_the_request_is_missing():
    from websecuritycheck.hypothesis.labels import describe, label_for

    # The envelope alone has no paths in it, and that must not break anything.
    assert label_for("a" * 12, None) == "a" * 12
    assert describe("a" * 12, {}) == "a" * 12
    assert label_for(None, {"x": "y"}) == "(no endpoint)"


def test_selector_is_told_the_path_not_just_the_hash():
    from websecuritycheck.hypothesis.llm import prompt_for

    output = Module2Output.model_validate(_minimal_output())
    record = _record(
        kind=CorrelationKind.ENDPOINT_SINK,
        status=CorrelationStatus.PARTIAL,
        confidence=ConfidenceLevel.LOW,
        input_ref=None,
        sink_relationship=SinkRelationship.UNVERIFIED_STATIC_SINK,
    )
    seen: list[SelectionRequest] = []

    generate_hypotheses(
        output,
        [record],
        select_inputs=lambda request: (seen.append(request), [0])[1],
        endpoint_labels={"a" * 12: "GET /api/users"},
    )

    assert seen[0].endpoint_label == "GET /api/users"
    # The path is real signal for the model, so it has to reach the prompt.
    assert "GET /api/users" in prompt_for(seen[0])


# --------------------------------------------------------------------------- #
# Code slices: reading the handler instead of guessing from names
# --------------------------------------------------------------------------- #


def test_handler_ranges_come_from_route_binding_evidence(captured):
    from websecuritycheck.hypothesis.slices import handler_ranges

    output, correlation = captured
    ranges = handler_ranges(output)

    for record in correlation.records:
        span = ranges[record.endpoint_id]
        sink = next(s for s in output.sink_candidates if s.sink_id == record.sink_ref)
        # The binding is only useful if the sink really sits inside it.
        assert span.file_path == sink.file_path
        assert span.start_line <= sink.start_line <= span.end_line


def test_slice_quotes_the_handler_and_marks_the_sink(tmp_path):
    from websecuritycheck.hypothesis.slices import CodeRange, SourceSlicer

    source = tmp_path / "app.js"
    source.write_text("\n".join(f"line {n}" for n in range(1, 21)), encoding="utf-8")

    text = SourceSlicer(tmp_path).read(CodeRange("app.js", 3, 6), highlight=[5])

    assert "    3 | line 3" in text
    assert ">    5 | line 5" in text  # the sink line carries the marker
    assert "line 7" not in text


def test_slice_windows_a_long_handler_around_the_sink(tmp_path):
    from websecuritycheck.hypothesis.slices import CodeRange, SourceSlicer

    source = tmp_path / "app.js"
    source.write_text("\n".join(f"line {n}" for n in range(1, 301)), encoding="utf-8")

    text = SourceSlicer(tmp_path, max_lines=20).read(CodeRange("app.js", 1, 300), highlight=[150])

    # One very long function must not crowd out the rest of the prompt, and
    # the part worth keeping is what surrounds the sink.
    assert "line 150" in text
    assert "line 1\n" not in text
    assert "(lines" in text, "a trimmed window says so rather than looking complete"


def test_slicer_refuses_to_read_outside_the_source_root(tmp_path):
    from websecuritycheck.hypothesis.slices import CodeRange, SourceSlicer

    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("not yours", encoding="utf-8")

    slicer = SourceSlicer(root)
    assert slicer.read(CodeRange("../secret.txt", 1, 1)) == ""
    assert any("outside the approved source root" in item for item in slicer.errors)


def test_missing_source_is_reported_not_raised(tmp_path):
    from websecuritycheck.hypothesis.slices import CodeRange, SourceSlicer

    slicer = SourceSlicer(tmp_path)
    assert slicer.read(CodeRange("nope.js", 1, 5)) == ""
    assert slicer.errors, "an unreadable file is a note, never a crash"


def test_slice_reaches_the_prompt_framed_as_untrusted():
    from websecuritycheck.hypothesis.llm import prompt_for

    output = Module2Output.model_validate(_minimal_output())
    record = _record(
        kind=CorrelationKind.ENDPOINT_SINK,
        status=CorrelationStatus.PARTIAL,
        confidence=ConfidenceLevel.LOW,
        input_ref=None,
        sink_relationship=SinkRelationship.UNVERIFIED_STATIC_SINK,
    )
    seen: list[SelectionRequest] = []

    generate_hypotheses(
        output,
        [record],
        select_inputs=lambda request: (seen.append(request), [0])[1],
        code_slices={"a" * 12: ">   42 | db.query(sql)"},
    )

    text = prompt_for(seen[0])
    assert ">   42 | db.query(sql)" in text
    assert "untrusted" in text
    # With the source present the question becomes one of fact, so the model
    # is asked to cite lines rather than rank names.
    assert "line where its value enters" in text


def test_generation_reads_no_files_without_slices():
    """Hypothesis generation still runs from one JSON file and nothing else."""
    output = Module2Output.model_validate(_minimal_output())
    seen: list[SelectionRequest] = []

    generate_hypotheses(
        output,
        [
            _record(
                kind=CorrelationKind.ENDPOINT_SINK,
                status=CorrelationStatus.PARTIAL,
                confidence=ConfidenceLevel.LOW,
                input_ref=None,
                sink_relationship=SinkRelationship.UNVERIFIED_STATIC_SINK,
            )
        ],
        select_inputs=lambda request: (seen.append(request), [0])[1],
    )

    assert all(request.code_slice == "" for request in seen)
