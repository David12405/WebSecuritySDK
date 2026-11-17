"""Turn Module 2 correlation records into hypotheses, deterministically.

Module 2 stops at "these two clues are related". This turns each relation
into a testable statement - "parameter `id` of this endpoint may be SQL
injectable, because the handler contains a raw SQL sink" - plus a proposal
saying what capability would validate it.

The design rule here is the whole point of the module: **code owns every
field that carries an identifier, and the model never emits one.** IDs are
allocated here, refs are copied from the source record, and confidence is
capped against it. The one genuinely uncertain decision - which parameter of
an endpoint flows into a sink, when the static analysis could not say - is
delegated to an `InputSelector`, and even that selector answers with
*positions in a list this module hands it*, never with an `INP-` string. A
selector cannot invent a reference that does not exist; the class of error is
removed by construction rather than caught afterwards.

`heuristic_selector` is the default and needs no model. An LLM-backed
selector is a drop-in replacement, and because the deterministic one already
works, the model has a baseline it has to beat.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field

from ..analysis.correlation import CorrelationKind, CorrelationRecord, CorrelationStatus
from ..domain.analysis_models import (
    ConfidenceLevel,
    ExpectedSignal,
    Hypothesis,
    InputCandidate,
    Module2Output,
    SinkRelationship,
    ValidationCapability,
    ValidationCapabilityRequirement,
    VulnerabilityCategory,
)
from .labels import describe, label_for

# Fixed by the handoff: a category implies the capability that validates it.
# Module 3 picks the tool; this only names the capability.
CAPABILITY_FOR: dict[VulnerabilityCategory, ValidationCapability] = {
    VulnerabilityCategory.SQL_INJECTION: ValidationCapability.SQLI_DETECTION,
    VulnerabilityCategory.OS_COMMAND_INJECTION: ValidationCapability.CMDI_DETECTION,
    VulnerabilityCategory.NOSQL_INJECTION: ValidationCapability.NOSQLI_DETECTION,
    VulnerabilityCategory.SSTI: ValidationCapability.SSTI_DETECTION,
    VulnerabilityCategory.LDAP_XPATH_ORM_INJECTION: (
        ValidationCapability.LDAP_XPATH_ORM_DETECTION
    ),
    VulnerabilityCategory.XSS: ValidationCapability.XSS_DETECTION,
    VulnerabilityCategory.PATH_TRAVERSAL: ValidationCapability.PATH_TRAVERSAL_DETECTION,
    VulnerabilityCategory.KNOWN_CVE: ValidationCapability.CVE_SAFE_CHECK,
}

# What Module 3 would expect to see if the hypothesis holds.
SIGNALS_FOR: dict[VulnerabilityCategory, tuple[ExpectedSignal, ...]] = {
    VulnerabilityCategory.SQL_INJECTION: (
        ExpectedSignal.SQL_SYNTAX_ERROR,
        ExpectedSignal.BOOLEAN_RESPONSE_DIFF,
        ExpectedSignal.TIMING_DIFF,
    ),
    VulnerabilityCategory.OS_COMMAND_INJECTION: (
        ExpectedSignal.COMMAND_OUTPUT_REFLECTED,
        ExpectedSignal.TIMING_DIFF,
    ),
    VulnerabilityCategory.NOSQL_INJECTION: (
        ExpectedSignal.NOSQL_OPERATOR_DIFF,
        ExpectedSignal.BOOLEAN_RESPONSE_DIFF,
    ),
    VulnerabilityCategory.SSTI: (ExpectedSignal.TEMPLATE_EXPR_EVALUATED,),
    VulnerabilityCategory.LDAP_XPATH_ORM_INJECTION: (ExpectedSignal.BOOLEAN_RESPONSE_DIFF,),
    VulnerabilityCategory.XSS: (
        ExpectedSignal.UNENCODED_REFLECTION,
        ExpectedSignal.DOM_EXECUTION_CONFIRMED,
    ),
    VulnerabilityCategory.PATH_TRAVERSAL: (ExpectedSignal.PATH_CONTENT_DISCLOSURE,),
    VulnerabilityCategory.KNOWN_CVE: (ExpectedSignal.SAFE_CVE_CHECK_MATCH,),
}

#: Categories whose successful exploitation is typically the most severe,
#: used only to break ties in `priority`.
HEAVY_CATEGORIES = frozenset(
    {VulnerabilityCategory.OS_COMMAND_INJECTION, VulnerabilityCategory.SSTI}
)

#: 10 is the most urgent. Fixed by the handoff's worked example, where a
#: HIGH-confidence verified taint flow is priority 9.
MAX_PRIORITY = 10
MIN_PRIORITY = 1

_CONFIDENCE_ORDER = {ConfidenceLevel.LOW: 0, ConfidenceLevel.MEDIUM: 1, ConfidenceLevel.HIGH: 2}

#: Parameter names that commonly reach an interpreter. Only ever used to rank
#: candidates the static analysis already tied to the same handler - never to
#: claim a parameter is vulnerable.
_INJECTABLE_HINTS = frozenset(
    {
        "category",
        "cmd",
        "command",
        "email",
        "exec",
        "expression",
        "field",
        "filter",
        "id",
        "key",
        "keyword",
        "name",
        "order",
        "path",
        "q",
        "query",
        "search",
        "sort",
        "sql",
        "template",
        "term",
        "user",
        "username",
        "where",
    }
)

_NUMERIC_TYPES = frozenset({"boolean", "float", "int", "integer", "number"})


@dataclass(frozen=True)
class InputChoice:
    """One candidate parameter, offered to a selector by position."""

    index: int
    input_id: str
    parameter_name: str
    location: str
    data_type: str | None


@dataclass(frozen=True)
class SelectionRequest:
    """Everything a selector may see when choosing which parameters to flag."""

    endpoint_id: str
    sink_id: str
    sink_kind: str
    vulnerability_category: str
    rationale: str
    candidates: tuple[InputChoice, ...]
    limit: int
    #: `"POST /api/search"` when the Module 1 endpoints are available, else
    #: the id. The path is evidence in its own right - a parameter named
    #: `keyword` on `/api/search` is a far better candidate than the same
    #: name on `/healthz` - so a selector that can read it decides better.
    endpoint_label: str = ""
    #: The handler's source, line-numbered with the sink marked, when a
    #: caller supplied it. This turns the question from "which name sounds
    #: injectable" into "which value does this code put in the query", and
    #: it is the difference between guessing and reading. Empty by default:
    #: nothing in this package reads the filesystem on its own.
    code_slice: str = ""


#: Answers with positions in `SelectionRequest.candidates`, never with ids.
InputSelector = Callable[[SelectionRequest], Sequence[int]]


@dataclass
class GenerationResult:
    """Hypotheses plus a line for every relation deliberately not turned into one."""

    hypotheses: list[Hypothesis] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    #: hypothesis_id -> correlation_id, so the guard can re-check each one
    #: against the record it came from.
    provenance: dict[str, str] = field(default_factory=dict)


def heuristic_selector(request: SelectionRequest) -> list[int]:
    """Rank candidates by name and type, with no model involved.

    Deliberately simple, and deliberately the baseline an LLM selector has to
    beat. Two rules do most of the work: a parameter that is only a container
    for others (`filters` next to `filters.category`) is not itself the value
    that reaches the sink, and a numeric parameter is a weaker candidate than
    a string one for a query built by concatenation.
    """
    names = {choice.parameter_name for choice in request.candidates}
    scored: list[tuple[int, int, int]] = []  # (-score, index, index)
    for choice in request.candidates:
        if any(other.startswith(f"{choice.parameter_name}.") for other in names):
            continue  # a container, not a leaf value
        leaf = choice.parameter_name.rsplit(".", 1)[-1].casefold()
        score = 1
        if leaf in _INJECTABLE_HINTS:
            score += 3
        if (choice.data_type or "").casefold() in _NUMERIC_TYPES:
            score -= 2
        if score <= 0:
            continue
        scored.append((-score, choice.index, choice.index))
    scored.sort()
    return [index for _score, _tie, index in scored[: request.limit]]


def generate_hypotheses(
    output: Module2Output,
    records: Sequence[CorrelationRecord],
    *,
    select_inputs: InputSelector = heuristic_selector,
    max_inputs_per_sink: int = 3,
    endpoint_labels: Mapping[str, str] | None = None,
    code_slices: Mapping[str, str] | None = None,
) -> GenerationResult:
    """Build one hypothesis per relation Module 2 verified, and no more.

    A relation Module 2 left without a category, or one whose evidence does
    not survive, becomes a line in `limitations` rather than a quiet omission:
    a reader of the report has to be able to tell "nothing here" from "we did
    not look".
    """
    result = GenerationResult()
    inputs_by_id = {item.input_id: item for item in output.inputs}
    inputs_by_endpoint: dict[str, list[InputCandidate]] = {}
    for item in output.inputs:
        inputs_by_endpoint.setdefault(item.endpoint_id, []).append(item)

    counter = _Counter()
    for record in records:
        result_for = _hypotheses_for_record(
            record,
            inputs_by_id=inputs_by_id,
            inputs_by_endpoint=inputs_by_endpoint,
            select_inputs=select_inputs,
            max_inputs_per_sink=max_inputs_per_sink,
            counter=counter,
            endpoint_labels=endpoint_labels,
            code_slices=code_slices,
        )
        result.hypotheses.extend(result_for.hypotheses)
        result.limitations.extend(result_for.limitations)
        result.provenance.update(result_for.provenance)
    return result


class _Counter:
    """Hands out `HYP-001` / `VCR-001` in order. Ids are the SDK's to assign."""

    def __init__(self) -> None:
        self._hypothesis = 0
        self._proposal = 0

    def hypothesis_id(self) -> str:
        self._hypothesis += 1
        return f"HYP-{self._hypothesis:03d}"

    def proposal_id(self) -> str:
        self._proposal += 1
        return f"VCR-{self._proposal:03d}"


def _hypotheses_for_record(
    record: CorrelationRecord,
    *,
    inputs_by_id: dict[str, InputCandidate],
    inputs_by_endpoint: dict[str, list[InputCandidate]],
    select_inputs: InputSelector,
    max_inputs_per_sink: int,
    counter: _Counter,
    endpoint_labels: Mapping[str, str] | None = None,
    code_slices: Mapping[str, str] | None = None,
) -> GenerationResult:
    out = GenerationResult()
    kind = _kind(record)

    # A sink tied to a CVE strengthens a KNOWN_CVE hypothesis; it is not a
    # separate claim about a separate weakness.
    if kind == CorrelationKind.SINK_CVE:
        return out

    category = record.vulnerability_category
    if category is None:
        out.limitations.append(
            f"{record.correlation_id}: no vulnerability_category on the relation, "
            "so no hypothesis was generated"
        )
        return out

    evidence_refs, observation_refs = _support(record)
    if not evidence_refs and not observation_refs:
        out.limitations.append(
            f"{record.correlation_id}: relation carries no evidence or observation "
            "references, so no hypothesis could be grounded"
        )
        return out

    if kind in {CorrelationKind.CVE_TECHNOLOGY, CorrelationKind.INPUT_SINK_CVE_CHAIN}:
        cve = _cve_hypothesis(record, evidence_refs, observation_refs, counter)
        if cve is not None:
            out.hypotheses.append(cve)
            out.provenance[cve.hypothesis_id] = record.correlation_id
        elif kind == CorrelationKind.CVE_TECHNOLOGY:
            out.limitations.append(
                f"{record.correlation_id}: CVE relation is missing cve_candidate_ref "
                "or target_technology, so no KNOWN_CVE hypothesis was generated"
            )

    if kind == CorrelationKind.CVE_TECHNOLOGY:
        return out

    # Everything below is an injection-shaped hypothesis, which the schema
    # requires to name both an endpoint and an input.
    endpoint_id = record.endpoint_id
    if endpoint_id is None:
        out.limitations.append(
            f"{record.correlation_id}: relation names no endpoint, "
            f"so no {category.value} hypothesis was generated"
        )
        return out

    chosen = _choose_inputs(
        record,
        category=category,
        endpoint_id=endpoint_id,
        inputs_by_id=inputs_by_id,
        inputs_by_endpoint=inputs_by_endpoint,
        select_inputs=select_inputs,
        max_inputs_per_sink=max_inputs_per_sink,
        endpoint_labels=endpoint_labels,
        code_slices=code_slices,
    )
    if not chosen:
        out.limitations.append(
            f"{record.correlation_id}: no input of endpoint "
            f"{describe(endpoint_id, endpoint_labels)} could be tied to sink "
            f"{record.sink_ref}, so no {category.value} hypothesis was generated"
        )
        return out

    for rank, candidate in enumerate(chosen):
        hypothesis = _injection_hypothesis(
            record,
            category=category,
            endpoint_id=endpoint_id,
            input_id=candidate.input_id,
            evidence_refs=evidence_refs,
            observation_refs=observation_refs,
            counter=counter,
            inputs_by_id=inputs_by_id,
            rank=rank,
        )
        out.hypotheses.append(hypothesis)
        out.provenance[hypothesis.hypothesis_id] = record.correlation_id
    return out


def _choose_inputs(
    record: CorrelationRecord,
    *,
    category: VulnerabilityCategory,
    endpoint_id: str,
    inputs_by_id: dict[str, InputCandidate],
    inputs_by_endpoint: dict[str, list[InputCandidate]],
    select_inputs: InputSelector,
    max_inputs_per_sink: int,
    endpoint_labels: Mapping[str, str] | None = None,
    code_slices: Mapping[str, str] | None = None,
) -> list[InputCandidate]:
    """The input Module 2 proved, or the ones a selector proposes.

    When the static analysis traced the flow it already named the parameter -
    there is nothing to decide, and asking anyone to choose would only
    introduce a way to get it wrong.
    """
    if record.input_ref is not None:
        proven = inputs_by_id.get(record.input_ref)
        return [proven] if proven is not None else []

    candidates = _leaf_inputs(inputs_by_endpoint.get(endpoint_id, []))
    if not candidates:
        return []

    request = SelectionRequest(
        endpoint_id=endpoint_id,
        endpoint_label=label_for(endpoint_id, endpoint_labels),
        code_slice=(code_slices or {}).get(endpoint_id, ""),
        sink_id=record.sink_ref or "",
        sink_kind=_sink_kind_hint(category),
        vulnerability_category=category.value,
        rationale=record.rationale or "",
        candidates=tuple(
            InputChoice(
                index=position,
                input_id=item.input_id,
                parameter_name=item.parameter_name,
                location=_enum_value(item.location),
                data_type=item.data_type,
            )
            for position, item in enumerate(candidates)
        ),
        limit=max_inputs_per_sink,
    )
    picks = select_inputs(request)

    # A selector answers with positions. Anything outside the list it was
    # given is dropped rather than trusted - the contract is the defence.
    seen: set[int] = set()
    chosen: list[InputCandidate] = []
    for position in picks:
        if not isinstance(position, int) or position in seen:
            continue
        if 0 <= position < len(candidates):
            seen.add(position)
            chosen.append(candidates[position])
        if len(chosen) >= max_inputs_per_sink:
            break
    return chosen


def _leaf_inputs(candidates: list[InputCandidate]) -> list[InputCandidate]:
    """Drop parameters that only hold other parameters.

    When Module 1 saw a JSON body it recorded both the object and its fields,
    so `filters` arrives alongside `filters.category`. The value a handler
    interpolates is the leaf; the object is the envelope it came in. This is
    a fact about the names, not a judgement, so it is settled here rather
    than offered to a selector - every selector would otherwise have to get
    the same structural rule right, and a model asked to rank `filters`
    against `filters.category` will sometimes keep both.
    """
    names = {item.parameter_name for item in candidates}
    return [
        item
        for item in candidates
        if not any(other.startswith(f"{item.parameter_name}.") for other in names)
    ]


def _injection_hypothesis(
    record: CorrelationRecord,
    *,
    category: VulnerabilityCategory,
    endpoint_id: str,
    input_id: str,
    evidence_refs: list[str],
    observation_refs: list[str],
    counter: _Counter,
    inputs_by_id: dict[str, InputCandidate],
    rank: int = 0,
) -> Hypothesis:
    hypothesis_id = counter.hypothesis_id()
    sink_ref = record.sink_ref
    relationship = _relationship(record, sink_ref)
    confidence = _confidence(record)
    parameter = inputs_by_id[input_id].parameter_name if input_id in inputs_by_id else input_id

    hypothesis = Hypothesis(
        hypothesis_id=hypothesis_id,
        vulnerability_category=category,
        target_endpoint_id=endpoint_id,
        input_ref=input_id,
        sink_ref=sink_ref,
        sink_relationship=relationship,
        confidence=confidence,
        rationale=_rationale(record, category, parameter, relationship),
        missing_evidence=_missing(record, relationship),
        supporting_evidence_refs=evidence_refs,
        supporting_observation_refs=observation_refs,
    )
    return hypothesis.model_copy(
        update={
            "validation_proposals": [
                _proposal(
                    hypothesis, record, counter, evidence_refs, observation_refs, rank=rank
                )
            ]
        }
    )


def _cve_hypothesis(
    record: CorrelationRecord,
    evidence_refs: list[str],
    observation_refs: list[str],
    counter: _Counter,
) -> Hypothesis | None:
    if record.cve_candidate_ref is None or record.target_technology is None:
        return None
    hypothesis_id = counter.hypothesis_id()
    technology = record.target_technology
    # `target_endpoint_id` is left unset on purpose: associating a CVE with an
    # endpoint requires evidence shared with that endpoint, and a component
    # finding does not need an endpoint to be actionable.
    hypothesis = Hypothesis(
        hypothesis_id=hypothesis_id,
        vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
        target_technology=technology,
        cve_candidate_ref=record.cve_candidate_ref,
        sink_relationship=SinkRelationship.UNKNOWN,
        confidence=_confidence(record),
        rationale=(
            record.rationale
            or (
                f"{technology.name} {technology.version} matches the affected range of "
                f"{record.cve_candidate_ref}."
            )
        ),
        missing_evidence=_missing(record, SinkRelationship.UNKNOWN),
        supporting_evidence_refs=evidence_refs,
        supporting_observation_refs=observation_refs,
    )
    return hypothesis.model_copy(
        update={
            "validation_proposals": [
                _proposal(hypothesis, record, counter, evidence_refs, observation_refs)
            ]
        }
    )


def _proposal(
    hypothesis: Hypothesis,
    record: CorrelationRecord,
    counter: _Counter,
    evidence_refs: list[str],
    observation_refs: list[str],
    rank: int = 0,
) -> ValidationCapabilityRequirement:
    """Copy the parent's targeting fields rather than restating them.

    Every field here that identifies something is read off the hypothesis, so
    a proposal cannot drift from its parent - the schema rejects that anyway,
    and this makes the rejection unreachable.
    """
    category = hypothesis.vulnerability_category
    return ValidationCapabilityRequirement(
        proposal_id=counter.proposal_id(),
        hypothesis_ref=hypothesis.hypothesis_id,
        vulnerability_category=category,
        suggested_capability=CAPABILITY_FOR[category],
        target_endpoint_id=hypothesis.target_endpoint_id,
        target_technology=hypothesis.target_technology,
        target_input_ref=hypothesis.input_ref,
        cve_candidate_ref=hypothesis.cve_candidate_ref,
        evidence_refs=evidence_refs,
        observation_refs=observation_refs,
        priority=_priority(hypothesis, record, rank),
        expected_signals=list(SIGNALS_FOR[category]),
    )


def _priority(hypothesis: Hypothesis, record: CorrelationRecord, rank: int = 0) -> int:
    """Rank by how much is known, then by how bad it would be.

    Confidence dominates because it summarises the evidence; a traced flow
    and a severe category only break ties. An endpoint never seen at runtime
    is ranked down - validating something that may not be reachable wastes
    Module 3's time.

    `rank` carries over the selector's own ordering when one sink produced
    several candidate parameters. Without it every candidate from the same
    relation scores identically and Module 3 is handed a tie it has no way to
    break, discarding the one judgement that was actually made.
    """
    base = {ConfidenceLevel.HIGH: 8, ConfidenceLevel.MEDIUM: 5, ConfidenceLevel.LOW: 3}[
        hypothesis.confidence
    ]
    if hypothesis.sink_relationship == SinkRelationship.STATIC_TAINT_FLOW_FOUND:
        base += 1
    if hypothesis.vulnerability_category in HEAVY_CATEGORIES:
        base += 1
    if any("ENDPOINT_NOT_RUNTIME_OBSERVED" in cap for cap in record.confidence_caps_applied):
        base -= 1
    base -= rank
    return max(MIN_PRIORITY, min(MAX_PRIORITY, base))


def _confidence(record: CorrelationRecord) -> ConfidenceLevel:
    """Never above the relation's own confidence, and never HIGH on a partial.

    Module 2 already applied its caps; repeating the rule here is what stops a
    later generator - an LLM in particular - from quietly promoting a guess.
    """
    confidence = record.confidence
    ceiling = ConfidenceLevel.HIGH
    if _status(record) is CorrelationStatus.PARTIAL:
        ceiling = ConfidenceLevel.MEDIUM
    if _kind(record) == CorrelationKind.ENDPOINT_SINK:
        # The parameter was chosen, not traced. That is weaker than anything
        # Module 2 verified, whatever it scored the relation.
        ceiling = ConfidenceLevel.LOW
    return min(confidence, ceiling, key=lambda level: _CONFIDENCE_ORDER[level])


def _relationship(record: CorrelationRecord, sink_ref: str | None) -> SinkRelationship:
    if sink_ref is None:
        return SinkRelationship.UNKNOWN
    declared = record.sink_relationship
    if declared is None:
        return SinkRelationship.UNVERIFIED_STATIC_SINK
    if isinstance(declared, SinkRelationship):
        resolved = declared
    else:
        try:
            resolved = SinkRelationship(str(declared))
        except ValueError:
            return SinkRelationship.UNVERIFIED_STATIC_SINK
    # A sink named without a traced flow is exactly UNVERIFIED_STATIC_SINK;
    # the schema refuses UNKNOWN once a sink is attached.
    if resolved == SinkRelationship.UNKNOWN:
        return SinkRelationship.UNVERIFIED_STATIC_SINK
    return resolved


def _support(record: CorrelationRecord) -> tuple[list[str], list[str]]:
    """The relation's own references, deduplicated and ordered.

    Both the refs proving the parts exist and the refs proving they are
    related: a reader following the hypothesis back needs the whole chain.
    """
    evidence = sorted(
        {*record.existence_evidence_refs, *record.relation_evidence_refs}
    )
    observations = sorted(
        {*record.existence_observation_refs, *record.relation_observation_refs}
    )
    return evidence, observations


def _missing(record: CorrelationRecord, relationship: SinkRelationship) -> list[str]:
    missing = [*record.missing_links, *record.unverified_preconditions]
    if relationship == SinkRelationship.UNVERIFIED_STATIC_SINK:
        missing.append(
            "The parameter was selected from the endpoint's inputs, not traced into "
            "the sink; a static dataflow trace would confirm or rule it out."
        )
    return missing


def _rationale(
    record: CorrelationRecord,
    category: VulnerabilityCategory,
    parameter: str,
    relationship: SinkRelationship,
) -> str:
    """Start from Module 2's own sentence; say plainly what is still unproven."""
    base = record.rationale or (
        f"Parameter {parameter!r} reaches a {category.value} sink in the handler."
    )
    if relationship == SinkRelationship.UNVERIFIED_STATIC_SINK:
        # Module 2's note is a fragment as often as a sentence; joining two
        # of them without a stop reads as one run-on claim.
        base = base.rstrip()
        if base and base[-1] not in ".!?":
            base = f"{base}."
        return (
            f"{base} The handler contains the sink, but no dataflow trace ties "
            f"{parameter!r} to it, so this parameter is a candidate rather than a "
            "traced source."
        )
    return base


def _kind(record: CorrelationRecord) -> CorrelationKind:
    kind = record.kind
    return kind if isinstance(kind, CorrelationKind) else CorrelationKind(str(kind))


def _status(record: CorrelationRecord) -> CorrelationStatus:
    status = record.status
    return status if isinstance(status, CorrelationStatus) else CorrelationStatus(str(status))


def _enum_value(value: object) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _sink_kind_hint(category: VulnerabilityCategory) -> str:
    return category.value
