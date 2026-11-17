"""The checks nothing else performs.

Three layers already stand between a generated hypothesis and Module 3. The
schema rejects a malformed one at parse time, and it is strict enough to
enforce that a proposal matches its parent field for field.
`validate_module2_handoff` then resolves every evidence and observation
reference against an authoritative index built from Module 1, failing closed.

Neither can check the rules below, for one structural reason: both see
`Module2Output`, and `Module2Output` does not contain the correlation
records. Without the relation a hypothesis came from there is nothing to
compare its confidence against - so "confidence only ever moves down", the
handoff's fourth principle, is unenforced by the pipeline. The same gap
leaves `input_ref` and `sink_ref` unresolved: the handoff validator checks
the evidence refs and the endpoint, but never that the input and sink the
hypothesis names actually exist, or that the input belongs to the endpoint.

This module closes that gap deterministically. It is the layer that matters
most once a model is generating the judgement calls, because it is the only
one that can catch a confident-sounding promotion.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..analysis.correlation import CorrelationRecord, CorrelationStatus
from ..domain.analysis_models import (
    ConfidenceLevel,
    Hypothesis,
    Module2Output,
    SinkRelationship,
)

_CONFIDENCE_ORDER = {ConfidenceLevel.LOW: 0, ConfidenceLevel.MEDIUM: 1, ConfidenceLevel.HIGH: 2}


class HypothesisGuardError(ValueError):
    """Raised by `enforce` when a hypothesis breaks a rule that must not bend."""

    def __init__(self, violations: Sequence[str]) -> None:
        self.violations = list(violations)
        joined = "; ".join(self.violations)
        super().__init__(f"{len(self.violations)} hypothesis violation(s): {joined}")


def check_hypotheses(
    hypotheses: Sequence[Hypothesis],
    output: Module2Output,
    records: Sequence[CorrelationRecord],
    provenance: Mapping[str, str],
) -> list[str]:
    """Return one message per violation, empty when everything holds.

    Returning rather than raising is what makes this usable as the validator
    half of a generate-and-retry loop: the messages are written to be handed
    straight back to whatever produced the hypotheses.
    """
    violations: list[str] = []
    inputs = {item.input_id: item for item in output.inputs}
    sinks = {item.sink_id: item for item in output.sink_candidates}
    by_correlation = {record.correlation_id: record for record in records}

    seen_hypotheses: set[str] = set()
    seen_proposals: set[str] = set()

    for hypothesis in hypotheses:
        name = hypothesis.hypothesis_id
        if name in seen_hypotheses:
            violations.append(f"{name}: duplicate hypothesis_id")
        seen_hypotheses.add(name)
        for proposal in hypothesis.validation_proposals:
            if proposal.proposal_id in seen_proposals:
                violations.append(f"{name}: duplicate proposal_id {proposal.proposal_id}")
            seen_proposals.add(proposal.proposal_id)

        violations.extend(_check_refs_exist(hypothesis, inputs, sinks))

        record = by_correlation.get(provenance.get(name, ""))
        if record is None:
            violations.append(
                f"{name}: not traceable to a correlation record, so its confidence "
                "and references cannot be verified"
            )
            continue
        violations.extend(_check_confidence(hypothesis, record))
        violations.extend(_check_support(hypothesis, record))

    return violations


def enforce(
    hypotheses: Sequence[Hypothesis],
    output: Module2Output,
    records: Sequence[CorrelationRecord],
    provenance: Mapping[str, str],
) -> None:
    """`check_hypotheses`, but fail closed. Use before handing to Module 3."""
    violations = check_hypotheses(hypotheses, output, records, provenance)
    if violations:
        raise HypothesisGuardError(violations)


def _check_refs_exist(
    hypothesis: Hypothesis,
    inputs: Mapping[str, object],
    sinks: Mapping[str, object],
) -> list[str]:
    """The input and sink must exist, and the input must be on the endpoint.

    An id with the right shape is not an id that resolves. `INP-999` passes
    the schema's pattern and passes the handoff validator, which never looks
    at `input_ref` - it would reach Module 3 as a target that does not exist.
    """
    violations: list[str] = []
    name = hypothesis.hypothesis_id

    if hypothesis.input_ref is not None:
        candidate = inputs.get(hypothesis.input_ref)
        if candidate is None:
            violations.append(
                f"{name}: input_ref {hypothesis.input_ref} is not an InputCandidate "
                "in this output"
            )
        elif (
            hypothesis.target_endpoint_id is not None
            and getattr(candidate, "endpoint_id", None) != hypothesis.target_endpoint_id
        ):
            violations.append(
                f"{name}: input {hypothesis.input_ref} belongs to endpoint "
                f"{getattr(candidate, 'endpoint_id', None)}, not to the hypothesis "
                f"endpoint {hypothesis.target_endpoint_id}"
            )

    if hypothesis.sink_ref is not None:
        sink = sinks.get(hypothesis.sink_ref)
        if sink is None:
            violations.append(
                f"{name}: sink_ref {hypothesis.sink_ref} is not a SinkCandidate "
                "in this output"
            )
        elif (
            hypothesis.sink_relationship == SinkRelationship.STATIC_TAINT_FLOW_FOUND
            and not getattr(sink, "has_static_taint_flow", False)
        ):
            # Claiming a traced flow over a sink that was only pattern-matched
            # is the difference between "proven" and "suspected".
            violations.append(
                f"{name}: claims STATIC_TAINT_FLOW_FOUND but sink "
                f"{hypothesis.sink_ref} has no static taint flow"
            )

    return violations


def _check_confidence(hypothesis: Hypothesis, record: CorrelationRecord) -> list[str]:
    """Confidence may be kept or lowered against the relation, never raised."""
    violations: list[str] = []
    name = hypothesis.hypothesis_id
    if _rank(hypothesis.confidence) > _rank(record.confidence):
        violations.append(
            f"{name}: confidence {_label(hypothesis.confidence)} is above "
            f"{_label(record.confidence)} on relation {record.correlation_id}"
        )
    if (
        _status(record) is CorrelationStatus.PARTIAL
        and _rank(hypothesis.confidence) > _rank(ConfidenceLevel.MEDIUM)
    ):
        violations.append(
            f"{name}: relation {record.correlation_id} is PARTIAL, so confidence "
            "cannot be HIGH"
        )
    return violations


def _check_support(hypothesis: Hypothesis, record: CorrelationRecord) -> list[str]:
    """Supporting references must come from the relation, not from elsewhere.

    A hypothesis may cite fewer references than its relation, never other
    ones: an id borrowed from an unrelated finding resolves against the index
    and still grounds the claim in the wrong thing.
    """
    violations: list[str] = []
    name = hypothesis.hypothesis_id
    allowed_evidence = {*record.existence_evidence_refs, *record.relation_evidence_refs}
    allowed_observations = {
        *record.existence_observation_refs,
        *record.relation_observation_refs,
    }

    stray_evidence = sorted(set(hypothesis.supporting_evidence_refs) - allowed_evidence)
    if stray_evidence:
        violations.append(
            f"{name}: evidence {', '.join(stray_evidence)} is not referenced by "
            f"relation {record.correlation_id}"
        )
    stray_observations = sorted(
        set(hypothesis.supporting_observation_refs) - allowed_observations
    )
    if stray_observations:
        violations.append(
            f"{name}: observations {', '.join(stray_observations)} are not referenced "
            f"by relation {record.correlation_id}"
        )
    return violations


def _rank(level: ConfidenceLevel) -> int:
    return _CONFIDENCE_ORDER[level]


def _label(level: ConfidenceLevel) -> str:
    return level.value if hasattr(level, "value") else str(level)


def _status(record: CorrelationRecord) -> CorrelationStatus:
    status = record.status
    return status if isinstance(status, CorrelationStatus) else CorrelationStatus(str(status))
