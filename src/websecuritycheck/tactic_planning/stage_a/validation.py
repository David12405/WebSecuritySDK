"""Deterministic admission gates for an authored tactic.

Admission is automatic but fail-closed: a tactic becomes active only when every
gate passes. `admit_tactic` returns one message per violation (empty = clean),
so it doubles as the feedback handed back to the authoring model on a retry. No
gate asks a model anything; code decides.

Parsing and JSON-shape gates (1-2 in the design) are already enforced by
constructing a `TacticDocument`, so the function starts at the semantic gates
(identity, provenance, capability, context, control-flow, safety, confirmation).
"""

from __future__ import annotations

from ..contracts import (
    CAPABILITY_CONTRACTS,
    SQLiSafetyPolicy,
    SQLiTechnique,
)
from .models import (
    CANONICAL_TACTIC_ID,
    CANONICAL_TACTIC_NAME,
    TACTIC_SCHEMA_VERSION,
    TacticDocument,
)
from .wstg import WstgSnapshot

#: The versioned WSTG reference an admitted SQLi tactic must cite.
REQUIRED_WSTG_REFERENCE = "WSTG-v42-INPV-05"

TERMINAL_OUTCOMES = frozenset(
    {"CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE", "ERROR", "UNSUPPORTED", "POLICY_BLOCKED"}
)

#: Module 1 / Module 2 contracts a tactic's required_context may name.
ALLOWED_CONTEXT_SOURCES = frozenset(
    {
        "M1.EndpointDefinition",
        "M1.ExecutionPolicy",
        "M1.EvidenceArtifactRecord",
        "M1.AssessmentConfig.auth_references",
        "M1.TargetModel",
        "M2.InputCandidate",
        "M2.SinkCandidate",
        "M2.Hypothesis",
        "M2.ValidationCapabilityRequirement",
    }
)

REQUIRED_CAPABILITIES = ("HTTP_REQUEST", "SQLI_DETECTION")


def admit_tactic(
    document: TacticDocument,
    *,
    snapshot: WstgSnapshot,
    safety_policy: SQLiSafetyPolicy,
) -> list[str]:
    """Run every semantic admission gate; return violations in gate order."""
    violations: list[str] = []
    violations.extend(_gate_identity(document))
    violations.extend(_gate_wstg_provenance(document, snapshot))
    violations.extend(_gate_capabilities(document))
    violations.extend(_gate_context(document))
    violations.extend(_gate_control_flow(document))
    violations.extend(_gate_safety(document, safety_policy))
    violations.extend(_gate_confirmation(document))
    return violations


def _gate_identity(doc: TacticDocument) -> list[str]:
    out: list[str] = []
    if doc.tactic_id != CANONICAL_TACTIC_ID:
        out.append(f"identity: tactic_id must be {CANONICAL_TACTIC_ID}, got {doc.tactic_id}")
    if doc.name != CANONICAL_TACTIC_NAME:
        out.append(f"identity: name must be {CANONICAL_TACTIC_NAME}, got {doc.name}")
    if doc.schema_version != TACTIC_SCHEMA_VERSION:
        out.append(f"identity: schema_version must be {TACTIC_SCHEMA_VERSION}")
    if doc.scope.vulnerability != "SQL_INJECTION":
        out.append(
            f"identity: scope.vulnerability must be SQL_INJECTION, got {doc.scope.vulnerability}"
        )
    return out


def _gate_wstg_provenance(doc: TacticDocument, snapshot: WstgSnapshot) -> list[str]:
    out: list[str] = []
    if REQUIRED_WSTG_REFERENCE not in doc.references:
        out.append(
            f"wstg: references must include {REQUIRED_WSTG_REFERENCE} "
            f"(the preserved snapshot), got {doc.references}"
        )
    if snapshot.wstg_version not in REQUIRED_WSTG_REFERENCE and snapshot.wstg_version != "v42":
        out.append(f"wstg: snapshot version {snapshot.wstg_version} is not the configured v42")
    return out


def _gate_capabilities(doc: TacticDocument) -> list[str]:
    out: list[str] = []
    declared = {cap.id for cap in doc.capabilities}
    for cap in doc.capabilities:
        if cap.id not in CAPABILITY_CONTRACTS:
            out.append(f"capability: {cap.id} is not in the MVP capability registry")
    for required in REQUIRED_CAPABILITIES:
        if required not in declared:
            out.append(f"capability: required capability {required} is not declared")
    for step in doc.steps:
        rec = step.recommended_capability
        if rec is not None and rec not in declared:
            out.append(
                f"capability: step {step.id} recommends {rec}, which the tactic does not declare"
            )
    return out


def _gate_context(doc: TacticDocument) -> list[str]:
    out: list[str] = []
    for ctx in doc.required_context:
        if ctx.source not in ALLOWED_CONTEXT_SOURCES:
            out.append(
                f"context: required_context {ctx.name} source {ctx.source!r} "
                "does not resolve to a known Module 1/Module 2 contract"
            )
    return out


def _gate_control_flow(doc: TacticDocument) -> list[str]:
    out: list[str] = []
    step_ids = [step.id for step in doc.steps]
    id_set = set(step_ids)
    if len(step_ids) != len(id_set):
        out.append("control-flow: step ids are not unique")

    reaches_terminal = False
    for step in doc.steps:
        for option in step.next_options:
            action = option.action
            if action in TERMINAL_OUTCOMES:
                reaches_terminal = True
            elif action not in id_set:
                out.append(
                    f"control-flow: step {step.id} action {action!r} is neither a step "
                    "id nor a terminal outcome"
                )
    if not reaches_terminal:
        out.append("control-flow: no action reaches a terminal outcome")

    # Reachability from the first step (the entry point by convention).
    if doc.steps:
        reachable: set[str] = set()
        frontier = [doc.steps[0].id]
        by_id = {step.id: step for step in doc.steps}
        while frontier:
            current = frontier.pop()
            if current in reachable:
                continue
            reachable.add(current)
            step = by_id.get(current)
            if step is None:
                continue
            for option in step.next_options:
                if option.action in id_set and option.action not in reachable:
                    frontier.append(option.action)
        for step in doc.steps:
            if not step.optional and step.id not in reachable:
                out.append(f"control-flow: mandatory step {step.id} is unreachable")
    return out


def _gate_safety(doc: TacticDocument, policy: SQLiSafetyPolicy) -> list[str]:
    out: list[str] = []
    allowed = {technique.value for technique in policy.allowed_techniques}
    for step in doc.steps:
        suggested = step.suggested_inputs
        if suggested is None:
            continue
        techniques = suggested.techniques or []
        for technique in techniques:
            if technique not in allowed:
                out.append(
                    f"safety: step {step.id} suggests technique {technique!r} "
                    "outside the safety policy"
                )
        has_time = SQLiTechnique.TIME.value in techniques
        ceiling = (
            policy.time_detection_max_requests
            if has_time
            else policy.primary_detection_max_requests
        )
        if suggested.max_requests is not None and suggested.max_requests > ceiling:
            out.append(
                f"safety: step {step.id} max_requests {suggested.max_requests} "
                f"exceeds ceiling {ceiling}"
            )
        if (
            suggested.timeout_seconds is not None
            and suggested.timeout_seconds > policy.detection_timeout_seconds
        ):
            out.append(
                f"safety: step {step.id} timeout_seconds {suggested.timeout_seconds} "
                f"exceeds ceiling {policy.detection_timeout_seconds}"
            )
    # The tactic must not describe prohibited actions in scope limitations.
    joined = " ".join(doc.scope.limitations).lower()
    if "no " not in joined and "exclud" not in joined:
        out.append("safety: scope.limitations must state the excluded/prohibited actions")
    return out


def _gate_confirmation(doc: TacticDocument) -> list[str]:
    out: list[str] = []
    if "CONFIRMED" not in doc.outcomes:
        out.append("confirmation: CONFIRMED must be a declared outcome")
    text = " ".join(doc.confirmation_rules).lower()
    if "verified" not in text and "proof" not in text:
        out.append("confirmation: rules must require verified technique-specific proof")
    if "evidence" not in text:
        out.append("confirmation: rules must require non-empty evidence references")
    if "observation" not in text and "control" not in text:
        out.append("confirmation: rules must require control/test observation references")
    return out
