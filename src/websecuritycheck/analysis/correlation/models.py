"""Data-plane and diagnostic Pydantic models for M2-T05 correlation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    CveCandidateId,
    CweId,
    EvidenceId,
    InputId,
    Module2Output,
    ObservationId,
    SinkId,
    SinkRelationship,
    TechnologyTargetRef,
    VulnerabilityCategory,
)
from websecuritycheck.domain.enums import InputLocation

from ..cve import InjectionScopeStatus, InjectionSubtype
from ..route_binding.models import RouteBindingArtifactRef
from .policy import (
    AccessorResolution,
    CorrelationId,
    CorrelationKind,
    CorrelationStatus,
    FlowTrust,
    IndependenceStatus,
    RuleProvenanceStatus,
)


class RouteHandlerBinding(BaseModel):
    """Internal verified route-to-handler binding derived strictly from trusted artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_id: str
    method: str
    path: str
    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    evidence_ref: EvidenceId
    execution_ref: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    source_tree_sha256: str | None = None
    source_repository_ref: str | None = None


class TaintSourceAccessor(BaseModel):
    """Structured result of parsing a taint source snippet for input parameters."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resolution: AccessorResolution
    locations: frozenset[InputLocation] = frozenset()
    parameter_name: str | None = None
    pattern_id: str | None = None


class InjectionSinkScope(BaseModel):
    """Result of multi-axial verification of a static SinkCandidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sink_id: SinkId
    scope_status: InjectionScopeStatus
    scope_basis: str
    subtype: InjectionSubtype | None = None
    corroborating_cwe_ids: tuple[CweId, ...] = ()
    rule_provenance: RuleProvenanceStatus
    provenance_gaps: tuple[str, ...] = ()
    flow_trust: FlowTrust
    source_revision: str | None = None
    source_tree_sha256: str | None = None
    source_repository_ref: str | None = None
    reason: str


class IndependenceAssessment(BaseModel):
    """Result of evaluating provenance independence across relation evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: IndependenceStatus
    distinct_execution_count: int = Field(ge=0)
    reasons: tuple[str, ...] = ()


class CorrelationRecord(BaseModel):
    """Canonical correlated relationship between security analysis entities."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: CorrelationId
    kind: CorrelationKind
    status: CorrelationStatus
    confidence: ConfidenceLevel
    injection_subtype: InjectionSubtype
    vulnerability_category: VulnerabilityCategory | None = None
    endpoint_id: str | None = None
    input_ref: InputId | None = None
    sink_ref: SinkId | None = None
    sink_relationship: SinkRelationship = SinkRelationship.UNKNOWN
    cve_candidate_ref: CveCandidateId | None = None
    target_technology: TechnologyTargetRef | None = None
    component_refs: tuple[CorrelationId, ...] = ()
    existence_evidence_refs: tuple[EvidenceId, ...] = ()
    existence_observation_refs: tuple[ObservationId, ...] = ()
    relation_evidence_refs: tuple[EvidenceId, ...] = ()
    relation_observation_refs: tuple[ObservationId, ...] = ()
    independent_relation_source_count: int = Field(ge=0)
    independence: IndependenceAssessment
    unverified_preconditions: tuple[str, ...] = ()
    missing_links: tuple[str, ...] = ()
    confidence_caps_applied: tuple[str, ...] = ()
    candidate_input_names_in_handler: tuple[str, ...] = ()
    handler_code_slice: str | None = None
    rationale: str = Field(min_length=10)
    is_confirmed_vulnerability: Literal[False] = False

    @model_validator(mode="after")
    def validate_record_invariants(self) -> CorrelationRecord:
        if self.status == CorrelationStatus.UNRESOLVED:
            raise ValueError("CorrelationRecord cannot have status UNRESOLVED")

        if self.status == CorrelationStatus.PARTIAL and self.confidence == ConfidenceLevel.HIGH:
            raise ValueError("PARTIAL CorrelationRecord cannot have HIGH confidence")

        if (
            self.confidence == ConfidenceLevel.HIGH
            and self.independence.status != IndependenceStatus.INDEPENDENT
        ):
            raise ValueError(
                "HIGH confidence requires IndependenceStatus.INDEPENDENT, got "
                f"{self.independence.status}"
            )

        if not self.relation_evidence_refs and not self.relation_observation_refs:
            raise ValueError(
                f"CorrelationRecord {self.correlation_id} requires at least one relation ref"
            )

        if self.kind == CorrelationKind.INPUT_SINK:
            if self.status != CorrelationStatus.VERIFIED:
                raise ValueError("INPUT_SINK record must have status VERIFIED")
            if not self.endpoint_id or not self.input_ref or not self.sink_ref:
                raise ValueError("INPUT_SINK requires endpoint_id, input_ref, and sink_ref")
            if self.sink_relationship != SinkRelationship.STATIC_TAINT_FLOW_FOUND:
                raise ValueError("INPUT_SINK requires STATIC_TAINT_FLOW_FOUND sink_relationship")
            if self.cve_candidate_ref is not None or self.target_technology is not None:
                raise ValueError("INPUT_SINK must not specify CVE references")

        elif self.kind == CorrelationKind.ENDPOINT_SINK:
            if self.status != CorrelationStatus.PARTIAL:
                raise ValueError("ENDPOINT_SINK record must have status PARTIAL")
            if not self.endpoint_id or not self.sink_ref:
                raise ValueError("ENDPOINT_SINK requires endpoint_id and sink_ref")
            if self.input_ref is not None:
                raise ValueError("ENDPOINT_SINK must not specify input_ref")
            if self.cve_candidate_ref is not None or self.target_technology is not None:
                raise ValueError("ENDPOINT_SINK must not specify CVE references")

        elif self.kind == CorrelationKind.CVE_TECHNOLOGY:
            if not self.cve_candidate_ref or not self.target_technology:
                raise ValueError("CVE_TECHNOLOGY requires cve_candidate_ref and target_technology")
            if (
                self.endpoint_id is not None
                or self.input_ref is not None
                or self.sink_ref is not None
            ):
                raise ValueError("CVE_TECHNOLOGY must not specify endpoint, input, or sink refs")

        elif self.kind == CorrelationKind.SINK_CVE:
            if self.status != CorrelationStatus.PARTIAL:
                raise ValueError("SINK_CVE record must have status PARTIAL")
            if not self.sink_ref or not self.cve_candidate_ref or not self.target_technology:
                raise ValueError(
                    "SINK_CVE requires sink_ref, cve_candidate_ref, and target_technology"
                )
            if self.endpoint_id is not None or self.input_ref is not None:
                raise ValueError("SINK_CVE must not specify endpoint_id or input_ref")
            if not self.component_refs:
                raise ValueError(
                    "SINK_CVE requires component_refs linking the CVE_TECHNOLOGY record"
                )

        elif self.kind == CorrelationKind.INPUT_SINK_CVE_CHAIN:
            if self.status != CorrelationStatus.PARTIAL:
                raise ValueError("INPUT_SINK_CVE_CHAIN must have status PARTIAL")
            if not self.endpoint_id or not self.input_ref or not self.sink_ref:
                raise ValueError("INPUT_SINK_CVE_CHAIN requires endpoint, input, and sink refs")
            if not self.cve_candidate_ref or not self.target_technology:
                raise ValueError(
                    "INPUT_SINK_CVE_CHAIN requires cve_candidate_ref and target_technology"
                )
            if len(self.component_refs) < 2:
                raise ValueError(
                    "INPUT_SINK_CVE_CHAIN requires component_refs for INPUT_SINK and SINK_CVE"
                )

        return self


class CorrelationDiagnostic(BaseModel):
    """Structured deterministic record of skipped, excluded, or unresolved correlations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_ref: str
    stage: Literal[
        "grounding",
        "scope",
        "route_binding",
        "input_sink",
        "cve_technology",
        "sink_cve",
        "envelope",
    ]
    outcome: Literal["EXCLUDED", "UNRESOLVED", "SKIPPED", "CONFLICT"]
    code: str
    reason: str


class CorrelationCoverage(BaseModel):
    """Clear declaration of enabled correlation capabilities and blocking dependencies."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_sink_enabled: bool
    sink_cve_enabled: bool
    chain_enabled: bool
    cve_technology_enabled: bool
    blocking_dependencies: tuple[str, ...]


class CorrelationResult(BaseModel):
    """Output envelope of deterministic evidence correlation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    records: tuple[CorrelationRecord, ...] = ()
    sink_scopes: tuple[InjectionSinkScope, ...] = ()
    diagnostics: tuple[CorrelationDiagnostic, ...] = ()
    limitations: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    coverage: CorrelationCoverage
    trust_policy_fingerprint: str
    trust_policy_is_default: bool


class Module2CorrelationEnvelope(BaseModel):
    """Complete Module 2 envelope packaging validated Module2Output and CorrelationResult."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_id: Literal["websecuritycheck.m2_correlation.v1"] = "websecuritycheck.m2_correlation.v1"
    output: Module2Output
    correlation: CorrelationResult


__all__ = [
    "CorrelationCoverage",
    "CorrelationDiagnostic",
    "CorrelationRecord",
    "CorrelationResult",
    "IndependenceAssessment",
    "InjectionSinkScope",
    "Module2CorrelationEnvelope",
    "RouteBindingArtifactRef",
    "RouteHandlerBinding",
    "TaintSourceAccessor",
]

