"""Module 2 Vulnerability Analysis and Hypothesis Generation domain schemas.

These schemas define the data models, contracts, and deterministic validators for
Module 2 (Vulnerability Analysis & Hypothesis Generation) of the Web Security AI Agent.
"""

from __future__ import annotations

from collections.abc import Set
from datetime import datetime
from enum import StrEnum
from pathlib import PurePath
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, ValidationInfo, model_validator

from .enums import ArtifactType, DiscoverySource, InputLocation, TechnologyCategory, TestingMode
from .models import (
    EndpointId,
    EvidenceArtifactRecord,
    ObservationRecord,
    StrictModel,
    TargetModel,
    TechnologyRecord,
)

# ---------------------------------------------------------------------------
# 1. Prefix-Constrained Identifier Types
# ---------------------------------------------------------------------------

AssessmentId = Annotated[str, StringConstraints(pattern=r"^ASM-[0-9]{3,}$")]
TargetId = Annotated[str, StringConstraints(pattern=r"^TGT-[0-9]{3,}$")]
EvidenceId = Annotated[str, StringConstraints(pattern=r"^EVD-[0-9]{3,}$")]
ObservationId = Annotated[str, StringConstraints(pattern=r"^OBS-[0-9]{3,}$")]
InputId = Annotated[str, StringConstraints(pattern=r"^INP-[0-9]{3,}$")]
SinkId = Annotated[str, StringConstraints(pattern=r"^SNK-[0-9]{3,}$")]
CveCandidateId = Annotated[str, StringConstraints(pattern=r"^CVC-[0-9]{3,}$")]
HypothesisId = Annotated[str, StringConstraints(pattern=r"^HYP-[0-9]{3,}$")]
ProposalId = Annotated[str, StringConstraints(pattern=r"^VCR-[0-9]{3,}$")]
CveId = Annotated[str, StringConstraints(pattern=r"^CVE-(1999|20[0-9]{2})-[0-9]{4,}$")]
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-[1-9][0-9]*$")]


# ---------------------------------------------------------------------------
# 2. Module 2 Enums & Draft Cross-Team Capability Mapping
# ---------------------------------------------------------------------------


class ConfidenceLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SinkKind(StrEnum):
    SQL_QUERY = "SQL_QUERY"
    OS_COMMAND = "OS_COMMAND"
    HTML_OUTPUT = "HTML_OUTPUT"
    TEMPLATE_RENDER = "TEMPLATE_RENDER"
    NOSQL_QUERY = "NOSQL_QUERY"
    CODE_EVAL = "CODE_EVAL"
    PATH_ACCESS = "PATH_ACCESS"
    LDAP_OR_XPATH = "LDAP_OR_XPATH"
    ORM_QUERY = "ORM_QUERY"


class SinkRelationship(StrEnum):
    """Static code relationship only; never implies confirmed runtime exploitability."""

    STATIC_TAINT_FLOW_FOUND = "STATIC_TAINT_FLOW_FOUND"
    UNVERIFIED_STATIC_SINK = "UNVERIFIED_STATIC_SINK"
    UNKNOWN = "UNKNOWN"


class VulnerabilityCategory(StrEnum):
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    OS_COMMAND_INJECTION = "OS_COMMAND_INJECTION"
    SSTI = "SSTI"
    NOSQL_INJECTION = "NOSQL_INJECTION"
    LDAP_XPATH_ORM_INJECTION = "LDAP_XPATH_ORM_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    KNOWN_CVE = "KNOWN_CVE"


class ValidationCapability(StrEnum):
    """Draft cross-team capability identifiers pending Module 3 Tool Registry sign-off."""

    SQLI_DETECTION = "SQLI_DETECTION"
    XSS_DETECTION = "XSS_DETECTION"
    CMDI_DETECTION = "CMDI_DETECTION"
    SSTI_DETECTION = "SSTI_DETECTION"
    NOSQLI_DETECTION = "NOSQLI_DETECTION"
    LDAP_XPATH_ORM_DETECTION = "LDAP_XPATH_ORM_DETECTION"
    PATH_TRAVERSAL_DETECTION = "PATH_TRAVERSAL_DETECTION"
    CVE_SAFE_CHECK = "CVE_SAFE_CHECK"


class ExpectedSignal(StrEnum):
    SQL_SYNTAX_ERROR = "SQL_SYNTAX_ERROR"
    BOOLEAN_RESPONSE_DIFF = "BOOLEAN_RESPONSE_DIFF"
    TIMING_DIFF = "TIMING_DIFF"
    UNENCODED_REFLECTION = "UNENCODED_REFLECTION"
    DOM_EXECUTION_CONFIRMED = "DOM_EXECUTION_CONFIRMED"
    COMMAND_OUTPUT_REFLECTED = "COMMAND_OUTPUT_REFLECTED"
    TEMPLATE_EXPR_EVALUATED = "TEMPLATE_EXPR_EVALUATED"
    NOSQL_OPERATOR_DIFF = "NOSQL_OPERATOR_DIFF"
    PATH_CONTENT_DISCLOSURE = "PATH_CONTENT_DISCLOSURE"
    SAFE_CVE_CHECK_MATCH = "SAFE_CVE_CHECK_MATCH"


CATEGORY_TO_CAPABILITY: dict[VulnerabilityCategory, ValidationCapability] = {
    VulnerabilityCategory.SQL_INJECTION: ValidationCapability.SQLI_DETECTION,
    VulnerabilityCategory.XSS: ValidationCapability.XSS_DETECTION,
    VulnerabilityCategory.OS_COMMAND_INJECTION: ValidationCapability.CMDI_DETECTION,
    VulnerabilityCategory.SSTI: ValidationCapability.SSTI_DETECTION,
    VulnerabilityCategory.NOSQL_INJECTION: ValidationCapability.NOSQLI_DETECTION,
    VulnerabilityCategory.LDAP_XPATH_ORM_INJECTION: ValidationCapability.LDAP_XPATH_ORM_DETECTION,
    VulnerabilityCategory.PATH_TRAVERSAL: ValidationCapability.PATH_TRAVERSAL_DETECTION,
    VulnerabilityCategory.KNOWN_CVE: ValidationCapability.CVE_SAFE_CHECK,
}


# ---------------------------------------------------------------------------
# 3. Canonical Technology Reference & Module 1 -> Module 2 Input Contract
# ---------------------------------------------------------------------------


def _tech_key(category: TechnologyCategory, name: str, version: str | None) -> tuple[str, str, str]:
    """Canonical identity matching websecuritycheck.recon.technology._key."""
    return category.value.upper(), name.casefold().strip(), (version or "").casefold().strip()


class TechnologyTargetRef(StrictModel):
    """Canonical reference to a versioned TechnologyRecord in TargetModel.technologies."""

    category: TechnologyCategory
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)

    @property
    def canonical_key(self) -> tuple[str, str, str]:
        return _tech_key(self.category, self.name, self.version)

    @classmethod
    def from_record(cls, record: TechnologyRecord) -> TechnologyTargetRef:
        if not record.version or not record.version.strip():
            raise ValueError(f"TechnologyRecord {record.name!r} has no version for CVE targeting")
        return cls(category=record.category, name=record.name, version=record.version)


class Module2AnalysisRequest(StrictModel):
    """Input envelope consumed by Module 2 from canonical Module 1 outputs."""

    target_model: TargetModel
    observations: list[ObservationRecord] = Field(default_factory=list)
    evidence_records: list[EvidenceArtifactRecord] = Field(default_factory=list)
    source_repo_path: str | None = None

    @model_validator(mode="after")
    def validate_request_consistency(self) -> Module2AnalysisRequest:
        asm_id = self.target_model.assessment_id
        seen_obs: set[str] = set()
        for obs in self.observations:
            if obs.assessment_id != asm_id:
                raise ValueError(
                    f"observation {obs.observation_id} assessment_id {obs.assessment_id!r} "
                    f"does not match target_model {asm_id!r}"
                )
            if obs.observation_id in seen_obs:
                raise ValueError(f"Duplicate observation_id in request: {obs.observation_id}")
            seen_obs.add(obs.observation_id)

        seen_evd: set[str] = set()
        for evd in self.evidence_records:
            if evd.assessment_id != asm_id:
                raise ValueError(
                    f"evidence {evd.evidence_id} assessment_id {evd.assessment_id!r} "
                    f"does not match target_model {asm_id!r}"
                )
            if evd.evidence_id in seen_evd:
                raise ValueError(f"Duplicate evidence_id in request: {evd.evidence_id}")
            seen_evd.add(evd.evidence_id)

        if self.source_repo_path is not None and not self.source_repo_path.strip():
            raise ValueError("source_repo_path cannot be blank when provided")
        rules = self.target_model.scope_rules
        if (
            self.source_repo_path is not None
            and rules is not None
            and rules.testing_mode == TestingMode.BLACKBOX
        ):
            raise ValueError("source_repo_path is not allowed when testing_mode is BLACKBOX")
        return self


# ---------------------------------------------------------------------------
# 4. Module 2 Candidate Contracts
# ---------------------------------------------------------------------------


class InputCandidate(StrictModel):
    """Normalized attack input extracted from TargetModel endpoints and observations."""

    input_id: InputId
    endpoint_id: EndpointId
    location: InputLocation
    parameter_name: str = Field(min_length=1)
    data_type: str | None = None
    required: bool | None = None
    sample_value: str | None = None
    discovery_sources: list[DiscoverySource] = Field(default_factory=list)
    evidence_refs: list[EvidenceId] = Field(default_factory=list)
    observation_refs: list[ObservationId] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_grounding_reference(self) -> InputCandidate:
        if not self.evidence_refs and not self.observation_refs:
            raise ValueError(
                f"InputCandidate {self.input_id} requires at least one "
                "evidence_ref or observation_ref"
            )
        return self


def _is_safe_relative_path(path_text: str) -> bool:
    if not path_text or path_text.startswith(("/", "\\")) or ":" in path_text:
        return False
    parts = PurePath(path_text.replace("\\", "/")).parts
    return bool(parts) and ".." not in parts


class SinkCandidate(StrictModel):
    """Static source-code sink candidate extracted from Opengrep findings.

    Deliberately omits endpoint_id: static source findings never imply HTTP
    endpoint reachability on their own.
    """

    sink_id: SinkId
    sink_kind: SinkKind
    file_path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    rule_id: str = Field(min_length=1)
    snippet: str | None = None
    has_static_taint_flow: bool = False
    dataflow_steps: list[str] = Field(default_factory=list)
    confidence: ConfidenceLevel
    evidence_refs: list[EvidenceId] = Field(default_factory=list)
    observation_refs: list[ObservationId] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_sink_invariants(self) -> SinkCandidate:
        if not _is_safe_relative_path(self.file_path):
            raise ValueError(f"SinkCandidate {self.sink_id} file_path must be repository-relative")
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError(f"SinkCandidate {self.sink_id} end_line cannot precede start_line")
        if self.has_static_taint_flow and not self.dataflow_steps:
            raise ValueError(
                f"SinkCandidate {self.sink_id} with has_static_taint_flow=True "
                "requires dataflow_steps"
            )
        if not self.evidence_refs:
            raise ValueError(
                f"SinkCandidate {self.sink_id} requires at least one Opengrep evidence_ref"
            )
        return self


class CVECandidate(StrictModel):
    """Unconfirmed CVE candidate matched from a canonical TechnologyRecord."""

    cve_candidate_id: CveCandidateId
    cve_id: CveId
    target_technology: TechnologyTargetRef
    affected_range: str = Field(min_length=1)
    cwe_id: CweId | None = None
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    confidence: ConfidenceLevel
    match_rationale: str = Field(min_length=5)
    evidence_refs: list[EvidenceId] = Field(default_factory=list)
    observation_refs: list[ObservationId] = Field(default_factory=list)
    is_confirmed: Literal[False] = False

    @model_validator(mode="after")
    def require_cve_grounding(self) -> CVECandidate:
        if not self.evidence_refs and not self.observation_refs:
            raise ValueError(
                f"CVECandidate {self.cve_candidate_id} requires at least one "
                "evidence_ref or observation_ref"
            )
        return self


# ---------------------------------------------------------------------------
# 5. Shared Integration Contracts (Module 2 <-> AI Agent / Module 3)
# ---------------------------------------------------------------------------


class ValidationCapabilityRequirement(StrictModel):
    """Tool-independent validation requirement proposed for Module 3."""

    proposal_id: ProposalId
    hypothesis_ref: HypothesisId
    vulnerability_category: VulnerabilityCategory
    suggested_capability: ValidationCapability
    target_endpoint_id: EndpointId | None = None
    target_technology: TechnologyTargetRef | None = None
    target_input_ref: InputId | None = None
    cve_candidate_ref: CveCandidateId | None = None
    evidence_refs: list[EvidenceId] = Field(default_factory=list)
    observation_refs: list[ObservationId] = Field(default_factory=list)
    priority: int = Field(default=5, ge=1, le=10)
    expected_signals: list[ExpectedSignal] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_capability_alignment(self) -> ValidationCapabilityRequirement:
        expected_cap = CATEGORY_TO_CAPABILITY[self.vulnerability_category]
        if self.suggested_capability != expected_cap:
            raise ValueError(
                f"Proposal {self.proposal_id} capability {self.suggested_capability.value} "
                f"does not match category {self.vulnerability_category.value} "
                f"(expected {expected_cap.value})"
            )
        if self.vulnerability_category == VulnerabilityCategory.KNOWN_CVE:
            if self.cve_candidate_ref is None or self.target_technology is None:
                raise ValueError(
                    f"Proposal {self.proposal_id} for KNOWN_CVE requires "
                    "cve_candidate_ref and target_technology"
                )
            if self.target_input_ref is not None:
                raise ValueError(
                    f"Proposal {self.proposal_id} for KNOWN_CVE must not set target_input_ref"
                )
        else:
            if self.target_endpoint_id is None or self.target_input_ref is None:
                raise ValueError(
                    f"Proposal {self.proposal_id} for {self.vulnerability_category.value} "
                    "requires target_endpoint_id and target_input_ref"
                )
            if self.cve_candidate_ref is not None or self.target_technology is not None:
                raise ValueError(
                    f"Proposal {self.proposal_id} for {self.vulnerability_category.value} "
                    "must not set cve_candidate_ref or target_technology"
                )
        if not self.evidence_refs and not self.observation_refs:
            raise ValueError(
                f"Proposal {self.proposal_id} requires at least one evidence_ref or observation_ref"
            )
        return self


class Hypothesis(StrictModel):
    """Evidence-backed vulnerability hypothesis supporting endpoint or component scope."""

    hypothesis_id: HypothesisId
    vulnerability_category: VulnerabilityCategory
    target_endpoint_id: EndpointId | None = None
    target_technology: TechnologyTargetRef | None = None
    input_ref: InputId | None = None
    sink_ref: SinkId | None = None
    sink_relationship: SinkRelationship = SinkRelationship.UNKNOWN
    cve_candidate_ref: CveCandidateId | None = None
    confidence: ConfidenceLevel
    rationale: str = Field(min_length=5)
    missing_evidence: list[str] = Field(default_factory=list)
    supporting_evidence_refs: list[EvidenceId] = Field(default_factory=list)
    supporting_observation_refs: list[ObservationId] = Field(default_factory=list)
    validation_proposals: list[ValidationCapabilityRequirement] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_hypothesis_invariants(self) -> Hypothesis:
        if not self.supporting_evidence_refs and not self.supporting_observation_refs:
            raise ValueError(
                f"Hypothesis {self.hypothesis_id} must reference "
                "supporting evidence or observations"
            )
        if self.sink_ref is None and self.sink_relationship != SinkRelationship.UNKNOWN:
            raise ValueError(
                f"Hypothesis {self.hypothesis_id} without sink_ref "
                "must have sink_relationship=UNKNOWN"
            )
        if self.sink_ref is not None and self.sink_relationship == SinkRelationship.UNKNOWN:
            raise ValueError(
                f"Hypothesis {self.hypothesis_id} with sink_ref {self.sink_ref} "
                "must specify STATIC_TAINT_FLOW_FOUND or UNVERIFIED_STATIC_SINK"
            )
        if self.vulnerability_category == VulnerabilityCategory.KNOWN_CVE:
            if self.cve_candidate_ref is None or self.target_technology is None:
                raise ValueError(
                    f"Hypothesis {self.hypothesis_id} for KNOWN_CVE requires "
                    "cve_candidate_ref and target_technology"
                )
            if self.input_ref is not None or self.sink_ref is not None:
                raise ValueError(
                    f"Hypothesis {self.hypothesis_id} for KNOWN_CVE "
                    "must not set input_ref or sink_ref"
                )
        else:
            if self.target_endpoint_id is None or self.input_ref is None:
                raise ValueError(
                    f"Hypothesis {self.hypothesis_id} for {self.vulnerability_category.value} "
                    "requires target_endpoint_id and input_ref"
                )
            if self.cve_candidate_ref is not None or self.target_technology is not None:
                raise ValueError(
                    f"Hypothesis {self.hypothesis_id} for {self.vulnerability_category.value} "
                    "must not set cve_candidate_ref or target_technology"
                )
        for prop in self.validation_proposals:
            if prop.hypothesis_ref != self.hypothesis_id:
                raise ValueError(
                    f"Proposal {prop.proposal_id} hypothesis_ref {prop.hypothesis_ref} "
                    f"does not match {self.hypothesis_id}"
                )
            if prop.vulnerability_category != self.vulnerability_category:
                raise ValueError(
                    f"Proposal {prop.proposal_id} category does not match "
                    f"Hypothesis {self.hypothesis_id}"
                )
            if prop.target_endpoint_id != self.target_endpoint_id:
                raise ValueError(
                    f"Proposal {prop.proposal_id} target_endpoint_id does not match "
                    f"Hypothesis {self.hypothesis_id}"
                )
            if prop.target_technology != self.target_technology:
                raise ValueError(
                    f"Proposal {prop.proposal_id} target_technology does not match "
                    f"Hypothesis {self.hypothesis_id}"
                )
            if prop.target_input_ref != self.input_ref:
                raise ValueError(
                    f"Proposal {prop.proposal_id} target_input_ref does not match "
                    f"Hypothesis {self.hypothesis_id}"
                )
            if prop.cve_candidate_ref != self.cve_candidate_ref:
                raise ValueError(
                    f"Proposal {prop.proposal_id} cve_candidate_ref does not match "
                    f"Hypothesis {self.hypothesis_id}"
                )
        return self


class Module2Output(StrictModel):
    """Complete Module 2 output contract for Module 3 consumption.

    Structural and internal foreign-key checks run automatically on construction.
    Before handoff to Module 3, callers MUST run validate_module2_handoff() to
    enforce fail-closed external reference resolution against Module2AnalysisRequest.
    """

    assessment_id: AssessmentId
    target_id: TargetId
    schema_version: str = "3.0.0-m2"
    generated_at: datetime
    analysis_evidence_records: list[EvidenceArtifactRecord] = Field(default_factory=list)
    inputs: list[InputCandidate] = Field(default_factory=list)
    sink_candidates: list[SinkCandidate] = Field(default_factory=list)
    cve_candidates: list[CVECandidate] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_internal_integrity(self, info: ValidationInfo) -> Module2Output:
        analysis_evd_ids: set[str] = set()
        for evd in self.analysis_evidence_records:
            if evd.assessment_id != self.assessment_id:
                raise ValueError(
                    f"analysis_evidence_record {evd.evidence_id} assessment_id "
                    f"{evd.assessment_id!r} does not match {self.assessment_id!r}"
                )
            if evd.artifact_type != ArtifactType.SOURCE_ARTIFACT:
                raise ValueError(
                    f"analysis_evidence_record {evd.evidence_id} must have "
                    "artifact_type=SOURCE_ARTIFACT"
                )
            if evd.evidence_id in analysis_evd_ids:
                raise ValueError(f"Duplicate analysis_evidence_record ID: {evd.evidence_id}")
            analysis_evd_ids.add(evd.evidence_id)

        inputs_by_id: dict[str, InputCandidate] = {}
        for inp in self.inputs:
            if inp.input_id in inputs_by_id:
                raise ValueError(f"Duplicate input_id: {inp.input_id}")
            inputs_by_id[inp.input_id] = inp

        sinks_by_id: dict[str, SinkCandidate] = {}
        for snk in self.sink_candidates:
            if snk.sink_id in sinks_by_id:
                raise ValueError(f"Duplicate sink_id: {snk.sink_id}")
            sinks_by_id[snk.sink_id] = snk

        cves_by_id: dict[str, CVECandidate] = {}
        for cve in self.cve_candidates:
            if cve.cve_candidate_id in cves_by_id:
                raise ValueError(f"Duplicate cve_candidate_id: {cve.cve_candidate_id}")
            cves_by_id[cve.cve_candidate_id] = cve

        hyp_ids: set[str] = set()
        proposal_ids: set[str] = set()
        for hyp in self.hypotheses:
            if hyp.hypothesis_id in hyp_ids:
                raise ValueError(f"Duplicate hypothesis_id: {hyp.hypothesis_id}")
            hyp_ids.add(hyp.hypothesis_id)

            if hyp.input_ref is not None:
                matched_input = inputs_by_id.get(hyp.input_ref)
                if matched_input is None:
                    raise ValueError(
                        f"Hypothesis {hyp.hypothesis_id} references "
                        f"unknown input_ref {hyp.input_ref}"
                    )
                if matched_input.endpoint_id != hyp.target_endpoint_id:
                    raise ValueError(
                        f"Hypothesis {hyp.hypothesis_id} target_endpoint_id "
                        f"{hyp.target_endpoint_id} does not match "
                        f"InputCandidate {hyp.input_ref} endpoint_id {matched_input.endpoint_id}"
                    )

            if hyp.sink_ref is not None:
                matched_sink = sinks_by_id.get(hyp.sink_ref)
                if matched_sink is None:
                    raise ValueError(
                        f"Hypothesis {hyp.hypothesis_id} references unknown sink_ref {hyp.sink_ref}"
                    )
                if (
                    hyp.sink_relationship == SinkRelationship.STATIC_TAINT_FLOW_FOUND
                    and not matched_sink.has_static_taint_flow
                ):
                    raise ValueError(
                        f"Hypothesis {hyp.hypothesis_id} claims STATIC_TAINT_FLOW_FOUND but "
                        f"SinkCandidate {hyp.sink_ref} has has_static_taint_flow=False"
                    )

            if hyp.cve_candidate_ref is not None:
                matched_cve = cves_by_id.get(hyp.cve_candidate_ref)
                if matched_cve is None:
                    raise ValueError(
                        f"Hypothesis {hyp.hypothesis_id} references unknown cve_candidate_ref "
                        f"{hyp.cve_candidate_ref}"
                    )
                if hyp.target_technology != matched_cve.target_technology:
                    raise ValueError(
                        f"Hypothesis {hyp.hypothesis_id} target_technology does not match "
                        f"CVECandidate {hyp.cve_candidate_ref}"
                    )

            for prop in hyp.validation_proposals:
                if prop.proposal_id in proposal_ids:
                    raise ValueError(f"Duplicate proposal_id: {prop.proposal_id}")
                proposal_ids.add(prop.proposal_id)

        if info.context is not None:
            if not isinstance(info.context, dict) or (
                "reference_index" not in info.context and "request" not in info.context
            ):
                raise ValueError(
                    "validation context must provide 'reference_index' or 'request' (fail-closed)"
                )
            _validate_against_index(
                self,
                index=info.context.get("reference_index"),
                request=info.context.get("request"),
                allowed_capabilities=info.context.get("allowed_capabilities"),
            )

        return self


# ---------------------------------------------------------------------------
# 6. Authoritative Reference Index & Fail-Closed Handoff Validator
# ---------------------------------------------------------------------------


class AuthoritativeReferenceIndex(StrictModel):
    """Authoritative lookup index of Module 1 entities for fail-closed validation."""

    assessment_id: AssessmentId
    target_id: TargetId
    endpoint_refs: dict[EndpointId, frozenset[str]] = Field(default_factory=dict)
    technology_refs: dict[tuple[str, str, str], frozenset[str]] = Field(default_factory=dict)
    evidence_ids: frozenset[str] = Field(default_factory=frozenset)
    source_evidence_ids: frozenset[str] = Field(default_factory=frozenset)
    observation_ids: frozenset[str] = Field(default_factory=frozenset)

    @classmethod
    def from_request(cls, request: Module2AnalysisRequest) -> AuthoritativeReferenceIndex:
        tm = request.target_model
        evd_ids: set[str] = {evd.evidence_id for evd in request.evidence_records}
        src_evd_ids: set[str] = {
            evd.evidence_id
            for evd in request.evidence_records
            if evd.artifact_type == ArtifactType.SOURCE_ARTIFACT
        }
        obs_ids: set[str] = {obs.observation_id for obs in request.observations}

        ep_map: dict[str, frozenset[str]] = {}
        for ep in tm.endpoints:
            ep_support = set(ep.evidence_refs) | set(ep.observation_refs)
            for param in ep.observed_parameters:
                ep_support.update(param.evidence_refs)
                ep_support.update(param.observation_refs)
            ep_map[ep.endpoint_id] = frozenset(ep_support)
            evd_ids.update(ep.evidence_refs)
            obs_ids.update(ep.observation_refs)
            for param in ep.observed_parameters:
                evd_ids.update(param.evidence_refs)
                obs_ids.update(param.observation_refs)

        tech_map: dict[tuple[str, str, str], frozenset[str]] = {}
        for tech in tm.technologies:
            evd_ids.update(tech.evidence_refs)
            obs_ids.update(tech.observation_refs)
            if tech.version and tech.version.strip():
                key = _tech_key(tech.category, tech.name, tech.version)
                existing = tech_map.get(key, frozenset())
                tech_map[key] = existing | frozenset(tech.evidence_refs) | frozenset(
                    tech.observation_refs
                )

        return cls(
            assessment_id=tm.assessment_id,
            target_id=tm.target_id,
            endpoint_refs=ep_map,
            technology_refs=tech_map,
            evidence_ids=frozenset(evd_ids),
            source_evidence_ids=frozenset(src_evd_ids),
            observation_ids=frozenset(obs_ids),
        )


def _validate_against_index(
    output: Module2Output,
    *,
    index: AuthoritativeReferenceIndex | None = None,
    request: Module2AnalysisRequest | None = None,
    allowed_capabilities: Set[ValidationCapability] | None = None,
) -> AuthoritativeReferenceIndex:
    if index is None:
        if not isinstance(request, Module2AnalysisRequest):
            raise ValueError(
                "Handoff validation requires an AuthoritativeReferenceIndex "
                "or Module2AnalysisRequest"
            )
        index = AuthoritativeReferenceIndex.from_request(request)
    elif not isinstance(index, AuthoritativeReferenceIndex):
        raise ValueError("index must be an AuthoritativeReferenceIndex instance")

    if output.assessment_id != index.assessment_id:
        raise ValueError(
            f"Module2Output assessment_id {output.assessment_id!r} "
            f"does not match authoritative {index.assessment_id!r}"
        )
    if output.target_id != index.target_id:
        raise ValueError(
            f"Module2Output target_id {output.target_id!r} "
            f"does not match authoritative {index.target_id!r}"
        )

    m2_evd_ids: set[str] = set()
    for evd in output.analysis_evidence_records:
        if evd.evidence_id in index.evidence_ids:
            raise ValueError(
                f"Module2Output analysis_evidence_record {evd.evidence_id} "
                "collides with an existing Module 1 evidence_id"
            )
        m2_evd_ids.add(evd.evidence_id)

    all_valid_evd = index.evidence_ids | m2_evd_ids
    all_source_evd = index.source_evidence_ids | m2_evd_ids
    all_valid_obs = index.observation_ids

    def _require_resolvable(owner_id: str, evd_refs: list[str], obs_refs: list[str]) -> None:
        for ref in evd_refs:
            if ref not in all_valid_evd:
                raise ValueError(f"{owner_id} references unresolvable evidence_id {ref}")
        for ref in obs_refs:
            if ref not in all_valid_obs:
                raise ValueError(f"{owner_id} references unresolvable observation_id {ref}")

    for inp in output.inputs:
        if inp.endpoint_id not in index.endpoint_refs:
            raise ValueError(
                f"InputCandidate {inp.input_id} references unknown endpoint_id {inp.endpoint_id}"
            )
        _require_resolvable(inp.input_id, inp.evidence_refs, inp.observation_refs)

    for snk in output.sink_candidates:
        _require_resolvable(snk.sink_id, snk.evidence_refs, snk.observation_refs)
        if not any(ref in all_source_evd for ref in snk.evidence_refs):
            raise ValueError(
                f"SinkCandidate {snk.sink_id} must reference at least one SOURCE_ARTIFACT "
                "evidence record in analysis_evidence_records or request.evidence_records"
            )

    for cve in output.cve_candidates:
        tech_key = cve.target_technology.canonical_key
        if tech_key not in index.technology_refs:
            raise ValueError(
                f"CVECandidate {cve.cve_candidate_id} references technology "
                f"{cve.target_technology.name} {cve.target_technology.version} "
                "not present in TargetModel.technologies"
            )
        _require_resolvable(cve.cve_candidate_id, cve.evidence_refs, cve.observation_refs)
        tech_support = index.technology_refs[tech_key]
        cve_support = set(cve.evidence_refs) | set(cve.observation_refs)
        if tech_support and not (cve_support & tech_support):
            raise ValueError(
                f"CVECandidate {cve.cve_candidate_id} evidence/observation refs do not "
                "intersect the supporting refs of its TargetModel TechnologyRecord"
            )

    for hyp in output.hypotheses:
        _require_resolvable(
            hyp.hypothesis_id,
            hyp.supporting_evidence_refs,
            hyp.supporting_observation_refs,
        )
        if hyp.target_endpoint_id is not None:
            if hyp.target_endpoint_id not in index.endpoint_refs:
                raise ValueError(
                    f"Hypothesis {hyp.hypothesis_id} references unknown endpoint_id "
                    f"{hyp.target_endpoint_id}"
                )
            if hyp.vulnerability_category == VulnerabilityCategory.KNOWN_CVE:
                ep_support = index.endpoint_refs[hyp.target_endpoint_id]
                hyp_support = set(hyp.supporting_evidence_refs) | set(
                    hyp.supporting_observation_refs
                )
                if not (hyp_support & ep_support):
                    raise ValueError(
                        f"KNOWN_CVE Hypothesis {hyp.hypothesis_id} cannot associate with "
                        f"endpoint {hyp.target_endpoint_id} without shared endpoint "
                        "evidence/observations"
                    )
        if (
            hyp.target_technology is not None
            and hyp.target_technology.canonical_key not in index.technology_refs
        ):
            raise ValueError(
                f"Hypothesis {hyp.hypothesis_id} references unknown target_technology "
                f"{hyp.target_technology.name} {hyp.target_technology.version}"
            )
        for prop in hyp.validation_proposals:
            _require_resolvable(prop.proposal_id, prop.evidence_refs, prop.observation_refs)
            if (
                allowed_capabilities is not None
                and prop.suggested_capability not in allowed_capabilities
            ):
                raise ValueError(
                    f"Proposal {prop.proposal_id} requests unsupported capability "
                    f"{prop.suggested_capability.value}"
                )

    return index


def validate_module2_handoff(
    output: Module2Output,
    request: Module2AnalysisRequest | None = None,
    *,
    index: AuthoritativeReferenceIndex | None = None,
    allowed_capabilities: Set[ValidationCapability] | None = None,
) -> Module2Output:
    """Mandatory fail-closed semantic validation before Module 2 -> Module 3 handoff."""
    if not isinstance(output, Module2Output):
        raise ValueError("output must be a Module2Output instance")
    _validate_against_index(
        output,
        index=index,
        request=request,
        allowed_capabilities=allowed_capabilities,
    )
    return output


def filter_unsupported_capabilities(
    output: Module2Output,
    supported_capabilities: Set[ValidationCapability],
) -> Module2Output:
    """Deterministically prune proposals unsupported by Module 3 and record limitations."""
    updated_hypotheses: list[Hypothesis] = []
    limitations = list(output.limitations)
    for hyp in output.hypotheses:
        kept: list[ValidationCapabilityRequirement] = []
        for prop in hyp.validation_proposals:
            if prop.suggested_capability in supported_capabilities:
                kept.append(prop)
            else:
                msg = (
                    f"Dropped proposal {prop.proposal_id} ({prop.suggested_capability.value}) "
                    f"for hypothesis {hyp.hypothesis_id}: capability not supported by Module 3"
                )
                if msg not in limitations:
                    limitations.append(msg)
        updated_hypotheses.append(hyp.model_copy(update={"validation_proposals": kept}))
    return output.model_copy(
        update={"hypotheses": updated_hypotheses, "limitations": limitations}
    )


__all__ = [
    "CATEGORY_TO_CAPABILITY",
    "AssessmentId",
    "AuthoritativeReferenceIndex",
    "CVECandidate",
    "ConfidenceLevel",
    "CveCandidateId",
    "CveId",
    "CweId",
    "EvidenceId",
    "ExpectedSignal",
    "Hypothesis",
    "HypothesisId",
    "InputCandidate",
    "InputId",
    "Module2AnalysisRequest",
    "Module2Output",
    "ObservationId",
    "ProposalId",
    "SinkCandidate",
    "SinkId",
    "SinkKind",
    "SinkRelationship",
    "TechnologyTargetRef",
    "ValidationCapability",
    "ValidationCapabilityRequirement",
    "VulnerabilityCategory",
    "filter_unsupported_capabilities",
    "validate_module2_handoff",
]
