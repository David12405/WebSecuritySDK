"""M2-T05 Injection-Focused Evidence Correlation Engine.

Deterministic, offline, evidence-grounded correlation engine for Module 2
(Vulnerability Analysis) of the WebSecuritySDK. Correlates InputCandidate,
SinkCandidate, and CVECandidate within OWASP Top 10:2025 A05: Injection scope.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from websecuritycheck.analysis.cve import (
    DIRECT_INJECTION_CWES,
    EXCLUDED_CWES,
    CVEExtractionResult,
    InjectionScopePolicy,
    InjectionScopeStatus,
    InjectionSubtype,
    ProductMatchKind,
)
from websecuritycheck.analysis.inputs import (
    InputExtractionResult,
    normalize_parameter_name,
)
from websecuritycheck.analysis.sinks import (
    SinkCorrelationMetadata,
    SinkExtractionResult,
    is_safe_sink_path,
    normalize_sink_file_path,
    verify_sink_evidence_integrity,
)
from websecuritycheck.domain.analysis_models import (
    AuthoritativeReferenceIndex,
    ConfidenceLevel,
    CVECandidate,
    CveCandidateId,
    CveId,
    CweId,
    EvidenceId,
    InputCandidate,
    InputId,
    Module2AnalysisRequest,
    Module2Output,
    ObservationId,
    SinkCandidate,
    SinkId,
    SinkKind,
    SinkRelationship,
    TechnologyTargetRef,
    VulnerabilityCategory,
    validate_module2_handoff,
)
from websecuritycheck.domain.enums import (
    ArtifactType,
    InputLocation,
    TestingMode,
)
from websecuritycheck.domain.models import (
    ArtifactManifest,
    EvidenceArtifactRecord,
    ObservationRecord,
)

# ---------------------------------------------------------------------------
# 1. Identifiers and Custom Errors
# ---------------------------------------------------------------------------

CorrelationId = Annotated[str, StringConstraints(pattern=r"^COR-[0-9a-f]{16}$")]


class CorrelationInputError(ValueError):
    """Raised when correlation input data or references fail closed."""


class CorrelationTrustPolicyError(ValueError):
    """Raised when CorrelationTrustPolicy entries fail invariant checks."""


# ---------------------------------------------------------------------------
# 2. Enumerations
# ---------------------------------------------------------------------------


class CorrelationKind(StrEnum):
    """Classification of the security relation established by correlation."""

    INPUT_SINK = "INPUT_SINK"
    ENDPOINT_SINK = "ENDPOINT_SINK"
    CVE_TECHNOLOGY = "CVE_TECHNOLOGY"
    SINK_CVE = "SINK_CVE"
    INPUT_SINK_CVE_CHAIN = "INPUT_SINK_CVE_CHAIN"


class CorrelationStatus(StrEnum):
    """Certainty status of the correlated relationship."""

    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    UNRESOLVED = "UNRESOLVED"


class AccessorResolution(StrEnum):
    """Outcome of parsing a static taint source snippet for input accessors."""

    RESOLVED = "RESOLVED"
    DYNAMIC_KEY = "DYNAMIC_KEY"
    REDACTED = "REDACTED"
    TRUNCATED = "TRUNCATED"
    UNSUPPORTED = "UNSUPPORTED"


class RuleMode(StrEnum):
    """Semgrep analysis mode declared by an approved rule."""

    TAINT = "TAINT"
    SEARCH = "SEARCH"


class RuleProvenanceStatus(StrEnum):
    """Validation status of the Semgrep rule and ruleset provenance."""

    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    CONFLICT = "CONFLICT"


class FlowTrust(StrEnum):
    """Trust tier of the static dataflow / taint trace."""

    TRUSTED_TAINT = "TRUSTED_TAINT"
    UNTRUSTED_TAINT = "UNTRUSTED_TAINT"
    PATTERN_ONLY = "PATTERN_ONLY"
    CONFLICT = "CONFLICT"


class IndependenceStatus(StrEnum):
    """Provenance independence evaluation across supporting relation evidence."""

    INDEPENDENT = "INDEPENDENT"
    SHARED = "SHARED"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# 3. Scope & Taxonomy Mappings
# ---------------------------------------------------------------------------

SUBTYPE_TO_CATEGORY: dict[InjectionSubtype, VulnerabilityCategory | None] = {
    InjectionSubtype.SQL_INJECTION: VulnerabilityCategory.SQL_INJECTION,
    InjectionSubtype.OS_COMMAND_INJECTION: VulnerabilityCategory.OS_COMMAND_INJECTION,
    InjectionSubtype.NOSQL_INJECTION: VulnerabilityCategory.NOSQL_INJECTION,
    InjectionSubtype.LDAP_INJECTION: VulnerabilityCategory.LDAP_XPATH_ORM_INJECTION,
    InjectionSubtype.XPATH_INJECTION: VulnerabilityCategory.LDAP_XPATH_ORM_INJECTION,
    InjectionSubtype.ORM_QUERY_INJECTION: VulnerabilityCategory.LDAP_XPATH_ORM_INJECTION,
    InjectionSubtype.SSTI: VulnerabilityCategory.SSTI,
    # Gap G3: VulnerabilityCategory currently lacks CODE_INJECTION
    InjectionSubtype.CODE_INJECTION: None,
}

SINK_KIND_INJECTION_CWES: dict[SinkKind, frozenset[str]] = {
    SinkKind.SQL_QUERY: frozenset({"CWE-89"}),
    SinkKind.ORM_QUERY: frozenset({"CWE-564", "CWE-89"}),
    SinkKind.OS_COMMAND: frozenset({"CWE-77", "CWE-78"}),
    SinkKind.NOSQL_QUERY: frozenset({"CWE-943"}),
    SinkKind.LDAP_OR_XPATH: frozenset({"CWE-90", "CWE-91", "CWE-643"}),
    SinkKind.TEMPLATE_RENDER: frozenset({"CWE-1336"}),
    SinkKind.CODE_EVAL: frozenset({"CWE-94", "CWE-95", "CWE-917"}),
    SinkKind.HTML_OUTPUT: frozenset(),
    SinkKind.PATH_ACCESS: frozenset(),
}


# ---------------------------------------------------------------------------
# 4. Control-Plane: CorrelationTrustPolicy Models
# ---------------------------------------------------------------------------


class ApprovedRuleSpec(BaseModel):
    """Specification of an approved Semgrep rule within an approved ruleset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(min_length=1)
    mode: RuleMode = RuleMode.TAINT
    sink_kind: SinkKind
    subtype: InjectionSubtype
    cwe_ids: frozenset[CweId]


class ApprovedRulesetEntry(BaseModel):
    """Approved local ruleset registered by policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ruleset_id: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    review_ref: str = Field(min_length=1)
    rules: tuple[ApprovedRuleSpec, ...] = ()


PINNED_CLOUDFLARE_RULESET_SHA256 = (
    "11923c354378d4977056f74072d780cc3b5639cfb85b00f404dd10a144166f2e"
)

REVIEWED_CLOUDFLARE_RULESET_ENTRY = ApprovedRulesetEntry(
    ruleset_id="rules/cloudflare",
    sha256=PINNED_CLOUDFLARE_RULESET_SHA256,
    review_ref="SECURITY-REVIEW-2026-M2-T03C",
    rules=(
        ApprovedRuleSpec(
            rule_id="cloudflare-workers.tainted-code-injection",
            mode=RuleMode.TAINT,
            sink_kind=SinkKind.CODE_EVAL,
            subtype=InjectionSubtype.CODE_INJECTION,
            cwe_ids=frozenset({CweId("CWE-94")}),
        ),
        ApprovedRuleSpec(
            rule_id="cloudflare-workers.tainted-command-injection",
            mode=RuleMode.TAINT,
            sink_kind=SinkKind.OS_COMMAND,
            subtype=InjectionSubtype.OS_COMMAND_INJECTION,
            cwe_ids=frozenset({CweId("CWE-78")}),
        ),
        ApprovedRuleSpec(
            rule_id="cloudflare-workers.tainted-d1-sql-injection",
            mode=RuleMode.TAINT,
            sink_kind=SinkKind.SQL_QUERY,
            subtype=InjectionSubtype.SQL_INJECTION,
            cwe_ids=frozenset({CweId("CWE-89")}),
        ),
    ),
)


class TrustedRouteProducer(BaseModel):
    """Registered trusted producer capable of emitting verified RouteHandlerBinding artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    producer_id: str = Field(min_length=1)
    approved_methods: frozenset[str]
    approved_method_digests: frozenset[str]
    review_ref: str = Field(min_length=1)


class ApprovedVulnerableApiEntry(BaseModel):
    """Curated mapping linking an approved Semgrep rule to a specific CVE."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: CveId
    technology_name: str = Field(min_length=1)
    ruleset_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    rule_ids: frozenset[str]
    review_ref: str = Field(min_length=1)
    advisory_ref: str = Field(min_length=1)
    rationale: str = Field(min_length=5)


def _compute_policy_fingerprint(
    rulesets: tuple[ApprovedRulesetEntry, ...],
    producers: tuple[TrustedRouteProducer, ...],
    vulnerable_apis: tuple[ApprovedVulnerableApiEntry, ...],
) -> str:
    """Compute deterministic SHA-256 fingerprint of the trust policy configuration."""
    canonical_dict = {
        "rulesets": [
            {
                "id": r.ruleset_id,
                "sha256": r.sha256.lower(),
                "review_ref": r.review_ref,
                "rules": sorted(
                    [
                        {
                            "rule_id": rule.rule_id,
                            "mode": rule.mode.value,
                            "sink_kind": rule.sink_kind.value,
                            "subtype": rule.subtype.value,
                            "cwe_ids": sorted(str(c) for c in rule.cwe_ids),
                        }
                        for rule in r.rules
                    ],
                    key=lambda x: x["rule_id"],
                ),
            }
            for r in sorted(rulesets, key=lambda x: x.ruleset_id)
        ],
        "producers": [
            {
                "id": p.producer_id,
                "methods": sorted(p.approved_methods),
                "digests": sorted(p.approved_method_digests),
                "review_ref": p.review_ref,
            }
            for p in sorted(producers, key=lambda x: x.producer_id)
        ],
        "vulnerable_apis": [
            {
                "cve_id": v.cve_id,
                "tech": v.technology_name.casefold().strip(),
                "ruleset_sha256": v.ruleset_sha256.lower(),
                "rule_ids": sorted(v.rule_ids),
                "review_ref": v.review_ref,
                "advisory_ref": v.advisory_ref,
            }
            for v in sorted(vulnerable_apis, key=lambda x: (x.cve_id, x.technology_name))
        ],
    }
    dumped = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


class CorrelationTrustPolicy(BaseModel):
    """Control-plane policy defining approved registries and trusted producers.

    All registries are strictly empty by default in MVP.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    approved_rulesets: tuple[ApprovedRulesetEntry, ...] = ()
    trusted_route_producers: tuple[TrustedRouteProducer, ...] = ()
    approved_vulnerable_apis: tuple[ApprovedVulnerableApiEntry, ...] = ()
    fingerprint: str = ""

    @model_validator(mode="before")
    @classmethod
    def enforce_invariants_and_fingerprint(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        rulesets = tuple(data.get("approved_rulesets") or ())
        producers = tuple(data.get("trusted_route_producers") or ())
        apis = tuple(data.get("approved_vulnerable_apis") or ())

        # Index approved rules
        known_rules: dict[str, set[str]] = {}
        for rs in rulesets:
            rs_obj = rs if isinstance(rs, ApprovedRulesetEntry) else ApprovedRulesetEntry(**rs)
            digest = rs_obj.sha256.lower()
            rule_set = known_rules.setdefault(digest, set())
            for rule in rs_obj.rules:
                rule_set.add(rule.rule_id)

        # Cross-validate vulnerable api entries
        for api in apis:
            api_obj = (
                api
                if isinstance(api, ApprovedVulnerableApiEntry)
                else ApprovedVulnerableApiEntry(**api)
            )
            r_digest = api_obj.ruleset_sha256.lower()
            if r_digest not in known_rules:
                raise CorrelationTrustPolicyError(
                    f"VulnerableApiEntry {api_obj.cve_id} references unapproved "
                    f"ruleset digest {r_digest}"
                )
            missing = set(api_obj.rule_ids) - known_rules[r_digest]
            if missing:
                raise CorrelationTrustPolicyError(
                    f"VulnerableApiEntry {api_obj.cve_id} references rule(s) {sorted(missing)} "
                    f"not in ruleset {r_digest}"
                )

        computed_fp = _compute_policy_fingerprint(
            tuple(
                r if isinstance(r, ApprovedRulesetEntry) else ApprovedRulesetEntry(**r)
                for r in rulesets
            ),
            tuple(
                p if isinstance(p, TrustedRouteProducer) else TrustedRouteProducer(**p)
                for p in producers
            ),
            tuple(
                a if isinstance(a, ApprovedVulnerableApiEntry) else ApprovedVulnerableApiEntry(**a)
                for a in apis
            ),
        )
        data_copy = dict(data)
        data_copy["fingerprint"] = computed_fp
        return data_copy


DEFAULT_CORRELATION_TRUST_POLICY = CorrelationTrustPolicy()


# ---------------------------------------------------------------------------
# 5. Data-Plane & Diagnostic Models
# ---------------------------------------------------------------------------


class RouteBindingArtifactRef(BaseModel):
    """Data-plane reference to a RouteHandlerBinding artifact and manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_ref: EvidenceId
    manifest: ArtifactManifest


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


# ---------------------------------------------------------------------------
# 6. Extraction & Classification Logic
# ---------------------------------------------------------------------------


def classify_injection_sink(
    sink: SinkCandidate,
    manifest: ArtifactManifest,
    evidence_record: EvidenceArtifactRecord,
    metadata: SinkCorrelationMetadata | None,
    *,
    request: Module2AnalysisRequest,
    trust_policy: CorrelationTrustPolicy,
) -> InjectionSinkScope:
    """Evaluate a SinkCandidate along scope, rule provenance, and taint trust axes."""
    sink_id = sink.sink_id

    # 1. Verify evidence integrity
    if not verify_sink_evidence_integrity(evidence_record, manifest):
        return InjectionSinkScope(
            sink_id=sink_id,
            scope_status=InjectionScopeStatus.EXCLUDED,
            scope_basis="INTEGRITY_CHECK",
            rule_provenance=RuleProvenanceStatus.CONFLICT,
            flow_trust=FlowTrust.CONFLICT,
            reason="Evidence integrity verification failed",
        )

    # 2. Check hard excluded sink kinds
    if sink.sink_kind in {SinkKind.HTML_OUTPUT, SinkKind.PATH_ACCESS}:
        return InjectionSinkScope(
            sink_id=sink_id,
            scope_status=InjectionScopeStatus.EXCLUDED,
            scope_basis="SINK_KIND",
            rule_provenance=RuleProvenanceStatus.UNVERIFIED,
            flow_trust=FlowTrust.PATTERN_ONLY,
            reason=f"SinkKind {sink.sink_kind.value} is outside OWASP A05: Injection scope",
        )

    # Extract manifest CWEs
    manifest_cwes = set()
    manifest_meta = manifest.metadata or {}
    meta_cwes = manifest_meta.get("cwe_ids")
    if isinstance(meta_cwes, list):
        manifest_cwes.update(str(c) for c in meta_cwes)
    if metadata:
        manifest_cwes.update(str(c) for c in metadata.cwe_ids)

    # Check excluded CWEs
    if any(c in EXCLUDED_CWES for c in manifest_cwes):
        return InjectionSinkScope(
            sink_id=sink_id,
            scope_status=InjectionScopeStatus.EXCLUDED,
            scope_basis="EXCLUDED_CWES",
            rule_provenance=RuleProvenanceStatus.UNVERIFIED,
            flow_trust=FlowTrust.PATTERN_ONLY,
            reason=(
                f"Sink finding contains excluded CWE(s): {sorted(manifest_cwes & EXCLUDED_CWES)}"
            ),
        )

    # 3. Rule Provenance Verification
    prov = evidence_record.provenance or {}
    ruleset_sha256 = str(prov.get("ruleset_sha256") or "").lower().strip()
    exec_ref = str(evidence_record.execution_ref or "").strip()
    source_repo_ref = str(prov.get("source_repository_ref") or "").strip()
    source_rev = str(prov.get("source_revision") or "").strip()
    source_tree_sha256 = str(prov.get("source_tree_sha256") or "").strip()

    all_rule_ids = set()
    if metadata:
        all_rule_ids.update(metadata.all_rule_ids)
    all_rule_ids.add(sink.rule_id)

    # Match approved ruleset
    approved_rs = None
    for rs in trust_policy.approved_rulesets:
        if rs.sha256.lower() == ruleset_sha256:
            approved_rs = rs
            break

    provenance_gaps: list[str] = []
    if not ruleset_sha256:
        provenance_gaps.append("MISSING_RULESET_SHA256")
    elif approved_rs is None:
        provenance_gaps.append(f"UNAPPROVED_RULESET_DIGEST:{ruleset_sha256}")

    if not exec_ref:
        provenance_gaps.append("MISSING_EXECUTION_REF")

    scope_rules = request.target_model.scope_rules
    approved_repo = scope_rules.source_repository_ref if scope_rules else None
    if not source_repo_ref:
        provenance_gaps.append("MISSING_SOURCE_REPO_REF")
    elif approved_repo and normalize_sink_file_path(source_repo_ref) != normalize_sink_file_path(
        approved_repo
    ):
        provenance_gaps.append("REPO_REF_MISMATCH")

    if not source_rev:
        provenance_gaps.append("MISSING_SOURCE_REVISION")

    matched_specs: dict[str, ApprovedRuleSpec] = {}
    if approved_rs is not None:
        rules_by_id = {r.rule_id: r for r in approved_rs.rules}
        for rid in all_rule_ids:
            if rid in rules_by_id:
                matched_specs[rid] = rules_by_id[rid]
            else:
                provenance_gaps.append(f"UNAPPROVED_RULE:{rid}")

    rule_prov_status = (
        RuleProvenanceStatus.VERIFIED
        if approved_rs is not None and not provenance_gaps
        else RuleProvenanceStatus.UNVERIFIED
    )

    # 4. Scope and Subtype Resolution
    target_subtype: InjectionSubtype | None = None
    scope_status = InjectionScopeStatus.UNKNOWN
    scope_basis = "UNRESOLVED"
    corrob_cwes: list[CweId] = []

    if rule_prov_status == RuleProvenanceStatus.VERIFIED:
        # Grounded in policy specs
        primary_spec = matched_specs.get(sink.rule_id)
        if primary_spec:
            target_subtype = primary_spec.subtype
            corrob_cwes = sorted(primary_spec.cwe_ids)
            scope_status = InjectionScopeStatus.ALLOWED
            scope_basis = "APPROVED_REGISTRY"
    else:
        # Fallback to manifest CWEs
        allowed_cwes = SINK_KIND_INJECTION_CWES.get(sink.sink_kind, frozenset())
        matched_manifest_cwes = manifest_cwes & allowed_cwes
        if matched_manifest_cwes:
            # Map subtype
            sample_cwe = sorted(matched_manifest_cwes)[0]
            if sample_cwe in DIRECT_INJECTION_CWES:
                target_subtype = DIRECT_INJECTION_CWES[sample_cwe]
                corrob_cwes = [CweId(c) for c in sorted(matched_manifest_cwes)]
                scope_status = InjectionScopeStatus.ALLOWED
                scope_basis = "MANIFEST_CWE_ONLY"
            elif sink.sink_kind == SinkKind.ORM_QUERY:
                target_subtype = InjectionSubtype.ORM_QUERY_INJECTION
                corrob_cwes = [CweId(c) for c in sorted(matched_manifest_cwes)]
                scope_status = InjectionScopeStatus.ALLOWED
                scope_basis = "MANIFEST_CWE_ONLY"
        elif not manifest_cwes:
            scope_status = InjectionScopeStatus.UNKNOWN
            scope_basis = "KEYWORD_ONLY_CLASSIFICATION"

    # 5. Flow Trust Resolution
    manifest_content = manifest.content or "{}"
    has_steps = False
    try:
        parsed_payload = json.loads(manifest_content)
        dataflow_steps = parsed_payload.get("dataflow_steps") or []
        has_steps = bool(dataflow_steps)
    except Exception:
        has_steps = bool(sink.dataflow_steps)

    if rule_prov_status == RuleProvenanceStatus.VERIFIED:
        primary_spec = matched_specs.get(sink.rule_id)
        if (
            primary_spec
            and primary_spec.mode == RuleMode.SEARCH
            and (sink.has_static_taint_flow or has_steps)
        ):
            flow_trust = FlowTrust.CONFLICT
        elif (
            primary_spec
            and primary_spec.mode == RuleMode.TAINT
            and sink.has_static_taint_flow
            and has_steps
        ):
            flow_trust = FlowTrust.TRUSTED_TAINT
        else:
            flow_trust = FlowTrust.PATTERN_ONLY
    else:
        if sink.has_static_taint_flow and has_steps:
            flow_trust = FlowTrust.UNTRUSTED_TAINT
        else:
            flow_trust = FlowTrust.PATTERN_ONLY

    return InjectionSinkScope(
        sink_id=sink_id,
        scope_status=scope_status,
        scope_basis=scope_basis,
        subtype=target_subtype,
        corroborating_cwe_ids=tuple(corrob_cwes),
        rule_provenance=rule_prov_status,
        provenance_gaps=tuple(sorted(provenance_gaps)),
        flow_trust=flow_trust,
        source_revision=source_rev or None,
        source_tree_sha256=source_tree_sha256 or None,
        source_repository_ref=source_repo_ref or None,
        reason=(
            f"Evaluated sink {sink_id}: scope={scope_status.value} ({scope_basis}), "
            f"provenance={rule_prov_status.value}, flow_trust={flow_trust.value}"
        ),
    )


# ---------------------------------------------------------------------------
# 7. Route Binding & Accessor Parsers
# ---------------------------------------------------------------------------

_FLASK_ARGS_RE = re.compile(
    r"""request\.(?:args|form|cookies|headers|view_args)(?:\.get\(|\[)\s*['"]([A-Za-z0-9_-]+)['"]"""
)
_FLASK_JSON_RE = re.compile(
    r"""(?:request\.json|request\.get_json\(\))(?:\.get\(|\[)\s*['"]([A-Za-z0-9_-]+)['"]"""
)
_DJANGO_GET_POST_RE = re.compile(
    r"""request\.(?:GET|POST|COOKIES)(?:\.get\(|\[)\s*['"]([A-Za-z0-9_-]+)['"]"""
)
_DJANGO_META_RE = re.compile(r"""request\.META\[\s*['"]HTTP_([A-Za-z0-9_]+)['"]\s*\]""")
_EXPRESS_PROP_RE = re.compile(
    r"""req\.(query|params|cookies|headers|body)(?:\.([A-Za-z0-9_]+)|\[\s*['"]([A-Za-z0-9_-]+)['"]\s*\])"""
)
_EXPRESS_GET_RE = re.compile(r"""req\.get\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)""")
_FETCH_SEARCH_PARAMS_RE = re.compile(
    r"""(?:\b[A-Za-z_$][\w$]*\.)?searchParams\.get\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)"""
)
_FETCH_FORM_DATA_RE = re.compile(
    r"""\b(?:formData|form)\.get\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)"""
)
_FETCH_HEADERS_RE = re.compile(
    r"""(?:\b(?:request|req)\.)?headers\.get\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)"""
)
_JS_BODY_PROP_RE = re.compile(
    r"""\b(?:body|data|payload)(?:\.([A-Za-z0-9_]+)|\[\s*['"]([A-Za-z0-9_-]+)['"]\s*\])"""
)
_DYNAMIC_ACCESSOR_RE = re.compile(
    r"""(?x)
    request\.(?:args|form|values)\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]
    | (?:\b[A-Za-z_$][\w$]*\.)?searchParams\.get\(\s*[A-Za-z_$][\w$]*\s*\)
    | \b(?:formData|form)\.get\(\s*[A-Za-z_$][\w$]*\s*\)
    | (?:\b(?:request|req)\.)?headers\.get\(\s*[A-Za-z_$][\w$]*\s*\)
    | \b(?:await\s+)?(?:request|req)\.(?:json|text|formData)\(\)
"""
)


def parse_taint_source_accessor(snippet: str | None) -> TaintSourceAccessor:
    """Parse a taint source snippet for input location and parameter name using strict grammar."""
    if not snippet or not snippet.strip():
        return TaintSourceAccessor(resolution=AccessorResolution.UNSUPPORTED)

    clean_snip = snippet.strip()
    if "<redacted>" in clean_snip.lower():
        return TaintSourceAccessor(resolution=AccessorResolution.REDACTED)

    if clean_snip.endswith("...") or clean_snip.startswith("..."):
        return TaintSourceAccessor(resolution=AccessorResolution.TRUNCATED)

    # 1. Flask matchers
    m = _FLASK_ARGS_RE.search(clean_snip)
    if m:
        param = m.group(1)
        loc = InputLocation.QUERY
        if "form" in clean_snip:
            loc = InputLocation.FORM
        elif "cookies" in clean_snip:
            loc = InputLocation.COOKIE
        elif "headers" in clean_snip:
            loc = InputLocation.HEADER
        elif "view_args" in clean_snip:
            loc = InputLocation.PATH
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({loc}),
            parameter_name=param,
            pattern_id="flask_request_args",
        )

    m = _FLASK_JSON_RE.search(clean_snip)
    if m:
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.JSON_BODY}),
            parameter_name=m.group(1),
            pattern_id="flask_request_json",
        )

    # 2. Django matchers
    m = _DJANGO_GET_POST_RE.search(clean_snip)
    if m:
        param = m.group(1)
        loc = InputLocation.QUERY
        if "POST" in clean_snip:
            loc = InputLocation.FORM
        elif "COOKIES" in clean_snip:
            loc = InputLocation.COOKIE
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({loc}),
            parameter_name=param,
            pattern_id="django_request_get_post",
        )

    m = _DJANGO_META_RE.search(clean_snip)
    if m:
        header_name = m.group(1).replace("_", "-").casefold()
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.HEADER}),
            parameter_name=header_name,
            pattern_id="django_request_meta",
        )

    # 3. Express matchers
    m = _EXPRESS_PROP_RE.search(clean_snip)
    if m:
        prop_kind = m.group(1)
        param = m.group(2) or m.group(3)
        if prop_kind == "query":
            locs = frozenset({InputLocation.QUERY})
        elif prop_kind == "params":
            locs = frozenset({InputLocation.PATH})
        elif prop_kind == "cookies":
            locs = frozenset({InputLocation.COOKIE})
        elif prop_kind == "headers":
            locs = frozenset({InputLocation.HEADER})
        elif prop_kind == "body":
            locs = frozenset({InputLocation.FORM, InputLocation.JSON_BODY, InputLocation.MULTIPART})
        else:
            locs = frozenset()
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=locs,
            parameter_name=param,
            pattern_id="express_req_property",
        )

    m = _EXPRESS_GET_RE.search(clean_snip)
    if m:
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.HEADER}),
            parameter_name=m.group(1),
            pattern_id="express_req_get",
        )

    # 4. Fetch API / Cloudflare Workers matchers
    m = _FETCH_SEARCH_PARAMS_RE.search(clean_snip)
    if m:
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.QUERY}),
            parameter_name=m.group(1),
            pattern_id="fetch_search_params_get",
        )

    m = _FETCH_FORM_DATA_RE.search(clean_snip)
    if m:
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.FORM}),
            parameter_name=m.group(1),
            pattern_id="fetch_form_data_get",
        )

    m = _FETCH_HEADERS_RE.search(clean_snip)
    if m:
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.HEADER}),
            parameter_name=m.group(1),
            pattern_id="fetch_headers_get",
        )

    m = _JS_BODY_PROP_RE.search(clean_snip)
    if m:
        param = m.group(1) or m.group(2)
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.JSON_BODY}),
            parameter_name=param,
            pattern_id="js_body_property",
        )

    # Check dynamic key attempts: e.g. request.args[var], searchParams.get(var),
    # or await request.json()
    if _DYNAMIC_ACCESSOR_RE.search(clean_snip):
        return TaintSourceAccessor(resolution=AccessorResolution.DYNAMIC_KEY)

    return TaintSourceAccessor(resolution=AccessorResolution.UNSUPPORTED)


def verify_route_binding_artifact(
    artifact_ref: RouteBindingArtifactRef,
    request: Module2AnalysisRequest,
    *,
    trust_policy: CorrelationTrustPolicy,
) -> tuple[RouteHandlerBinding | None, str]:
    """Verify and derive a RouteHandlerBinding against 9 strict trust conditions."""
    manifest = artifact_ref.manifest
    evd_id = artifact_ref.evidence_ref

    # 1. Scope mode
    rules = request.target_model.scope_rules
    if rules is None or rules.testing_mode == TestingMode.BLACKBOX or not request.source_repo_path:
        return None, "BLACKBOX_OR_MISSING_SOURCE_REPO"

    # 2. Authoritative evidence record
    matched_evd = None
    for evd in request.evidence_records:
        if evd.evidence_id == evd_id:
            matched_evd = evd
            break
    if matched_evd is None or matched_evd.artifact_type != ArtifactType.SOURCE_ARTIFACT:
        return None, f"EVIDENCE_RECORD_NOT_FOUND_OR_NOT_SOURCE_ARTIFACT:{evd_id}"

    # 3. Hash and size integrity
    content = manifest.content or ""
    content_bytes = content.encode("utf-8")
    actual_hash = hashlib.sha256(content_bytes).hexdigest()
    if matched_evd.sha256_hash.lower() != actual_hash.lower():
        return None, f"HASH_MISMATCH:record={matched_evd.sha256_hash},actual={actual_hash}"
    if manifest.sha256_hash and manifest.sha256_hash.lower() != actual_hash.lower():
        return None, f"MANIFEST_HASH_MISMATCH:manifest={manifest.sha256_hash},actual={actual_hash}"

    try:
        payload = json.loads(content)
    except Exception:
        return None, "MALFORMED_JSON_CONTENT"

    if payload.get("schema") != "websecuritycheck.route_binding_artifact.v1":
        return None, f"UNSUPPORTED_SCHEMA:{payload.get('schema')}"

    # 4. Trusted producer
    producer_id = str(matched_evd.source_tool_id or "").strip()
    trusted_producer = None
    for tp in trust_policy.trusted_route_producers:
        if tp.producer_id == producer_id:
            trusted_producer = tp
            break
    if trusted_producer is None:
        return None, f"UNTRUSTED_PRODUCER:{producer_id}"

    # 5. Approved extraction method
    prov = matched_evd.provenance or {}
    method = str(prov.get("extraction_method") or "").strip()
    method_digest = str(prov.get("extraction_method_digest") or "").strip().lower()

    if method not in trusted_producer.approved_methods:
        return None, f"UNAPPROVED_EXTRACTION_METHOD:{method}"
    if method_digest not in trusted_producer.approved_method_digests:
        return None, f"UNAPPROVED_METHOD_DIGEST:{method_digest}"

    # 6. Execution reference
    exec_ref = str(matched_evd.execution_ref or "").strip()
    if not exec_ref:
        return None, "MISSING_EXECUTION_REF"

    # 7. Source repository reference
    src_repo_ref = str(prov.get("source_repository_ref") or "").strip()
    if not src_repo_ref or normalize_sink_file_path(src_repo_ref) != normalize_sink_file_path(
        rules.source_repository_ref or ""
    ):
        return None, f"SOURCE_REPO_MISMATCH:{src_repo_ref}"

    # 8. Source revision
    src_rev = str(prov.get("source_revision") or "").strip()
    if not src_rev:
        return None, "MISSING_SOURCE_REVISION"

    # 9. Endpoint matching & file span validity
    ep_id = payload.get("endpoint_id")
    method_name = str(payload.get("method") or "").upper().strip()
    path_text = str(payload.get("path") or "").strip()
    file_path = str(payload.get("file_path") or "").strip()
    start_line = payload.get("start_line")
    end_line = payload.get("end_line")

    matched_ep = None
    for ep in request.target_model.endpoints:
        if ep.endpoint_id == ep_id:
            matched_ep = ep
            break

    if matched_ep is None:
        return None, f"UNKNOWN_ENDPOINT_ID:{ep_id}"
    if matched_ep.method.upper().strip() != method_name or matched_ep.path.strip() != path_text:
        return None, f"ENDPOINT_SIGNATURE_MISMATCH:{ep_id}"

    if not is_safe_sink_path(file_path):
        return None, f"UNSAFE_FILE_PATH:{file_path}"
    if (
        not isinstance(start_line, int)
        or not isinstance(end_line, int)
        or start_line < 1
        or end_line < start_line
    ):
        return None, f"INVALID_LINE_SPAN:{start_line}-{end_line}"

    src_tree_hash = str(prov.get("source_tree_sha256") or "").strip() or None
    binding = RouteHandlerBinding(
        endpoint_id=ep_id,
        method=method_name,
        path=path_text,
        file_path=normalize_sink_file_path(file_path),
        start_line=start_line,
        end_line=end_line,
        evidence_ref=evd_id,
        execution_ref=exec_ref,
        source_revision=src_rev,
        source_tree_sha256=src_tree_hash,
        source_repository_ref=src_repo_ref or None,
    )
    return binding, "VERIFIED"


# ---------------------------------------------------------------------------
# 8. Independence Assessment
# ---------------------------------------------------------------------------


def assess_independence(
    evidence: Sequence[EvidenceArtifactRecord],
    observations: Sequence[ObservationRecord],
) -> IndependenceAssessment:
    """Evaluate whether supporting relation evidence represents truly independent executions."""
    reasons: list[str] = []

    # 1. Require execution_ref on every relation record
    for evd in evidence:
        if not evd.execution_ref or not str(evd.execution_ref).strip():
            reasons.append(f"MISSING_EXECUTION_REF:{evd.evidence_id}")
    for obs in observations:
        if not obs.execution_ref or not str(obs.execution_ref).strip():
            reasons.append(f"MISSING_EXECUTION_REF:{obs.observation_id}")

    if reasons:
        return IndependenceAssessment(
            status=IndependenceStatus.UNKNOWN,
            distinct_execution_count=0,
            reasons=tuple(sorted(reasons)),
        )

    # 2. Check for shared upstream artifact identity
    seen_hashes: dict[str, str] = {}
    seen_artifacts: dict[str, str] = {}
    for evd in evidence:
        digest = evd.sha256_hash.lower().strip()
        if digest in seen_hashes:
            reasons.append(f"SHARED_ARTIFACT_DIGEST:{evd.evidence_id}_and_{seen_hashes[digest]}")
        else:
            seen_hashes[digest] = str(evd.evidence_id)

        aref = evd.artifact_ref.strip()
        if aref in seen_artifacts:
            reasons.append(f"SHARED_ARTIFACT_REF:{evd.evidence_id}_and_{seen_artifacts[aref]}")
        else:
            seen_artifacts[aref] = str(evd.evidence_id)

    # Check observation backing evidence collision
    evd_id_set = {str(e.evidence_id) for e in evidence}
    for obs in observations:
        for ref in obs.evidence_refs:
            if str(ref) in evd_id_set:
                reasons.append(f"SHARED_BACKING_EVIDENCE:{obs.observation_id}_backs_{ref}")

    # Check distinct execution refs
    exec_refs = set()
    for evd in evidence:
        exec_refs.add(str(evd.execution_ref).strip())
    for obs in observations:
        exec_refs.add(str(obs.execution_ref).strip())

    if len(exec_refs) <= 1:
        single_ref = next(iter(exec_refs)) if exec_refs else "none"
        reasons.append(f"SINGLE_EXECUTION_REF:{single_ref}")

    # Check for shared source snapshot across SOURCE_ARTIFACT records
    # If all supporting evidence records are SOURCE_ARTIFACT and observations is empty,
    # and they share the same source snapshot
    # (source_tree_sha256 or (source_repository_ref, source_revision)),
    # then even with distinct execution_ref values, they derive from the same static snapshot
    # and must not be marked INDEPENDENT.
    if (
        evidence
        and all(evd.artifact_type == ArtifactType.SOURCE_ARTIFACT for evd in evidence)
        and not observations
    ):
        snapshots = set()
        for evd in evidence:
            prov = evd.provenance or {}
            tree_hash = prov.get("source_tree_sha256")
            repo_ref = prov.get("source_repository_ref")
            rev = prov.get("source_revision")
            snapshots.add((repo_ref, rev, tree_hash))

        if len(snapshots) == 1:
            snap = next(iter(snapshots))
            rev_label = snap[1] or snap[2] or "unknown"
            reasons.append(f"SHARED_SOURCE_SNAPSHOT:{rev_label}")

    if reasons:
        return IndependenceAssessment(
            status=IndependenceStatus.SHARED,
            distinct_execution_count=len(exec_refs),
            reasons=tuple(sorted(reasons)),
        )

    return IndependenceAssessment(
        status=IndependenceStatus.INDEPENDENT,
        distinct_execution_count=len(exec_refs),
        reasons=(),
    )


# ---------------------------------------------------------------------------
# 9. Correlation Engine Pipeline
# ---------------------------------------------------------------------------


def correlation_identity_key(
    kind: CorrelationKind,
    endpoint_id: str | None,
    location: InputLocation | None,
    parameter_name: str | None,
    sink_file_path: str | None,
    sink_start_line: int | None,
    sink_kind: SinkKind | None,
    source_file: str | None,
    source_line: int | None,
    tech_canonical_key: tuple[str, str, str] | None,
    cve_id: str | None,
    component_identity_keys: Sequence[str] = (),
) -> str:
    """Generate a canonical deterministic identity string for deduplication."""
    parts: list[str] = [kind.value]
    if kind == CorrelationKind.INPUT_SINK:
        parts.extend(
            [
                endpoint_id or "",
                location.value if location else "",
                parameter_name or "",
                sink_file_path or "",
                str(sink_start_line or 0),
                sink_kind.value if sink_kind else "",
                source_file or "",
                str(source_line or 0),
            ]
        )
    elif kind == CorrelationKind.ENDPOINT_SINK:
        parts.extend(
            [
                endpoint_id or "",
                sink_file_path or "",
                str(sink_start_line or 0),
                sink_kind.value if sink_kind else "",
                source_file or "-",
                str(source_line or 0),
            ]
        )
    elif kind == CorrelationKind.CVE_TECHNOLOGY:
        cat, name, ver = tech_canonical_key or ("", "", "")
        parts.extend([cat, name, ver, cve_id or ""])
    elif kind == CorrelationKind.SINK_CVE:
        cat, name, ver = tech_canonical_key or ("", "", "")
        parts.extend(
            [sink_file_path or "", str(sink_start_line or 0), cve_id or "", cat, name, ver]
        )
    elif kind == CorrelationKind.INPUT_SINK_CVE_CHAIN:
        parts.extend(sorted(component_identity_keys))
    return "|".join(parts)


def evaluate_correlation_confidence(
    kind: CorrelationKind,
    status: CorrelationStatus,
    *,
    base_confidence: ConfidenceLevel,
    caps: Sequence[tuple[ConfidenceLevel, str]],
) -> tuple[ConfidenceLevel, tuple[str, ...]]:
    """Determine confidence monotonically capping without ever upgrading."""
    levels = {ConfidenceLevel.LOW: 1, ConfidenceLevel.MEDIUM: 2, ConfidenceLevel.HIGH: 3}
    inv_levels = {1: ConfidenceLevel.LOW, 2: ConfidenceLevel.MEDIUM, 3: ConfidenceLevel.HIGH}

    current_val = levels[base_confidence]
    applied_caps: list[str] = []

    # PARTIAL is capped at MEDIUM
    if status == CorrelationStatus.PARTIAL and current_val > levels[ConfidenceLevel.MEDIUM]:
        current_val = levels[ConfidenceLevel.MEDIUM]
        applied_caps.append("STATUS_PARTIAL_CAP_MEDIUM")

    for cap_lvl, cap_reason in caps:
        cap_val = levels[cap_lvl]
        if current_val > cap_val:
            current_val = cap_val
            applied_caps.append(cap_reason)

    return inv_levels[current_val], tuple(applied_caps)


def correlate_evidence(
    request: Module2AnalysisRequest,
    *,
    input_result: InputExtractionResult | None = None,
    sink_result: SinkExtractionResult | None = None,
    cve_result: CVEExtractionResult | None = None,
    route_binding_artifacts: Sequence[RouteBindingArtifactRef] = (),
    scope_policy: InjectionScopePolicy | None = None,
    trust_policy: CorrelationTrustPolicy | None = None,
) -> CorrelationResult:
    """Execute deterministic 6-stage evidence correlation within A05: Injection scope."""
    policy = trust_policy or DEFAULT_CORRELATION_TRUST_POLICY
    cve_policy = scope_policy or InjectionScopePolicy()
    diagnostics: list[CorrelationDiagnostic] = []
    limitations: list[str] = []
    warnings: list[str] = []

    # Stage 1: Build Authoritative Grounding Index
    ref_index = AuthoritativeReferenceIndex.from_request(request)
    analysis_evd_map: dict[str, EvidenceArtifactRecord] = {}
    if sink_result:
        for evd in sink_result.analysis_evidence_records:
            if evd.evidence_id in ref_index.evidence_ids:
                raise CorrelationInputError(
                    f"Evidence ID collision with Module 1: {evd.evidence_id}"
                )
            analysis_evd_map[str(evd.evidence_id)] = evd

    all_valid_evd = ref_index.evidence_ids | set(analysis_evd_map.keys())
    all_valid_obs = ref_index.observation_ids

    # Filter grounded candidates
    grounded_inputs: list[InputCandidate] = []
    if input_result:
        for inp in input_result.inputs:
            if inp.endpoint_id not in ref_index.endpoint_refs:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=inp.input_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="DANGLING_ENDPOINT_REF",
                        reason=(
                            f"Input {inp.input_id} references unknown endpoint {inp.endpoint_id}"
                        ),
                    )
                )
                continue
            if not all(r in all_valid_evd for r in inp.evidence_refs) or not all(
                r in all_valid_obs for r in inp.observation_refs
            ):
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=inp.input_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="DANGLING_REFERENCE",
                        reason=(
                            f"Input {inp.input_id} has unresolvable evidence or observation refs"
                        ),
                    )
                )
                continue
            grounded_inputs.append(inp)
    else:
        limitations.append("PARTIAL_UPSTREAM_RESULTS:INPUT_EXTRACTION_SKIPPED")

    sink_manifest_map = (
        {m.artifact_ref: m for m in sink_result.artifact_manifests} if sink_result else {}
    )
    sink_metadata_map = sink_result.sink_metadata if sink_result else {}

    grounded_sinks: list[tuple[SinkCandidate, ArtifactManifest, EvidenceArtifactRecord]] = []
    if sink_result:
        for snk in sink_result.sink_candidates:
            if not snk.evidence_refs or not all(r in all_valid_evd for r in snk.evidence_refs):
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="DANGLING_REFERENCE",
                        reason=f"Sink {snk.sink_id} has unresolvable evidence refs",
                    )
                )
                continue
            evd_rec = analysis_evd_map.get(str(snk.evidence_refs[0]))
            if not evd_rec:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="MISSING_SOURCE_ARTIFACT",
                        reason=f"Sink {snk.sink_id} missing backing EvidenceArtifactRecord",
                    )
                )
                continue
            man = sink_manifest_map.get(evd_rec.artifact_ref)
            if not man:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="MISSING_MANIFEST",
                        reason=f"Sink {snk.sink_id} missing backing ArtifactManifest",
                    )
                )
                continue
            grounded_sinks.append((snk, man, evd_rec))
    else:
        limitations.append("PARTIAL_UPSTREAM_RESULTS:SINK_EXTRACTION_SKIPPED")

    grounded_cves: list[CVECandidate] = []
    if cve_result:
        for cve in cve_result.cve_candidates:
            t_key = cve.target_technology.canonical_key
            if t_key not in ref_index.technology_refs:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="TECHNOLOGY_UNGROUNDED",
                        reason=f"CVE {cve.cve_candidate_id} technology {t_key} not in TargetModel",
                    )
                )
                continue
            if not all(r in all_valid_evd for r in cve.evidence_refs) or not all(
                r in all_valid_obs for r in cve.observation_refs
            ):
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="DANGLING_REFERENCE",
                        reason=f"CVE {cve.cve_candidate_id} has unresolvable refs",
                    )
                )
                continue
            tech_supp = ref_index.technology_refs[t_key]
            cve_supp = set(cve.evidence_refs) | set(cve.observation_refs)
            if tech_supp and not (cve_supp & tech_supp):
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="TECHNOLOGY_UNGROUNDED",
                        reason=f"CVE {cve.cve_candidate_id} refs do not intersect TechnologyRecord",
                    )
                )
                continue
            grounded_cves.append(cve)
    else:
        limitations.append("PARTIAL_UPSTREAM_RESULTS:CVE_EXTRACTION_SKIPPED")

    # Stage 2: Scope & Provenance Evaluation
    sink_scopes: list[InjectionSinkScope] = []
    allowed_sinks: list[
        tuple[SinkCandidate, ArtifactManifest, EvidenceArtifactRecord, InjectionSinkScope]
    ] = []

    for snk, man, evd in grounded_sinks:
        meta = sink_metadata_map.get(snk.sink_id)
        scope_res = classify_injection_sink(
            snk, man, evd, meta, request=request, trust_policy=policy
        )
        sink_scopes.append(scope_res)
        if scope_res.scope_status == InjectionScopeStatus.ALLOWED:
            allowed_sinks.append((snk, man, evd, scope_res))
        else:
            diagnostics.append(
                CorrelationDiagnostic(
                    subject_ref=snk.sink_id,
                    stage="scope",
                    outcome="EXCLUDED"
                    if scope_res.scope_status == InjectionScopeStatus.EXCLUDED
                    else "UNRESOLVED",
                    code=scope_res.scope_basis,
                    reason=scope_res.reason,
                )
            )

    cve_meta_map = (
        {m.cve_candidate_id: m for m in cve_result.correlation_metadata} if cve_result else {}
    )
    allowed_cves: list[tuple[CVECandidate, InjectionSubtype]] = []

    for cve in grounded_cves:
        c_meta = cve_meta_map.get(cve.cve_candidate_id)
        if not c_meta:
            diagnostics.append(
                CorrelationDiagnostic(
                    subject_ref=cve.cve_candidate_id,
                    stage="scope",
                    outcome="UNRESOLVED",
                    code="CVE_METADATA_MISSING",
                    reason=f"CVE {cve.cve_candidate_id} missing correlation metadata",
                )
            )
            continue

        # Re-verify scope via InjectionScopePolicy
        trusted = cve_policy.trusted_classification(cve.cve_id)
        if trusted:
            if cve.cwe_id and cve.cwe_id in trusted.expected_cwe_ids:
                allowed_cves.append((cve, trusted.canonical_subtype))
            else:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="scope",
                        outcome="EXCLUDED",
                        code="CVE_SCOPE_REVERIFICATION_FAILED",
                        reason=f"CVE {cve.cve_id} failed trusted classification CWE check",
                    )
                )
        else:
            if cve.cwe_id and cve.cwe_id in DIRECT_INJECTION_CWES:
                st = DIRECT_INJECTION_CWES[cve.cwe_id]
                if st == c_meta.injection_subtype:
                    allowed_cves.append((cve, st))
                else:
                    diagnostics.append(
                        CorrelationDiagnostic(
                            subject_ref=cve.cve_candidate_id,
                            stage="scope",
                            outcome="EXCLUDED",
                            code="CVE_SCOPE_REVERIFICATION_FAILED",
                            reason=(
                                f"Subtype conflict: CWE mapped {st} vs "
                                f"meta {c_meta.injection_subtype}"
                            ),
                        )
                    )
            else:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="scope",
                        outcome="EXCLUDED",
                        code="CVE_SCOPE_REVERIFICATION_FAILED",
                        reason=f"CWE {cve.cwe_id} not in direct injection allowlist",
                    )
                )

    # Stage 3: Route Binding Verification & Input/Endpoint-Sink Correlation
    verified_bindings: list[RouteHandlerBinding] = []
    if (
        request.target_model.scope_rules
        and request.target_model.scope_rules.testing_mode == TestingMode.BLACKBOX
    ):
        limitations.append("BLACKBOX_NO_SOURCE_CORRELATION")
    else:
        for r_art in route_binding_artifacts:
            binding, reason = verify_route_binding_artifact(r_art, request, trust_policy=policy)
            if binding:
                verified_bindings.append(binding)
            else:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=r_art.evidence_ref,
                        stage="route_binding",
                        outcome="EXCLUDED",
                        code="ROUTE_BINDING_REJECTED",
                        reason=reason,
                    )
                )

    # Index verified bindings by file_path
    bindings_by_file: dict[str, list[RouteHandlerBinding]] = {}
    for b in verified_bindings:
        bindings_by_file.setdefault(b.file_path, []).append(b)

    # Index inputs by (endpoint_id, location, normalized_name)
    inputs_by_key: dict[tuple[str, InputLocation, str], list[InputCandidate]] = {}
    for inp in grounded_inputs:
        norm_name = normalize_parameter_name(inp.parameter_name, inp.location)
        inputs_by_key.setdefault((inp.endpoint_id, inp.location, norm_name), []).append(inp)

    # Evaluate each allowed sink against verified bindings
    candidate_records: list[CorrelationRecord] = []
    endpoint_map = {ep.endpoint_id: ep for ep in request.target_model.endpoints}
    all_request_evd = {e.evidence_id: e for e in request.evidence_records}
    all_request_obs = {o.observation_id: o for o in request.observations}

    for snk, man, evd, scope_res in allowed_sinks:
        meta = sink_metadata_map.get(snk.sink_id)
        taint_sources = meta.all_taint_sources if meta and meta.all_taint_sources else []
        if (
            not taint_sources
            and meta
            and meta.taint_source_snippet
            and meta.taint_source_file
            and meta.taint_source_line
        ):
            taint_sources = [
                f"{meta.taint_source_file}:{meta.taint_source_line}: {meta.taint_source_snippet}"
            ]

        # Try to correlate taint sources
        correlated_any = False
        for ts_entry in taint_sources:
            # Parse entry "file:line: snippet"
            parts = ts_entry.split(":", 2)
            if len(parts) < 3:
                continue
            ts_file = normalize_sink_file_path(parts[0].strip())
            try:
                ts_line = int(parts[1].strip())
            except ValueError:
                continue
            ts_snippet = parts[2].strip()

            matching_bindings = [
                b
                for b in bindings_by_file.get(ts_file, [])
                if b.start_line <= ts_line <= b.end_line
            ]

            if not matching_bindings:
                continue

            if len(matching_bindings) > 1:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="input_sink",
                        outcome="UNRESOLVED",
                        code="AMBIGUOUS_ROUTE_BINDING",
                        reason=f"Taint source {ts_file}:{ts_line} intersects multiple bindings",
                    )
                )
                continue

            matched_b = matching_bindings[0]

            # Check revision alignment
            rev_mismatch = False
            if (
                not scope_res.source_revision
                or scope_res.source_revision != matched_b.source_revision
            ) or (
                scope_res.source_tree_sha256
                and matched_b.source_tree_sha256
                and scope_res.source_tree_sha256 != matched_b.source_tree_sha256
            ):
                rev_mismatch = True

            if rev_mismatch:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="input_sink",
                        outcome="UNRESOLVED",
                        code="REVISION_UNLINKED",
                        reason=(
                            f"Revision mismatch between sink ({scope_res.source_revision}) "
                            f"and binding ({matched_b.source_revision})"
                        ),
                    )
                )
                continue

            # Parse accessor
            accessor = parse_taint_source_accessor(ts_snippet)
            binding_evd = all_request_evd.get(matched_b.evidence_ref)
            rel_evd = [evd]
            if binding_evd:
                rel_evd.append(binding_evd)

            ind_assess = assess_independence(rel_evd, [])
            caps: list[tuple[ConfidenceLevel, str]] = []
            if ind_assess.status != IndependenceStatus.INDEPENDENT:
                caps.append((ConfidenceLevel.MEDIUM, f"INDEPENDENCE_{ind_assess.status.value}"))

            matched_ep = endpoint_map.get(matched_b.endpoint_id)
            if matched_ep and not matched_ep.runtime_observed:
                caps.append((ConfidenceLevel.MEDIUM, "ENDPOINT_NOT_RUNTIME_OBSERVED"))

            if man.redaction_applied or man.truncated:
                caps.append((ConfidenceLevel.MEDIUM, "MANIFEST_REDACTION_OR_TRUNCATION"))

            # Determine whether INPUT_SINK or ENDPOINT_SINK
            if (
                scope_res.rule_provenance == RuleProvenanceStatus.VERIFIED
                and scope_res.flow_trust == FlowTrust.TRUSTED_TAINT
                and accessor.resolution == AccessorResolution.RESOLVED
                and accessor.parameter_name
            ):
                candidate_inputs: list[InputCandidate] = []
                for loc in accessor.locations:
                    norm_p = normalize_parameter_name(accessor.parameter_name, loc)
                    candidate_inputs.extend(
                        inputs_by_key.get((matched_b.endpoint_id, loc, norm_p), [])
                    )

                if len(candidate_inputs) == 1:
                    matched_inp = candidate_inputs[0]
                    conf, applied_caps = evaluate_correlation_confidence(
                        CorrelationKind.INPUT_SINK,
                        CorrelationStatus.VERIFIED,
                        base_confidence=ConfidenceLevel.HIGH,
                        caps=[(snk.confidence, "SINK_CONFIDENCE_CAP"), *caps],
                    )

                    key = correlation_identity_key(
                        CorrelationKind.INPUT_SINK,
                        matched_b.endpoint_id,
                        matched_inp.location,
                        normalize_parameter_name(matched_inp.parameter_name, matched_inp.location),
                        snk.file_path,
                        snk.start_line,
                        snk.sink_kind,
                        ts_file,
                        ts_line,
                        None,
                        None,
                    )
                    cor_id = CorrelationId(
                        f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
                    )
                    assert scope_res.subtype is not None

                    rec = CorrelationRecord(
                        correlation_id=cor_id,
                        kind=CorrelationKind.INPUT_SINK,
                        status=CorrelationStatus.VERIFIED,
                        confidence=conf,
                        injection_subtype=scope_res.subtype,
                        vulnerability_category=SUBTYPE_TO_CATEGORY.get(scope_res.subtype),
                        endpoint_id=matched_b.endpoint_id,
                        input_ref=matched_inp.input_id,
                        sink_ref=snk.sink_id,
                        sink_relationship=SinkRelationship.STATIC_TAINT_FLOW_FOUND,
                        existence_evidence_refs=tuple(
                            sorted(set(snk.evidence_refs) | set(matched_inp.evidence_refs))
                        ),
                        existence_observation_refs=tuple(sorted(set(matched_inp.observation_refs))),
                        relation_evidence_refs=tuple(
                            sorted({EvidenceId(str(e.evidence_id)) for e in rel_evd})
                        ),
                        relation_observation_refs=(),
                        independent_relation_source_count=ind_assess.distinct_execution_count,
                        independence=ind_assess,
                        confidence_caps_applied=applied_caps,
                        rationale=(
                            f"Verified static taint flow from {matched_b.endpoint_id} parameter "
                            f"'{matched_inp.parameter_name}' to sink {snk.sink_id} "
                            f"({snk.file_path}:{snk.start_line})"
                        ),
                    )
                    candidate_records.append(rec)
                    correlated_any = True
                    continue

            # Fallback to ENDPOINT_SINK PARTIAL
            conf, applied_caps = evaluate_correlation_confidence(
                CorrelationKind.ENDPOINT_SINK,
                CorrelationStatus.PARTIAL,
                base_confidence=ConfidenceLevel.MEDIUM
                if scope_res.flow_trust == FlowTrust.TRUSTED_TAINT
                else ConfidenceLevel.LOW,
                caps=[(snk.confidence, "SINK_CONFIDENCE_CAP"), *caps],
            )
            key = correlation_identity_key(
                CorrelationKind.ENDPOINT_SINK,
                matched_b.endpoint_id,
                None,
                None,
                snk.file_path,
                snk.start_line,
                snk.sink_kind,
                ts_file,
                ts_line,
                None,
                None,
            )
            cor_id = CorrelationId(f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}")
            assert scope_res.subtype is not None

            missing_links = []
            if accessor.resolution != AccessorResolution.RESOLVED:
                missing_links.append(f"ACCESSOR_{accessor.resolution.value}")
            else:
                missing_links.append("AMBIGUOUS_INPUT_MAPPING")

            rec = CorrelationRecord(
                correlation_id=cor_id,
                kind=CorrelationKind.ENDPOINT_SINK,
                status=CorrelationStatus.PARTIAL,
                confidence=conf,
                injection_subtype=scope_res.subtype,
                vulnerability_category=SUBTYPE_TO_CATEGORY.get(scope_res.subtype),
                endpoint_id=matched_b.endpoint_id,
                sink_ref=snk.sink_id,
                sink_relationship=SinkRelationship.STATIC_TAINT_FLOW_FOUND
                if snk.has_static_taint_flow
                else SinkRelationship.UNVERIFIED_STATIC_SINK,
                existence_evidence_refs=tuple(sorted(set(snk.evidence_refs))),
                relation_evidence_refs=tuple(
                    sorted({EvidenceId(str(e.evidence_id)) for e in rel_evd})
                ),
                independent_relation_source_count=ind_assess.distinct_execution_count,
                independence=ind_assess,
                missing_links=tuple(missing_links),
                confidence_caps_applied=applied_caps,
                rationale=(
                    f"Partial endpoint correlation between {matched_b.endpoint_id} "
                    f"and sink {snk.sink_id}; input parameter unresolved "
                    f"({accessor.resolution.value})"
                ),
            )
            candidate_records.append(rec)
            correlated_any = True

        if not correlated_any:
            # Fallback for sinks inside an unambiguous route handler without taint trace
            # (e.g. Semgrep OSS runs where dataflow trace is unavailable or pattern mode)
            snk_file = normalize_sink_file_path(snk.file_path)
            matching_bindings = [
                b
                for b in bindings_by_file.get(snk_file, [])
                if b.start_line <= snk.start_line <= b.end_line
            ]

            if len(matching_bindings) > 1:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="input_sink",
                        outcome="UNRESOLVED",
                        code="AMBIGUOUS_ROUTE_BINDING",
                        reason=(
                            f"Sink {snk.file_path}:{snk.start_line} "
                            "intersects multiple bindings"
                        ),
                    )
                )
            elif len(matching_bindings) == 1:
                matched_b = matching_bindings[0]
                # Check revision alignment
                rev_mismatch = False
                if (
                    scope_res.source_revision
                    and matched_b.source_revision
                    and scope_res.source_revision != matched_b.source_revision
                ) or (
                    scope_res.source_tree_sha256
                    and matched_b.source_tree_sha256
                    and scope_res.source_tree_sha256 != matched_b.source_tree_sha256
                ):
                    rev_mismatch = True
                    diagnostics.append(
                        CorrelationDiagnostic(
                            subject_ref=snk.sink_id,
                            stage="input_sink",
                            outcome="UNRESOLVED",
                            code="REVISION_UNLINKED",
                            reason=(
                                f"Revision/tree mismatch between sink "
                            f"({scope_res.source_revision}, "
                                f"{scope_res.source_tree_sha256}) and binding "
                                f"({matched_b.source_revision}, {matched_b.source_tree_sha256})"
                            ),
                        )
                    )

                if not rev_mismatch and scope_res.rule_provenance == RuleProvenanceStatus.VERIFIED:
                    binding_evd = all_request_evd.get(matched_b.evidence_ref)
                    rel_evd = [evd]
                    if binding_evd:
                        rel_evd.append(binding_evd)

                    ind_assess = assess_independence(rel_evd, [])
                    caps: list[tuple[ConfidenceLevel, str]] = []
                    if ind_assess.status != IndependenceStatus.INDEPENDENT:
                        caps.append(
                            (ConfidenceLevel.MEDIUM, f"INDEPENDENCE_{ind_assess.status.value}")
                        )

                    matched_ep = endpoint_map.get(matched_b.endpoint_id)
                    if matched_ep and not matched_ep.runtime_observed:
                        caps.append((ConfidenceLevel.MEDIUM, "ENDPOINT_NOT_RUNTIME_OBSERVED"))

                    if man.redaction_applied or man.truncated:
                        caps.append((ConfidenceLevel.MEDIUM, "MANIFEST_REDACTION_OR_TRUNCATION"))

                    conf, applied_caps = evaluate_correlation_confidence(
                        CorrelationKind.ENDPOINT_SINK,
                        CorrelationStatus.PARTIAL,
                        base_confidence=ConfidenceLevel.LOW,
                        caps=[(snk.confidence, "SINK_CONFIDENCE_CAP"), *caps],
                    )

                    key = correlation_identity_key(
                        CorrelationKind.ENDPOINT_SINK,
                        matched_b.endpoint_id,
                        None,
                        None,
                        snk.file_path,
                        snk.start_line,
                        snk.sink_kind,
                        None,
                        None,
                        None,
                        None,
                    )
                    cor_id = CorrelationId(
                        f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
                    )
                    assert scope_res.subtype is not None

                    rec = CorrelationRecord(
                        correlation_id=cor_id,
                        kind=CorrelationKind.ENDPOINT_SINK,
                        status=CorrelationStatus.PARTIAL,
                        confidence=conf,
                        injection_subtype=scope_res.subtype,
                        vulnerability_category=SUBTYPE_TO_CATEGORY.get(scope_res.subtype),
                        endpoint_id=matched_b.endpoint_id,
                        sink_ref=snk.sink_id,
                        sink_relationship=SinkRelationship.UNVERIFIED_STATIC_SINK,
                        existence_evidence_refs=tuple(sorted(set(snk.evidence_refs))),
                        relation_evidence_refs=tuple(
                            sorted({EvidenceId(str(e.evidence_id)) for e in rel_evd})
                        ),
                        independent_relation_source_count=ind_assess.distinct_execution_count,
                        independence=ind_assess,
                        missing_links=("MISSING_DATAFLOW_TRACE",),
                        confidence_caps_applied=applied_caps,
                        rationale=(
                            f"Verified sink {snk.sink_id} falls within route "
                            f"{matched_b.endpoint_id} handler ({matched_b.file_path}:"
                            f"{matched_b.start_line}-{matched_b.end_line}) but lacks dataflow trace"
                        ),
                    )
                    candidate_records.append(rec)
                    correlated_any = True

            if not correlated_any:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="input_sink",
                        outcome="UNRESOLVED",
                        code="NO_MATCHING_ROUTE_BINDING",
                        reason=f"Sink {snk.sink_id} has no matching verified route-handler binding",
                    )
                )

    # Stage 4: CVE-Technology Correlation
    cve_tech_records: list[CorrelationRecord] = []
    for cve, subtype in allowed_cves:
        t_key = cve.target_technology.canonical_key
        tech_supp = ref_index.technology_refs.get(t_key, frozenset())
        cve_supp = set(cve.evidence_refs) | set(cve.observation_refs)
        intersected = cve_supp & tech_supp

        rel_evd = [all_request_evd[e] for e in intersected if e in all_request_evd]
        rel_obs = [all_request_obs[o] for o in intersected if o in all_request_obs]

        ind_assess = assess_independence(rel_evd, rel_obs)
        caps = []
        if ind_assess.status != IndependenceStatus.INDEPENDENT:
            caps.append((ConfidenceLevel.MEDIUM, f"INDEPENDENCE_{ind_assess.status.value}"))

        c_meta = cve_meta_map.get(cve.cve_candidate_id)
        preconditions = c_meta.environmental_preconditions if c_meta else ()
        if preconditions:
            caps.append((ConfidenceLevel.MEDIUM, "ENVIRONMENTAL_PRECONDITIONS_PRESENT"))

        if c_meta and c_meta.product_match_kind == ProductMatchKind.ALIAS:
            status = CorrelationStatus.PARTIAL
        else:
            status = CorrelationStatus.VERIFIED

        conf, applied_caps = evaluate_correlation_confidence(
            CorrelationKind.CVE_TECHNOLOGY,
            status,
            base_confidence=cve.confidence,
            caps=caps,
        )

        # Check overcount warning
        if c_meta and c_meta.independent_source_count > ind_assess.distinct_execution_count:
            warnings.append(
                f"M2T04_INDEPENDENCE_OVERCOUNT:{cve.cve_candidate_id} "
                f"(M2-T04 reported {c_meta.independent_source_count}, "
                f"verified {ind_assess.distinct_execution_count})"
            )

        key = correlation_identity_key(
            CorrelationKind.CVE_TECHNOLOGY,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            t_key,
            cve.cve_id,
        )
        cor_id = CorrelationId(f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}")

        missing_links = ["ENVIRONMENTAL_PRECONDITIONS_UNVERIFIED"] if preconditions else []
        rec = CorrelationRecord(
            correlation_id=cor_id,
            kind=CorrelationKind.CVE_TECHNOLOGY,
            status=status,
            confidence=conf,
            injection_subtype=subtype,
            vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
            cve_candidate_ref=cve.cve_candidate_id,
            target_technology=cve.target_technology,
            existence_evidence_refs=tuple(sorted(cve.evidence_refs)),
            existence_observation_refs=tuple(sorted(cve.observation_refs)),
            relation_evidence_refs=tuple(sorted(e.evidence_id for e in rel_evd)),
            relation_observation_refs=tuple(sorted(o.observation_id for o in rel_obs)),
            independent_relation_source_count=ind_assess.distinct_execution_count,
            independence=ind_assess,
            unverified_preconditions=tuple(preconditions),
            missing_links=tuple(missing_links),
            confidence_caps_applied=applied_caps,
            rationale=(
                f"Grounded CVE {cve.cve_id} against {cve.target_technology.name} "
                f"{cve.target_technology.version} ({subtype.value})"
            ),
        )
        cve_tech_records.append(rec)
        candidate_records.append(rec)

    # Stage 5: SINK_CVE and INPUT_SINK_CVE_CHAIN Composition
    # Check approved vulnerable APIs in policy
    if not policy.approved_vulnerable_apis:
        limitations.append("SINK_CVE_REGISTRY_EMPTY")
    else:
        # Index approved vulnerable APIs by cve_id
        api_by_cve: dict[str, list[ApprovedVulnerableApiEntry]] = {}
        for api in policy.approved_vulnerable_apis:
            api_by_cve.setdefault(api.cve_id, []).append(api)

        # Match approved sinks with cve_tech_records
        for cve_rec in cve_tech_records:
            cve_cand = next(
                (c for c in grounded_cves if c.cve_candidate_id == cve_rec.cve_candidate_ref),
                None,
            )
            if not cve_cand:
                continue
            matching_apis = api_by_cve.get(cve_cand.cve_id, [])
            for api in matching_apis:
                tech_name = cve_rec.target_technology.name.casefold().strip()  # type: ignore[union-attr]
                if api.technology_name.casefold().strip() != tech_name:
                    continue

                for snk, _man, evd, scope_res in allowed_sinks:
                    if scope_res.rule_provenance != RuleProvenanceStatus.VERIFIED:
                        continue
                    meta = sink_metadata_map.get(snk.sink_id)
                    all_rules = set(meta.all_rule_ids) if meta else {snk.rule_id}
                    if not (all_rules & api.rule_ids):
                        continue

                    # Compose SINK_CVE
                    rel_evd = [
                        evd,
                        *[
                            all_request_evd[e]
                            for e in cve_rec.relation_evidence_refs
                            if e in all_request_evd
                        ],
                    ]
                    rel_obs = [
                        all_request_obs[o]
                        for o in cve_rec.relation_observation_refs
                        if o in all_request_obs
                    ]
                    ind_assess = assess_independence(rel_evd, rel_obs)

                    conf, applied_caps = evaluate_correlation_confidence(
                        CorrelationKind.SINK_CVE,
                        CorrelationStatus.PARTIAL,
                        base_confidence=ConfidenceLevel.MEDIUM,
                        caps=[
                            (snk.confidence, "SINK_CONFIDENCE_CAP"),
                            (cve_rec.confidence, "CVE_CONFIDENCE_CAP"),
                        ],
                    )

                    sink_t_key = (
                        cve_rec.target_technology.category.value,  # type: ignore[union-attr]
                        cve_rec.target_technology.name,  # type: ignore[union-attr]
                        cve_rec.target_technology.version,  # type: ignore[union-attr]
                    )
                    key = correlation_identity_key(
                        CorrelationKind.SINK_CVE,
                        None,
                        None,
                        None,
                        snk.file_path,
                        snk.start_line,
                        None,
                        None,
                        None,
                        sink_t_key,
                        cve_cand.cve_id,
                    )
                    sink_cve_id = CorrelationId(
                        f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
                    )

                    sink_cve_rec = CorrelationRecord(
                        correlation_id=sink_cve_id,
                        kind=CorrelationKind.SINK_CVE,
                        status=CorrelationStatus.PARTIAL,
                        confidence=conf,
                        injection_subtype=cve_rec.injection_subtype,
                        vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
                        sink_ref=snk.sink_id,
                        cve_candidate_ref=cve_rec.cve_candidate_ref,
                        target_technology=cve_rec.target_technology,
                        component_refs=(cve_rec.correlation_id,),
                        existence_evidence_refs=tuple(
                            sorted(set(snk.evidence_refs) | set(cve_rec.existence_evidence_refs))
                        ),
                        existence_observation_refs=cve_rec.existence_observation_refs,
                        relation_evidence_refs=tuple(
                            sorted(
                                {
                                    *snk.evidence_refs,
                                    *cve_rec.relation_evidence_refs,
                                }
                            )
                        ),
                        relation_observation_refs=cve_rec.relation_observation_refs,
                        independent_relation_source_count=ind_assess.distinct_execution_count,
                        independence=ind_assess,
                        confidence_caps_applied=applied_caps,
                        rationale=(
                            f"Correlated sink {snk.sink_id} with CVE {cve_cand.cve_id} via "
                            f"approved vulnerable API registry entry ({api.review_ref})"
                        ),
                    )
                    candidate_records.append(sink_cve_rec)

                    # Compose INPUT_SINK_CVE_CHAIN if INPUT_SINK VERIFIED exists for this sink
                    for in_sink_rec in [
                        r
                        for r in candidate_records
                        if r.kind == CorrelationKind.INPUT_SINK
                        and r.status == CorrelationStatus.VERIFIED
                        and r.sink_ref == snk.sink_id
                    ]:
                        chain_conf, chain_caps = evaluate_correlation_confidence(
                            CorrelationKind.INPUT_SINK_CVE_CHAIN,
                            CorrelationStatus.PARTIAL,
                            base_confidence=ConfidenceLevel.MEDIUM,
                            caps=[
                                (in_sink_rec.confidence, "INPUT_SINK_CONFIDENCE_CAP"),
                                (sink_cve_rec.confidence, "SINK_CVE_CONFIDENCE_CAP"),
                            ],
                        )

                        chain_key = correlation_identity_key(
                            CorrelationKind.INPUT_SINK_CVE_CHAIN,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            component_identity_keys=[
                                in_sink_rec.correlation_id,
                                sink_cve_rec.correlation_id,
                            ],
                        )
                        chain_id = CorrelationId(
                            f"COR-{hashlib.sha256(chain_key.encode('utf-8')).hexdigest()[:16]}"
                        )

                        chain_rec = CorrelationRecord(
                            correlation_id=chain_id,
                            kind=CorrelationKind.INPUT_SINK_CVE_CHAIN,
                            status=CorrelationStatus.PARTIAL,
                            confidence=chain_conf,
                            injection_subtype=cve_rec.injection_subtype,
                            vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
                            endpoint_id=in_sink_rec.endpoint_id,
                            input_ref=in_sink_rec.input_ref,
                            sink_ref=snk.sink_id,
                            cve_candidate_ref=cve_rec.cve_candidate_ref,
                            target_technology=cve_rec.target_technology,
                            component_refs=(
                                in_sink_rec.correlation_id,
                                sink_cve_rec.correlation_id,
                            ),
                            existence_evidence_refs=tuple(
                                sorted(
                                    set(in_sink_rec.existence_evidence_refs)
                                    | set(sink_cve_rec.existence_evidence_refs)
                                )
                            ),
                            existence_observation_refs=tuple(
                                sorted(
                                    set(in_sink_rec.existence_observation_refs)
                                    | set(sink_cve_rec.existence_observation_refs)
                                )
                            ),
                            relation_evidence_refs=tuple(
                                sorted(
                                    set(in_sink_rec.relation_evidence_refs)
                                    | set(sink_cve_rec.relation_evidence_refs)
                                )
                            ),
                            relation_observation_refs=sink_cve_rec.relation_observation_refs,
                            independent_relation_source_count=min(
                                in_sink_rec.independent_relation_source_count,
                                sink_cve_rec.independent_relation_source_count,
                            ),
                            independence=in_sink_rec.independence,
                            confidence_caps_applied=chain_caps,
                            rationale=(
                                f"Composed end-to-end chain from input {in_sink_rec.input_ref} "
                                f"via sink {snk.sink_id} to CVE {cve_cand.cve_id}"
                            ),
                        )
                        candidate_records.append(chain_rec)

    # Stage 6: Deduplication & Canonical Result Packaging
    # Deduplicate candidate_records by correlation_id
    dedup_map: dict[str, CorrelationRecord] = {}
    for rec in candidate_records:
        cid = rec.correlation_id
        if cid not in dedup_map:
            dedup_map[cid] = rec
        else:
            # Merge refs and pick conservative confidence
            prev = dedup_map[cid]
            levels = {ConfidenceLevel.LOW: 1, ConfidenceLevel.MEDIUM: 2, ConfidenceLevel.HIGH: 3}
            inv_levels = {
                1: ConfidenceLevel.LOW,
                2: ConfidenceLevel.MEDIUM,
                3: ConfidenceLevel.HIGH,
            }
            merged_conf = inv_levels[min(levels[prev.confidence], levels[rec.confidence])]

            merged_rec = prev.model_copy(
                update={
                    "confidence": merged_conf,
                    "existence_evidence_refs": tuple(
                        sorted(set(prev.existence_evidence_refs) | set(rec.existence_evidence_refs))
                    ),
                    "existence_observation_refs": tuple(
                        sorted(
                            set(prev.existence_observation_refs)
                            | set(rec.existence_observation_refs)
                        )
                    ),
                    "relation_evidence_refs": tuple(
                        sorted(set(prev.relation_evidence_refs) | set(rec.relation_evidence_refs))
                    ),
                    "relation_observation_refs": tuple(
                        sorted(
                            set(prev.relation_observation_refs) | set(rec.relation_observation_refs)
                        )
                    ),
                    "confidence_caps_applied": tuple(
                        sorted(set(prev.confidence_caps_applied) | set(rec.confidence_caps_applied))
                    ),
                    "missing_links": tuple(
                        sorted(set(prev.missing_links) | set(rec.missing_links))
                    ),
                }
            )
            dedup_map[cid] = merged_rec

    # Sort records canonically
    kind_order = {
        CorrelationKind.INPUT_SINK: 1,
        CorrelationKind.ENDPOINT_SINK: 2,
        CorrelationKind.CVE_TECHNOLOGY: 3,
        CorrelationKind.SINK_CVE: 4,
        CorrelationKind.INPUT_SINK_CVE_CHAIN: 5,
    }
    status_order = {CorrelationStatus.VERIFIED: 1, CorrelationStatus.PARTIAL: 2}

    sorted_records = sorted(
        dedup_map.values(),
        key=lambda r: (
            kind_order.get(r.kind, 9),
            status_order.get(r.status, 9),
            r.correlation_id,
        ),
    )

    # Sort diagnostics canonically
    sorted_diagnostics = sorted(
        diagnostics,
        key=lambda d: (d.stage, d.subject_ref, d.code, d.reason),
    )

    # Coverage & blocking dependencies
    blocking: list[str] = []
    if not policy.trusted_route_producers:
        blocking.append("M2-T03b:NO_TRUSTED_ROUTE_PRODUCER")
    if not policy.approved_rulesets:
        blocking.append("M2-T03c:APPROVED_RULESET_REGISTRY_EMPTY")
    if not policy.approved_vulnerable_apis:
        blocking.append("VULNERABLE_API_REGISTRY_EMPTY")

    has_input_sink = any(r.kind == CorrelationKind.INPUT_SINK for r in sorted_records)
    has_sink_cve = any(r.kind == CorrelationKind.SINK_CVE for r in sorted_records)
    has_chain = any(r.kind == CorrelationKind.INPUT_SINK_CVE_CHAIN for r in sorted_records)
    has_cve_tech = any(r.kind == CorrelationKind.CVE_TECHNOLOGY for r in sorted_records)

    coverage = CorrelationCoverage(
        input_sink_enabled=has_input_sink,
        sink_cve_enabled=has_sink_cve,
        chain_enabled=has_chain,
        cve_technology_enabled=has_cve_tech or bool(allowed_cves),
        blocking_dependencies=tuple(sorted(blocking)),
    )

    return CorrelationResult(
        records=tuple(sorted_records),
        sink_scopes=tuple(sorted(sink_scopes, key=lambda s: s.sink_id)),
        diagnostics=tuple(sorted_diagnostics),
        limitations=tuple(sorted(set(limitations))),
        warnings=tuple(sorted(set(warnings))),
        coverage=coverage,
        trust_policy_fingerprint=policy.fingerprint,
        trust_policy_is_default=(
            policy.fingerprint == DEFAULT_CORRELATION_TRUST_POLICY.fingerprint
        ),
    )


async def acorrelate_evidence(
    request: Module2AnalysisRequest,
    *,
    input_result: InputExtractionResult | None = None,
    sink_result: SinkExtractionResult | None = None,
    cve_result: CVEExtractionResult | None = None,
    route_binding_artifacts: Sequence[RouteBindingArtifactRef] = (),
    scope_policy: InjectionScopePolicy | None = None,
    trust_policy: CorrelationTrustPolicy | None = None,
) -> CorrelationResult:
    """Asynchronous wrapper for deterministic evidence correlation."""
    return correlate_evidence(
        request,
        input_result=input_result,
        sink_result=sink_result,
        cve_result=cve_result,
        route_binding_artifacts=route_binding_artifacts,
        scope_policy=scope_policy,
        trust_policy=trust_policy,
    )


def build_correlation_envelope(
    output: Module2Output,
    correlation: CorrelationResult,
    request: Module2AnalysisRequest,
    *,
    expected_trust_policy_fingerprint: str = DEFAULT_CORRELATION_TRUST_POLICY.fingerprint,
) -> Module2CorrelationEnvelope:
    """Package Module2Output and CorrelationResult fail-closed into a validated envelope."""
    # 1. Enforce Module 2 handoff validation
    validate_module2_handoff(output, request)

    # 2. Check trust policy fingerprint alignment
    if correlation.trust_policy_fingerprint != expected_trust_policy_fingerprint:
        raise CorrelationInputError(
            f"Correlation trust policy fingerprint mismatch: "
            f"got {correlation.trust_policy_fingerprint}, "
            f"expected {expected_trust_policy_fingerprint}"
        )

    # 3. Verify that every candidate reference in correlation records resolves in Module2Output
    known_inputs = {i.input_id: i for i in output.inputs}
    known_sinks = {s.sink_id: s for s in output.sink_candidates}
    known_cves = {c.cve_candidate_id: c for c in output.cve_candidates}
    known_records = {r.correlation_id: r for r in correlation.records}

    ref_index = AuthoritativeReferenceIndex.from_request(request)
    output_evd_ids = {
        e.evidence_id for e in output.analysis_evidence_records
    } | ref_index.evidence_ids
    output_obs_ids = ref_index.observation_ids

    for rec in correlation.records:
        if rec.input_ref:
            inp = known_inputs.get(rec.input_ref)
            if not inp:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} references unknown input {rec.input_ref}"
                )
            if rec.endpoint_id and inp.endpoint_id != rec.endpoint_id:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} endpoint_id {rec.endpoint_id} does not "
                    f"match input {inp.input_id} endpoint {inp.endpoint_id}"
                )

        if rec.sink_ref and rec.sink_ref not in known_sinks:
            raise CorrelationInputError(
                f"Record {rec.correlation_id} references unknown sink {rec.sink_ref}"
            )

        if rec.cve_candidate_ref:
            cve = known_cves.get(rec.cve_candidate_ref)
            if not cve:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} references unknown cve {rec.cve_candidate_ref}"
                )
            if rec.target_technology and cve.target_technology != rec.target_technology:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} target_technology does not match CVE candidate"
                )

        for comp_id in rec.component_refs:
            if comp_id not in known_records:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} references unknown component correlation "
                    f"{comp_id}"
                )

        for e_ref in rec.existence_evidence_refs:
            if e_ref not in output_evd_ids:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} has unresolvable existence evidence ref {e_ref}"
                )
        for o_ref in rec.existence_observation_refs:
            if o_ref not in output_obs_ids:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} has unresolvable existence observation ref "
                    f"{o_ref}"
                )
        for r_ref in rec.relation_evidence_refs:
            if r_ref not in output_evd_ids:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} has unresolvable relation evidence ref {r_ref}"
                )
        for ro_ref in rec.relation_observation_refs:
            if ro_ref not in output_obs_ids:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} has unresolvable relation observation ref "
                    f"{ro_ref}"
                )

    return Module2CorrelationEnvelope(output=output, correlation=correlation)
