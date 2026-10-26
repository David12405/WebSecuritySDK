"""Canonical, tool-independent Module 1 models.

These models deliberately contain facts and execution contracts only. They do
not contain vulnerability conclusions, orchestration state, or AI concepts.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, StringConstraints, model_validator

from .enums import (
    ActionRequester,
    ActionType,
    ArtifactType,
    AuthMechanism,
    CapabilityType,
    ConfidenceLevel,
    DiscoverySource,
    InputLocation,
    ObservationSource,
    ObservationType,
    TechnologyCategory,
    TestingMode,
    ToolExecutionStatus,
    ToolRiskClass,
)

Id = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2,}-[0-9]{3,}$")]
JsonValue = Any


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, protected_namespaces=())


class ResourceCost(StrictModel):
    http_requests: int = Field(default=0, ge=0)
    network_scan_actions: int = Field(default=0, ge=0)
    browser_actions: int = Field(default=0, ge=0)
    source_analysis_actions: int = Field(default=0, ge=0)
    tool_actions: int = Field(default=0, ge=0)
    execution_seconds: float = Field(default=0, ge=0)


class ScopeApprovalRecord(StrictModel):
    is_approved: bool = False
    approved_by: str | None = None
    approval_timestamp: datetime | None = None
    scope_signature_hash: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")

    @model_validator(mode="after")
    def validate_approval(self) -> ScopeApprovalRecord:
        if self.is_approved and (not self.approved_by or not self.approval_timestamp):
            raise ValueError("approved scope requires approver and timestamp")
        if self.approval_timestamp and self.approval_timestamp > datetime.now(UTC):
            raise ValueError("approval timestamp cannot be in the future")
        if self.is_approved and not self.scope_signature_hash:
            raise ValueError("approved scope requires a signature hash")
        return self


class AuthReferenceConfig(StrictModel):
    role_name: str = Field(min_length=1)
    auth_mechanism: AuthMechanism
    vault_secret_ref: str = Field(pattern=r"^VAULT-[A-Za-z0-9_-]+$")
    header_or_cookie_name: str = Field(default="Authorization", min_length=1)


class HttpExecutionPolicy(StrictModel):
    timeout_seconds: float = Field(default=10, gt=0)
    max_requests_per_minute: int = Field(default=60, ge=1)
    request_budget: int = Field(default=1000, ge=1)
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "POST"])
    follow_redirects: bool = False
    max_redirects: int = Field(default=5, ge=0, le=20)
    max_capture_bytes: int = Field(default=1_000_000, ge=0)


class BrowserExecutionPolicy(StrictModel):
    enabled: bool = False
    max_sessions: int = Field(default=1, ge=1)
    max_actions_per_session: int = Field(default=50, ge=1)
    allow_javascript: bool = False
    allow_file_download: bool = False
    timeout_seconds: float = Field(default=30, gt=0)
    max_capture_bytes: int = Field(default=2_000_000, ge=0)


class NetworkScanPolicy(StrictModel):
    enabled: bool = False
    max_hosts: int = Field(default=256, ge=1)
    max_ports_per_host: int = Field(default=100, ge=1)
    max_concurrent_scans: int = Field(default=1, ge=1)
    allowed_profiles: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=120, gt=0)


class ExecutionPolicy(StrictModel):
    max_execution_seconds: float = Field(default=300, gt=0)
    max_concurrent_actions: int = Field(default=1, ge=1)
    allowed_capabilities: list[CapabilityType] = Field(default_factory=list)
    blocked_capabilities: list[CapabilityType] = Field(default_factory=list)
    http_policy: HttpExecutionPolicy = Field(default_factory=HttpExecutionPolicy)
    network_scan_policy: NetworkScanPolicy = Field(default_factory=NetworkScanPolicy)
    browser_policy: BrowserExecutionPolicy = Field(default_factory=BrowserExecutionPolicy)
    allowed_tool_ids: list[str] = Field(default_factory=list)
    blocked_tool_ids: list[str] = Field(default_factory=list)


class AssessmentConfig(StrictModel):
    assessment_id: Id
    schema_version: str = "2.0.0"
    target: HttpUrl
    authorized_scope: list[str] = Field(min_length=1)
    excluded_scope: list[str] = Field(default_factory=list)
    scope_approval: ScopeApprovalRecord
    testing_mode: TestingMode = TestingMode.BLACKBOX
    execution_policy: ExecutionPolicy = Field(default_factory=ExecutionPolicy)
    auth_references: list[AuthReferenceConfig] = Field(default_factory=list)
    api_specification_ref: str | None = None
    source_repository_ref: str | None = None


def _validate_opaque_artifact_ref(value: str) -> str:
    """Reject physical paths and URI schemes at the logical-ref boundary."""

    if (
        "://" in value
        or value.startswith(("/", "\\"))
        or "/" in value
        or "\\" in value
        or re.match(r"^[A-Za-z]:", value)
        or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value)
    ):
        raise ValueError("artifact_ref must be an opaque logical reference")
    return value


class ArtifactManifest(StrictModel):
    artifact_ref: str = Field(min_length=1)
    artifact_type: ArtifactType
    storage_uri: str | None = None
    content: str | None = None
    sha256_hash: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    size_bytes: int | None = Field(default=None, ge=0)
    media_type: str | None = None
    redaction_applied: bool = False
    truncated: bool = False
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def artifact_ref_is_opaque(self) -> ArtifactManifest:
        _validate_opaque_artifact_ref(self.artifact_ref)
        return self


class EvidenceArtifactRecord(StrictModel):
    evidence_id: Id
    assessment_id: Id
    artifact_type: ArtifactType
    artifact_ref: str = Field(min_length=1)
    storage_uri: str | None = None
    sha256_hash: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    size_bytes: int = Field(ge=0)
    media_type: str | None = None
    captured_at: datetime
    execution_ref: Id | None = None
    source_tool_id: str | None = None
    provenance: dict[str, JsonValue] = Field(default_factory=dict)
    redaction_applied: bool = False
    truncated: bool = False
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def artifact_ref_is_opaque(self) -> EvidenceArtifactRecord:
        _validate_opaque_artifact_ref(self.artifact_ref)
        return self


class ObservedParameter(StrictModel):
    name: str = Field(min_length=1)
    location: InputLocation
    data_type: str | None = None
    required: bool | None = None
    content_type: str | None = None
    evidence_refs: list[Id] = Field(default_factory=list)
    observation_refs: list[Id] = Field(default_factory=list)


class EndpointObservationPayload(StrictModel):
    kind: Literal["endpoint"] = "endpoint"
    origin: str
    path: str = Field(min_length=1)
    method: str = Field(min_length=1)
    request_content_types: list[str] = Field(default_factory=list)
    response_content_types: list[str] = Field(default_factory=list)
    parameters: list[ObservedParameter] = Field(default_factory=list)
    status: int | None = Field(default=None, ge=100, le=599)
    response_headers: dict[str, str] = Field(default_factory=dict)
    declared_security: list[str] = Field(default_factory=list)


class HttpExchangeObservationPayload(StrictModel):
    kind: Literal["http_exchange"] = "http_exchange"
    method: str = Field(min_length=1)
    url: str
    status: int | None = Field(default=None, ge=100, le=599)
    request_content_type: str | None = None
    response_content_type: str | None = None
    parameters: list[ObservedParameter] = Field(default_factory=list)


class RedirectObservationPayload(StrictModel):
    kind: Literal["redirect"] = "redirect"
    from_url: str
    to_url: str
    status: int = Field(ge=300, le=399)
    followed: bool


class AuthenticationObservationPayload(StrictModel):
    kind: Literal["authentication"] = "authentication"
    subject: str
    mechanism: str | None = None
    role: str | None = None
    session_present: bool | None = None
    cookie_names: list[str] = Field(default_factory=list)


class TechnologyObservationPayload(StrictModel):
    kind: Literal["technology"] = "technology"
    name: str = Field(min_length=1)
    category: TechnologyCategory
    version: str | None = None
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN


class BrowserBehaviorObservationPayload(StrictModel):
    kind: Literal["browser_behavior"] = "browser_behavior"
    action_id: str | None = None
    event: str = Field(min_length=1)
    url: str | None = None
    related_network_event_ids: list[str] = Field(default_factory=list)


class NetworkHostObservationPayload(StrictModel):
    kind: Literal["network_host"] = "network_host"
    address: str
    hostnames: list[str] = Field(default_factory=list)
    state: str


class NetworkServiceObservationPayload(StrictModel):
    kind: Literal["network_service"] = "network_service"
    address: str
    port: int = Field(ge=1, le=65535)
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None


ObservationPayload = (
    EndpointObservationPayload
    | HttpExchangeObservationPayload
    | RedirectObservationPayload
    | AuthenticationObservationPayload
    | TechnologyObservationPayload
    | BrowserBehaviorObservationPayload
    | NetworkHostObservationPayload
    | NetworkServiceObservationPayload
)


class ObservationRecord(StrictModel):
    observation_id: Id
    assessment_id: Id
    observation_type: ObservationType
    payload: ObservationPayload
    source_type: ObservationSource
    source_tool_id: str | None = None
    execution_ref: Id | None = None
    evidence_refs: list[Id] = Field(default_factory=list)
    source_locator: str | None = None
    observed_at: datetime
    validated: bool = True

    @model_validator(mode="after")
    def payload_matches_type(self) -> ObservationRecord:
        kind = getattr(self.payload, "kind", None)
        allowed = {
            ObservationType.ENDPOINT: {"endpoint", "http_exchange"},
            ObservationType.HTTP_METADATA: {"redirect", "http_exchange"},
            ObservationType.AUTHENTICATION: {"authentication"},
            ObservationType.TECHNOLOGY: {"technology"},
            ObservationType.BROWSER_BEHAVIOR: {"browser_behavior"},
            ObservationType.NETWORK_HOST: {"network_host"},
            ObservationType.NETWORK_SERVICE: {"network_service"},
        }
        expected = allowed.get(self.observation_type)
        if expected is not None and kind not in expected:
            raise ValueError(f"payload kind {kind!r} does not match {self.observation_type.value}")
        return self


class EndpointDefinition(StrictModel):
    endpoint_id: Id
    origin: str
    path: str = Field(min_length=1)
    method: str = Field(min_length=1)
    request_content_types: list[str] = Field(default_factory=list)
    response_content_types: list[str] = Field(default_factory=list)
    observed_parameters: list[ObservedParameter] = Field(default_factory=list)
    declared_security: list[str] = Field(default_factory=list)
    required_auth_role: str | None = None
    discovery_sources: list[DiscoverySource] = Field(default_factory=list)
    evidence_refs: list[Id] = Field(default_factory=list)
    observation_refs: list[Id] = Field(default_factory=list)

    @property
    def runtime_observed(self) -> bool:
        """Whether independent runtime evidence supports this declaration."""

        return any(
            source in {
                DiscoverySource.HTTP_OBSERVATION,
                DiscoverySource.CRAWLER,
                DiscoverySource.BROWSER,
            }
            for source in self.discovery_sources
        )

    @property
    def discovery_status(self) -> str:
        """Derived declaration/runtime relation; never persisted as mutable state."""

        declared = DiscoverySource.API_SPEC in self.discovery_sources
        if declared and self.runtime_observed:
            return "both"
        if declared:
            return "declared"
        if self.runtime_observed:
            return "runtime"
        return "other"


class TechnologyRecord(StrictModel):
    category: TechnologyCategory
    name: str = Field(min_length=1)
    version: str | None = None
    confidence: ConfidenceLevel = ConfidenceLevel.UNKNOWN
    observation_refs: list[Id] = Field(default_factory=list)
    evidence_refs: list[Id] = Field(default_factory=list)


class TargetModel(StrictModel):
    target_id: Id
    assessment_id: Id
    schema_version: str = "2.0.0"
    revision: int = Field(default=1, ge=1)
    last_updated: datetime
    scope_rules: AssessmentConfig | None = None
    assets: list[str] = Field(default_factory=list)
    technologies: list[TechnologyRecord] = Field(default_factory=list)
    endpoints: list[EndpointDefinition] = Field(default_factory=list)


class ToolCapability(StrictModel):
    tool_id: str = Field(min_length=1)
    tool_name: str = Field(min_length=1)
    adapter_type: str = Field(min_length=1)
    capabilities: list[CapabilityType] = Field(min_length=1)
    allowed_profiles: list[str] = Field(default_factory=list)
    supported_modules: list[str] = Field(default_factory=list)
    requires_network: bool = True
    risk_class: ToolRiskClass = ToolRiskClass.PASSIVE
    default_timeout_seconds: float = Field(default=30, gt=0)
    enabled: bool = True


class ActionRequest(StrictModel):
    action_id: Id
    assessment_id: Id
    action_type: ActionType
    target_refs: list[str] = Field(default_factory=list)
    requested_capability: CapabilityType
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    requested_by: ActionRequester
    reason: str = Field(min_length=1)
    estimated_cost: ResourceCost = Field(default_factory=ResourceCost)
    created_at: datetime


class ToolExecutionResult(StrictModel):
    execution_id: Id
    assessment_id: Id
    action_ref: Id | None = None
    tool_id: str = Field(min_length=1)
    target: str | None = None
    result_type: str = Field(min_length=1)
    result_schema_version: str = "1.0"
    result_data: dict[str, JsonValue] = Field(default_factory=dict)
    artifact_manifests: list[ArtifactManifest] = Field(default_factory=list)
    status: ToolExecutionStatus
    started_at: datetime
    finished_at: datetime | None = None
    truncated: bool = False
    dropped_items: int = Field(default=0, ge=0)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    resource_usage: ResourceCost = Field(default_factory=ResourceCost)


class ReconProcessingResult(StrictModel):
    execution_ref: Id
    evidence_records: list[EvidenceArtifactRecord] = Field(default_factory=list)
    observation_records: list[ObservationRecord] = Field(default_factory=list)
    endpoint_updates: list[EndpointDefinition] = Field(default_factory=list)
    technology_updates: list[TechnologyRecord] = Field(default_factory=list)
    updated_target_model: TargetModel | None = None
    model_changed: bool = False
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
