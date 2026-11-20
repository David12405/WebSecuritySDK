"""Typed MVP contracts for the two capabilities a SQLi plan may use.

`HTTP_REQUEST@1.0` establishes a baseline and `SQLI_DETECTION@1.0` runs the
bounded detection. The planner never sees these full I/O shapes: it only sets
the narrow, safe subset in `HttpRequestArgs` / `SqliDetectionArgs` (techniques,
sample count, budgets below the ceilings). Opaque request/baseline references
are bound by code at the Module 3 handoff, never chosen by a model.

`SQLiSafetyPolicy` is the executable ceiling. Prose inside a tactic cannot
loosen it; the stricter of this policy and the generic `ExecutionPolicy` always
wins (enforced in `planning.validation`). The policy and the capability set each
expose a stable fingerprint so a tactic's compatibility can be re-checked
whenever either changes.
"""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum

from pydantic import Field, model_validator

from ..domain.enums import InputLocation
from ..domain.models import StrictModel

CONTRACT_VERSION = "1.0"


class SQLiTechnique(StrEnum):
    ERROR = "ERROR"
    BOOLEAN = "BOOLEAN"
    UNION = "UNION"
    TIME = "TIME"


class RiskProfile(StrEnum):
    LOW = "LOW"


class DetectionStatus(StrEnum):
    VERIFIED = "VERIFIED"
    HEURISTIC_ONLY = "HEURISTIC_ONLY"
    NOT_DETECTED = "NOT_DETECTED"
    INTERRUPTED = "INTERRUPTED"
    ERROR = "ERROR"


def _canonical_hash(payload: object) -> str:
    """SHA-256 over canonical JSON, so formatting never changes identity."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Safety policy
# --------------------------------------------------------------------------- #


class SQLiSafetyPolicy(StrictModel):
    """Strict ceilings for SQLi testing, defaulting to the reference tactic.

    `enabled` defaults to False so planning fails closed until an assessment
    explicitly authorizes active SQLi testing. Every numeric field is a ceiling
    a plan may come in under, never a grant it may exceed.
    """

    enabled: bool = False
    risk_profile: RiskProfile = RiskProfile.LOW
    allowed_techniques: list[SQLiTechnique] = Field(
        default_factory=lambda: [
            SQLiTechnique.ERROR,
            SQLiTechnique.BOOLEAN,
            SQLiTechnique.UNION,
            SQLiTechnique.TIME,
        ]
    )
    primary_detection_max_requests: int = Field(default=150, ge=1)
    time_detection_max_requests: int = Field(default=100, ge=1)
    aggregate_max_requests: int = Field(default=250, ge=1)
    detection_timeout_seconds: int = Field(default=120, ge=1)
    require_stable_baseline_for_time: bool = True
    allow_enumeration: bool = False
    allow_data_dump: bool = False
    allow_os_shell: bool = False
    allow_file_rw: bool = False
    allow_waf_bypass: bool = False

    @model_validator(mode="after")
    def validate_ceilings(self) -> SQLiSafetyPolicy:
        if not self.allowed_techniques:
            raise ValueError("SQLiSafetyPolicy must allow at least one technique")
        if len(set(self.allowed_techniques)) != len(self.allowed_techniques):
            raise ValueError("SQLiSafetyPolicy.allowed_techniques must be unique")
        if self.primary_detection_max_requests > self.aggregate_max_requests:
            raise ValueError("primary detection budget cannot exceed the aggregate budget")
        if self.time_detection_max_requests > self.aggregate_max_requests:
            raise ValueError("time detection budget cannot exceed the aggregate budget")
        return self

    def fingerprint(self) -> str:
        """Stable identity of the policy, for the compatibility fingerprint."""
        return _canonical_hash(self.model_dump(mode="json"))

    def max_requests_for(self, technique: SQLiTechnique) -> int:
        if technique == SQLiTechnique.TIME:
            return self.time_detection_max_requests
        return self.primary_detection_max_requests


# --------------------------------------------------------------------------- #
# HTTP_REQUEST@1.0
# --------------------------------------------------------------------------- #


class HttpRequestArgs(StrictModel):
    """The only HTTP_REQUEST fields a planner is allowed to choose."""

    sample_count: int = Field(default=2, ge=2, le=5)
    timeout_seconds: int = Field(default=15, ge=1)


class HttpRequestInput(StrictModel):
    """Full HTTP_REQUEST@1.0 input; code adds the opaque references."""

    request_template_ref: str = Field(min_length=1)
    sample_count: int = Field(default=2, ge=2, le=5)
    timeout_seconds: int = Field(default=15, ge=1)
    policy_context_ref: str = Field(min_length=1)


class HttpRequestOutput(StrictModel):
    baseline_ready: bool
    target_stable: bool
    auth_failure_detected: bool = False
    rate_limited: bool = False
    waf_or_filter_detected: bool = False
    control_observation_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    error: str | None = None


# --------------------------------------------------------------------------- #
# SQLI_DETECTION@1.0
# --------------------------------------------------------------------------- #


class SqliDetectionArgs(StrictModel):
    """The only SQLI_DETECTION fields a planner is allowed to choose."""

    techniques: list[SQLiTechnique] = Field(min_length=1)
    risk_profile: RiskProfile = RiskProfile.LOW
    max_requests: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)
    dbms_hint: str | None = None

    @model_validator(mode="after")
    def techniques_unique(self) -> SqliDetectionArgs:
        if len(set(self.techniques)) != len(self.techniques):
            raise ValueError("SqliDetectionArgs.techniques must be unique")
        return self


class SqliDetectionInput(StrictModel):
    """Full SQLI_DETECTION@1.0 input; code adds the opaque references."""

    request_template_ref: str = Field(min_length=1)
    parameter_name: str = Field(min_length=1)
    parameter_location: InputLocation
    techniques: list[SQLiTechnique] = Field(min_length=1)
    baseline_observation_refs: list[str] = Field(default_factory=list)
    risk_profile: RiskProfile = RiskProfile.LOW
    max_requests: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)
    dbms_hint: str | None = None


class DetectionProof(StrictModel):
    """Evidence for one technique. A tool's boolean flag alone cannot satisfy it."""

    technique: SQLiTechnique
    verified: bool
    control_observation_refs: list[str] = Field(min_length=1)
    test_observation_refs: list[str] = Field(min_length=1)
    evidence_refs: list[str] = Field(min_length=1)


class SqliDetectionOutput(StrictModel):
    detection_status: DetectionStatus
    tested_techniques: list[SQLiTechnique] = Field(default_factory=list)
    confirmed_techniques: list[SQLiTechnique] = Field(default_factory=list)
    heuristic_signal_detected: bool = False
    target_stable: bool = True
    blocked: bool = False
    proofs: list[DetectionProof] = Field(default_factory=list)
    observation_refs: list[str] = Field(default_factory=list)
    redacted_evidence_refs: list[str] = Field(default_factory=list)
    requests_used: int = Field(default=0, ge=0)
    error: str | None = None


# --------------------------------------------------------------------------- #
# Capability registry
# --------------------------------------------------------------------------- #


class CapabilityContract(StrictModel):
    """One capability's identity and the planner-facing argument model name."""

    capability_id: str
    version: str
    args_model: str
    input_model: str
    output_model: str


CAPABILITY_CONTRACTS: dict[str, CapabilityContract] = {
    "HTTP_REQUEST": CapabilityContract(
        capability_id="HTTP_REQUEST",
        version=CONTRACT_VERSION,
        args_model="HttpRequestArgs",
        input_model="HttpRequestInput",
        output_model="HttpRequestOutput",
    ),
    "SQLI_DETECTION": CapabilityContract(
        capability_id="SQLI_DETECTION",
        version=CONTRACT_VERSION,
        args_model="SqliDetectionArgs",
        input_model="SqliDetectionInput",
        output_model="SqliDetectionOutput",
    ),
}

_ARGS_MODELS: dict[str, type[StrictModel]] = {
    "HTTP_REQUEST": HttpRequestArgs,
    "SQLI_DETECTION": SqliDetectionArgs,
}


def validate_capability_arguments(capability_id: str, arguments: dict) -> list[str]:
    """Validate a plan's per-case arguments against the capability's arg model.

    Returns one message per problem, empty when the arguments are admissible.
    An unknown capability is itself a violation - the planner may only name
    capabilities the registry declares.
    """
    model = _ARGS_MODELS.get(capability_id)
    if model is None:
        return [f"capability {capability_id} is not in the MVP capability registry"]
    try:
        model.model_validate(arguments)
    except Exception as exc:  # pydantic ValidationError, kept bounded
        return [f"{capability_id} arguments invalid: {exc}"]
    return []


def capability_fingerprint() -> str:
    """Stable identity of the capability contract set, version included."""
    payload = {
        cid: contract.model_dump(mode="json")
        for cid, contract in sorted(CAPABILITY_CONTRACTS.items())
    }
    return _canonical_hash(payload)
