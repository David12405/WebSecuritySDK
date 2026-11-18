"""Canonical Pydantic I/O contract models for Module 3 validation capabilities."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator

from websecuritycheck.domain.enums import InputLocation
from websecuritycheck.domain.models import StrictModel, _validate_opaque_artifact_ref

SUPPORTED_SQLI_LOCATIONS = frozenset(
    {
        InputLocation.QUERY,
        InputLocation.FORM,
        InputLocation.JSON_BODY,
        InputLocation.COOKIE,
        InputLocation.HEADER,
    }
)


class SQLiTechnique(StrEnum):
    """Supported non-destructive SQLi detection techniques in v0.1."""

    ERROR = "ERROR"
    BOOLEAN = "BOOLEAN"
    UNION = "UNION"
    TIME = "TIME"


class CapabilityExecutionStatus(StrEnum):
    """Execution lifecycle status for Module 3 capabilities."""

    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


class DetectionStatus(StrEnum):
    """Capability-level security detection status."""

    CONFIRMED = "CONFIRMED"
    NOT_DETECTED = "NOT_DETECTED"
    HEURISTIC_ONLY = "HEURISTIC_ONLY"
    INCONCLUSIVE = "INCONCLUSIVE"


class RiskProfile(StrEnum):
    """Permitted execution risk profile."""

    LOW = "LOW"


class HttpRequestCapabilityInput(StrictModel):
    """Input contract for ``HTTP_REQUEST`` baseline verification."""

    request_artifact_ref: str | None = None
    target_url: str = Field(min_length=1)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    headers_ref: str | None = None
    body_ref: str | None = None
    auth_ref: str | None = None
    sample_count: int = Field(default=2, ge=1, le=3)
    timeout_seconds: int = Field(default=15, ge=1, le=60)

    @field_validator("request_artifact_ref", "headers_ref", "body_ref")
    @classmethod
    def validate_optional_opaque_ref(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_opaque_artifact_ref(value)
        return value


class HttpRequestCapabilityOutput(StrictModel):
    """Output contract for ``HTTP_REQUEST`` matching ``docs/CAPABILITY_CONTRACTS.md``."""

    execution_status: CapabilityExecutionStatus
    http_status: int | None = Field(default=None, ge=100, le=599)
    reachable: bool | None = None
    auth_failure_detected: bool | None = None
    rate_limited: bool | None = None
    waf_or_filter_detected: bool | None = None
    target_stable: bool | None = None
    baseline_ready: bool
    artifact_refs: list[str] = Field(default_factory=list)
    error_code: str | None = None


class SQLiProof(StrictModel):
    """Structured per-technique SQLi verification proof."""

    technique: SQLiTechnique
    parameter_name: str = Field(min_length=1)
    verification_method: str = Field(min_length=1)
    control_observation_refs: list[str] = Field(default_factory=list)
    test_observation_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    redacted_payload_summary: str | None = None
    repeatable: bool | None = None
    verified: bool = False


class SqliDetectionCapabilityInput(StrictModel):
    """Input contract for ``SQLI_DETECTION`` matching ``docs/CAPABILITY_CONTRACTS.md``."""

    request_artifact_ref: str | None = None
    target_url: str = Field(min_length=1)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    parameter_name: str = Field(min_length=1)
    parameter_location: InputLocation
    auth_ref: str | None = None
    baseline_artifact_refs: list[str] = Field(min_length=1)
    techniques: list[SQLiTechnique] = Field(
        default_factory=lambda: [SQLiTechnique.ERROR, SQLiTechnique.BOOLEAN, SQLiTechnique.UNION],
        min_length=1,
    )
    dbms_hint: str | None = None
    max_requests: int = Field(default=150, ge=10, le=500)
    timeout_seconds: int = Field(default=120, ge=5, le=300)
    risk_profile: RiskProfile = RiskProfile.LOW

    @field_validator("request_artifact_ref")
    @classmethod
    def validate_request_ref(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_opaque_artifact_ref(value)
        return value

    @field_validator("dbms_hint")
    @classmethod
    def validate_dbms_hint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if cleaned.startswith("-"):
            raise ValueError(
                "dbms_hint must be null or a valid DBMS name, "
                "not a CLI flag or placeholder like '--'"
            )
        return cleaned

    @field_validator("baseline_artifact_refs")
    @classmethod
    def validate_baseline_refs(cls, value: list[str]) -> list[str]:
        for item in value:
            if not item:
                raise ValueError("baseline_artifact_refs entries must be non-empty")
            _validate_opaque_artifact_ref(item)
        return value


class SqliDetectionCapabilityOutput(StrictModel):
    """Output contract for ``SQLI_DETECTION`` matching ``docs/CAPABILITY_CONTRACTS.md``."""

    execution_status: CapabilityExecutionStatus
    detection_status: DetectionStatus
    tested_techniques: list[SQLiTechnique] = Field(default_factory=list)
    confirmed_techniques: list[SQLiTechnique] = Field(default_factory=list)
    heuristic_signal_detected: bool = False
    target_stable: bool | None = None
    auth_failure_detected: bool | None = None
    rate_limited: bool | None = None
    waf_or_filter_detected: bool | None = None
    dbms_identified: str | None = None
    proofs: list[SQLiProof] = Field(default_factory=list)
    artifact_refs: list[str] = Field(default_factory=list)
    error_code: str | None = None
