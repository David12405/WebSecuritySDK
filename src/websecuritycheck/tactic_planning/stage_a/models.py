"""Stage A domain models: the tactic, its WSTG provenance, and its identity.

`TacticDocument` is a faithful Pydantic mirror of `schemas/tactic.schema.json`.
It is used twice: as the structured-output target the authoring model fills in,
and as the canonical object the admission gates validate. One model, no transport
schema and no projector - the strictness the OpenAI docs ask of a transport
schema is exactly what `StrictModel` (`extra="forbid"`) already gives, and a
single source cannot drift from itself.

Everything that carries identity - the tactic version, the content and schema
hashes, the compatibility fingerprint, the authoring provenance - lives in
`TacticMetadata` beside the document, never inside it. A model fills in the
document; code owns the metadata.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints, model_validator

from ...domain.models import StrictModel

TACTIC_SCHEMA_VERSION = "0.1.0"

#: The bundled canonical JSON Schema, imported from the approved v0.1.0 input.
SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "tactic.schema.json"

#: Canonical identifiers code allocates; a model never emits them.
CANONICAL_TACTIC_ID = "TACTIC-SQLI-001"
CANONICAL_TACTIC_NAME = "sqli_testing"

TacticId = Annotated[str, StringConstraints(pattern=r"^TACTIC-[A-Z0-9-]+$")]
TacticName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]
StepId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]
CapabilityId = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9_]*$")]
ContextName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$")]

_OUTCOMES = (
    "CONFIRMED",
    "NOT_CONFIRMED",
    "INCONCLUSIVE",
    "ERROR",
    "UNSUPPORTED",
    "POLICY_BLOCKED",
)


def canonical_hash(payload: object) -> str:
    """SHA-256 over canonical JSON (sorted keys), so formatting is not identity."""
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@lru_cache(maxsize=1)
def bundled_schema_sha256() -> str:
    """SHA-256 of the bundled tactic JSON Schema bytes, for the fingerprint."""
    return hashlib.sha256(SCHEMA_PATH.read_bytes()).hexdigest()


# --------------------------------------------------------------------------- #
# The tactic document (mirror of tactic.schema.json v0.1.0)
# --------------------------------------------------------------------------- #


class TacticScope(StrictModel):
    vulnerability: str = Field(min_length=1)
    supported_input_locations: list[str] = Field(min_length=1)
    limitations: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_locations(self) -> TacticScope:
        if len(set(self.supported_input_locations)) != len(self.supported_input_locations):
            raise ValueError("supported_input_locations must be unique")
        return self


class RequiredContext(StrictModel):
    name: ContextName
    source: str = Field(min_length=1)
    required: bool
    description: str | None = Field(default=None, min_length=1)


class TacticCapability(StrictModel):
    id: CapabilityId
    contract_ref: str = Field(min_length=1)
    role: Literal["required", "optional"] | None = None


class NextOption(StrictModel):
    when: str = Field(min_length=1)
    action: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class StepSuggestedInputs(StrictModel):
    """Advisory per-step defaults.

    A closed, typed object rather than an open dict: an open object cannot carry
    `additionalProperties: false`, which OpenAI's strict Structured Outputs
    requires, so an open dict here makes the whole tactic schema unusable as an
    authoring response format. These values are advisory only - the real ceilings
    live in SQLiSafetyPolicy and the Stage B plan.
    """

    sample_count: int | None = None
    timeout_seconds: int | None = None
    techniques: list[str] | None = None
    risk_profile: str | None = None
    max_requests: int | None = None


class TacticStep(StrictModel):
    id: StepId
    goal: str = Field(min_length=1)
    recommended_capability: str | None = None
    optional: bool = False
    guidance: str = Field(min_length=1)
    suggested_inputs: StepSuggestedInputs | None = None
    next_options: list[NextOption] = Field(min_length=1)


class TacticDocument(StrictModel):
    """Canonical tactic, faithful to tactic.schema.json v0.1.0."""

    schema_version: Literal["0.1.0"] = "0.1.0"
    tactic_id: TacticId
    name: TacticName
    mode: Literal["GUIDED_AGENT"] = "GUIDED_AGENT"
    scope: TacticScope
    references: list[str] = Field(min_length=1)
    required_context: list[RequiredContext] = Field(min_length=1)
    capabilities: list[TacticCapability] = Field(min_length=1)
    safety_rules: list[str] = Field(min_length=1)
    steps: list[TacticStep] = Field(min_length=1)
    outcomes: list[str] = Field(min_length=6, max_length=6)
    confirmation_rules: list[str] = Field(min_length=1)
    upgrade_notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_outcomes(self) -> TacticDocument:
        if sorted(self.outcomes) != sorted(_OUTCOMES):
            raise ValueError(f"outcomes must be exactly {set(_OUTCOMES)}")
        return self

    def canonical_content_hash(self) -> str:
        """Identity of the tactic's content, independent of YAML formatting."""
        return canonical_hash(self.model_dump(mode="json"))


# --------------------------------------------------------------------------- #
# WSTG provenance
# --------------------------------------------------------------------------- #


class WstgSnapshot(StrictModel):
    """Normalized WSTG retrieval, preserving the complete returned content."""

    requested_id: str = Field(min_length=1)
    returned_id: str = Field(min_length=1)
    wstg_version: str = Field(min_length=1)
    content: str = Field(min_length=1)
    chunks: list[str] = Field(default_factory=list)
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)
    source_uri: str | None = None
    mcp_server: str | None = None
    upstream_metadata: dict[str, Any] = Field(default_factory=dict)
    license: str = "CC BY-SA 4.0"
    attribution: str = "OWASP Web Security Testing Guide"

    def content_hash(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()


class WstgSnapshotMetadata(StrictModel):
    """Canonical-JSON sidecar persisted beside a raw WSTG snapshot."""

    requested_id: str
    returned_id: str
    wstg_version: str
    source_uri: str | None = None
    retrieved_at: datetime
    mcp_server: str | None = None
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    license: str = "CC BY-SA 4.0"
    attribution: str = "OWASP Web Security Testing Guide"
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Identity, compatibility, metadata
# --------------------------------------------------------------------------- #


class TacticState(StrEnum):
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    REJECTED = "REJECTED"


class EnvironmentFingerprint(StrictModel):
    """The reuse key that does not require re-querying WSTG.

    Everything whose change must invalidate reuse, except the live WSTG content
    hash - so a warm registry is reused without any WSTG retrieval, honouring the
    goal that only a cold registry pays for the upstream service. A change to the
    WSTG dataset is signalled by its version, which is included here.
    """

    vulnerability_category: str
    wstg_version: str
    tactic_schema_version: str
    tactic_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    capability_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    safety_policy_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")

    def value(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))


class CompatibilityFingerprint(StrictModel):
    """Full identity recorded at authoring time: environment plus WSTG content."""

    vulnerability_category: str
    wstg_version: str
    wstg_content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    tactic_schema_version: str
    tactic_schema_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    capability_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    safety_policy_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")

    def value(self) -> str:
        return canonical_hash(self.model_dump(mode="json"))


class TacticMetadata(StrictModel):
    """Everything about a tactic that is not the tactic itself."""

    tactic_id: str
    tactic_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    schema_version: str
    vulnerability_category: str
    state: TacticState
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    compatibility: CompatibilityFingerprint
    compatibility_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    environment_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    wstg_requested_id: str
    wstg_version: str
    authoring_model: str
    prompt_version: str
    authoring_attempts: int = Field(ge=1)
    created_at: datetime
    validation_report: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def fingerprint_matches(self) -> TacticMetadata:
        if self.compatibility.value() != self.compatibility_fingerprint:
            raise ValueError("compatibility_fingerprint does not match its components")
        return self


class ManifestEntry(StrictModel):
    active_version: str | None = None
    versions: list[str] = Field(default_factory=list)


class RegistryManifest(StrictModel):
    schema_id: Literal["websecuritycheck.tactic_registry.v1"] = (
        "websecuritycheck.tactic_registry.v1"
    )
    tactics: dict[str, ManifestEntry] = Field(default_factory=dict)


class AdmittedTactic(StrictModel):
    """A published, reusable tactic paired with its metadata."""

    document: TacticDocument
    metadata: TacticMetadata
