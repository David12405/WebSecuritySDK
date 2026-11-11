"""Domain enums, advisory schemas, and extraction result models for CVE matching."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from websecuritycheck.domain.analysis_models import (
    CVECandidate,
    CveCandidateId,
    CveId,
    CweId,
)
from websecuritycheck.domain.enums import TechnologyCategory


class InjectionSubtype(StrEnum):
    """Subtypes within OWASP Top 10:2025 A05: Injection."""

    SQL_INJECTION = "SQL_INJECTION"
    OS_COMMAND_INJECTION = "OS_COMMAND_INJECTION"
    NOSQL_INJECTION = "NOSQL_INJECTION"
    LDAP_INJECTION = "LDAP_INJECTION"
    XPATH_INJECTION = "XPATH_INJECTION"
    ORM_QUERY_INJECTION = "ORM_QUERY_INJECTION"
    SSTI = "SSTI"
    CODE_INJECTION = "CODE_INJECTION"


class InjectionScopeStatus(StrEnum):
    """Decision status returned by InjectionScopePolicy."""

    ALLOWED = "ALLOWED"
    EXCLUDED = "EXCLUDED"
    UNKNOWN = "UNKNOWN"


class ProductMatchKind(StrEnum):
    """Matching fidelity between observed technology and known product entry."""

    EXACT = "EXACT"
    ALIAS = "ALIAS"
    AMBIGUOUS = "AMBIGUOUS"
    UNMAPPED = "UNMAPPED"


class VersionScheme(StrEnum):
    """Supported version parsing and comparison scheme."""

    NUMERIC_DOT = "NUMERIC_DOT"


class VersionApplicability(StrEnum):
    """Tri-state version evaluation outcome."""

    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"


class CVEProviderError(RuntimeError):
    """Raised when a vulnerability knowledge provider fails or contains invalid data."""


class CVEAdvisoryRecord(BaseModel):
    """Vulnerability advisory record returned by a knowledge provider.

    Deliberately omits any provider-asserted override flags to preserve the
    InjectionScopePolicy trust boundary.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: CveId
    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)
    cpe_prefix: str = Field(min_length=1)
    version_scheme: VersionScheme = VersionScheme.NUMERIC_DOT
    affected_range: str = Field(min_length=1)
    primary_cwe_id: CweId | None = None
    cwe_ids: tuple[CweId, ...] = Field(default_factory=tuple)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    injection_subtype: InjectionSubtype | None = None
    injection_rationale: str | None = None
    environmental_preconditions: tuple[str, ...] = Field(default_factory=tuple)
    summary: str = Field(min_length=5)
    advisory_source: str = Field(min_length=3)
    published_date: str = Field(min_length=4)
    advisory_url: str | None = None
    provider_name: str = Field(default="local_seed_catalog", min_length=1)
    catalog_version: str = Field(default="2026.03", min_length=1)


class CPEProductEntry(BaseModel):
    """Product resolution and mapping definition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)
    cpe_prefix: str = Field(min_length=1)
    version_scheme: VersionScheme = VersionScheme.NUMERIC_DOT
    exact_names: tuple[str, ...] = Field(default_factory=tuple)
    aliases: tuple[str, ...] = Field(default_factory=tuple)
    allowed_categories: tuple[TechnologyCategory, ...] = Field(default_factory=tuple)


class TrustedInjectionClassification(BaseModel):
    """Policy-owned curated classification for multi-CWE or context-dependent CVEs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: CveId
    expected_cwe_ids: frozenset[CweId]
    canonical_subtype: InjectionSubtype
    policy_rationale: str = Field(min_length=10)


class InjectionScopeEvaluation(BaseModel):
    """Result of evaluating an advisory against InjectionScopePolicy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: InjectionScopeStatus
    subtype: InjectionSubtype | None = None
    matched_cwe_id: CweId | None = None
    used_trusted_allowlist: bool = False
    reason: str = Field(min_length=3)


class CVEEvaluationDiagnostic(BaseModel):
    """Structured diagnostic record explaining an evaluation outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technology_name: str
    technology_version: str | None = None
    cve_id: CveId | None = None
    stage: Literal[
        "grounding",
        "product_matching",
        "version_parsing",
        "injection_scope",
        "version_applicability",
        "catalog_coverage",
    ]
    outcome: Literal["SKIPPED", "EXCLUDED", "UNKNOWN"]
    reason: str


class CVECorrelationMetadata(BaseModel):
    """Detailed advisory and environment metadata companion to CVECandidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_candidate_id: CveCandidateId
    cve_id: CveId
    matched_cpe: str
    product_match_kind: ProductMatchKind
    injection_subtype: InjectionSubtype
    environmental_preconditions: tuple[str, ...] = Field(default_factory=tuple)
    independent_source_count: int = Field(ge=1)
    provider_name: str
    catalog_version: str
    advisory_source: str
    published_date: str
    advisory_url: str | None = None


class CVEExtractionResult(BaseModel):
    """Complete Module 2 deterministic CVE candidate extraction output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_candidates: tuple[CVECandidate, ...] = Field(default_factory=tuple)
    correlation_metadata: tuple[CVECorrelationMetadata, ...] = Field(default_factory=tuple)
    diagnostics: tuple[CVEEvaluationDiagnostic, ...] = Field(default_factory=tuple)
    limitations: tuple[str, ...] = Field(default_factory=tuple)


__all__ = [
    "CPEProductEntry",
    "CVEAdvisoryRecord",
    "CVECorrelationMetadata",
    "CVEEvaluationDiagnostic",
    "CVEExtractionResult",
    "CVEProviderError",
    "InjectionScopeEvaluation",
    "InjectionScopeStatus",
    "InjectionSubtype",
    "ProductMatchKind",
    "TrustedInjectionClassification",
    "VersionApplicability",
    "VersionScheme",
]

