"""Module 2 Injection-Focused CVE Matching and Candidate Extraction."""

from __future__ import annotations

from .extractor import aextract_cve_candidates, extract_cve_candidates
from .models import (
    CPEProductEntry,
    CVEAdvisoryRecord,
    CVECorrelationMetadata,
    CVEEvaluationDiagnostic,
    CVEExtractionResult,
    CVEProviderError,
    InjectionScopeEvaluation,
    InjectionScopeStatus,
    InjectionSubtype,
    ProductMatchKind,
    TrustedInjectionClassification,
    VersionApplicability,
    VersionScheme,
)
from .policy import (
    CONTEXT_DEPENDENT_CWES,
    DEFAULT_TRUSTED_INJECTION_CLASSIFICATIONS,
    DIRECT_INJECTION_CWES,
    EXCLUDED_CWES,
    InjectionScopePolicy,
)
from .provider import (
    AsyncVulnerabilityKnowledgePort,
    LocalSeedCVEProvider,
    VulnerabilityKnowledgeProvider,
)
from .version_matcher import (
    evaluate_version_applicability,
    normalize_technology_fingerprint,
)

__all__ = [
    "CONTEXT_DEPENDENT_CWES",
    "DEFAULT_TRUSTED_INJECTION_CLASSIFICATIONS",
    "DIRECT_INJECTION_CWES",
    "EXCLUDED_CWES",
    "AsyncVulnerabilityKnowledgePort",
    "CPEProductEntry",
    "CVEAdvisoryRecord",
    "CVECorrelationMetadata",
    "CVEEvaluationDiagnostic",
    "CVEExtractionResult",
    "CVEProviderError",
    "InjectionScopeEvaluation",
    "InjectionScopePolicy",
    "InjectionScopeStatus",
    "InjectionSubtype",
    "LocalSeedCVEProvider",
    "ProductMatchKind",
    "TrustedInjectionClassification",
    "VersionApplicability",
    "VersionScheme",
    "VulnerabilityKnowledgeProvider",
    "aextract_cve_candidates",
    "evaluate_version_applicability",
    "extract_cve_candidates",
    "normalize_technology_fingerprint",
]
