"""Module 3 validation capability adapters and deterministic proof verifiers."""

from .http_baseline import HttpBaselineAdapter
from .models import (
    SUPPORTED_SQLI_LOCATIONS,
    CapabilityExecutionStatus,
    DetectionStatus,
    HttpRequestCapabilityInput,
    HttpRequestCapabilityOutput,
    RiskProfile,
    SqliDetectionCapabilityInput,
    SqliDetectionCapabilityOutput,
    SQLiProof,
    SQLiTechnique,
)
from .resolvers import (
    InMemoryRequestMaterializer,
    MaterializedRequest,
    RequestMaterializerProtocol,
    ResolvedAuthContext,
)
from .sqlmap_adapter import SqlmapDetectionAdapter
from .verifier import verify_sqli_proofs

__all__ = [
    "SUPPORTED_SQLI_LOCATIONS",
    "CapabilityExecutionStatus",
    "DetectionStatus",
    "HttpBaselineAdapter",
    "HttpRequestCapabilityInput",
    "HttpRequestCapabilityOutput",
    "InMemoryRequestMaterializer",
    "MaterializedRequest",
    "RequestMaterializerProtocol",
    "ResolvedAuthContext",
    "RiskProfile",
    "SQLiProof",
    "SQLiTechnique",
    "SqliDetectionCapabilityInput",
    "SqliDetectionCapabilityOutput",
    "SqlmapDetectionAdapter",
    "verify_sqli_proofs",
]
