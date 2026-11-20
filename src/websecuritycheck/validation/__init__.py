"""Module 3 validation capability adapters and deterministic proof verifiers."""

from .executor import ValidationPlanExecutor
from .http_baseline import HttpBaselineAdapter
from .models import (
    SUPPORTED_SQLI_LOCATIONS,
    CapabilityExecutionStatus,
    DetectionStatus,
    HttpRequestCapabilityInput,
    HttpRequestCapabilityOutput,
    PlanExecutionResult,
    RiskProfile,
    SqliDetectionCapabilityInput,
    SqliDetectionCapabilityOutput,
    SQLiProof,
    SQLiTechnique,
    TestCaseExecutionRecord,
    ValidationOutcome,
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
    "PlanExecutionResult",
    "RequestMaterializerProtocol",
    "ResolvedAuthContext",
    "RiskProfile",
    "SQLiProof",
    "SQLiTechnique",
    "SqliDetectionCapabilityInput",
    "SqliDetectionCapabilityOutput",
    "SqlmapDetectionAdapter",
    "TestCaseExecutionRecord",
    "ValidationOutcome",
    "ValidationPlanExecutor",
    "verify_sqli_proofs",
]
