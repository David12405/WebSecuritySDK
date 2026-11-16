"""Stage A - tactic authoring.

Retrieve the WSTG methodology, author a reusable SQLi tactic, admit it through
deterministic gates, and publish an immutable version - or reuse the active one.
"""

from __future__ import annotations

from .author import (
    PROMPT_VERSION,
    FakeTacticAuthor,
    StrandsTacticAuthor,
    TacticAuthor,
    TacticAuthorError,
)
from .models import (
    CANONICAL_TACTIC_ID,
    CANONICAL_TACTIC_NAME,
    TACTIC_SCHEMA_VERSION,
    AdmittedTactic,
    CompatibilityFingerprint,
    EnvironmentFingerprint,
    TacticDocument,
    TacticMetadata,
    TacticState,
    bundled_schema_sha256,
)
from .registry import DEFAULT_ROOT, FileTacticRegistry, RegistryError, TacticRegistry
from .resolver import (
    DEFAULT_MAX_RETRIES,
    ResolvedTactic,
    TacticResolutionError,
    environment_fingerprint,
    resolve_tactic,
)
from .validation import REQUIRED_WSTG_REFERENCE, admit_tactic
from .wstg import (
    CATEGORY_TO_WSTG,
    EXPECTED_WSTG_VERSION,
    OWASP_WSTG_TAG,
    WSTG_DOC_PATHS,
    GithubWstgAdapter,
    RecordedWstgAdapter,
    WstgAdapter,
    WstgRetrievalError,
    WstgSnapshot,
    reference_for,
    retrieve_snapshot,
    validate_snapshot,
)

__all__ = [
    "CANONICAL_TACTIC_ID",
    "CANONICAL_TACTIC_NAME",
    "CATEGORY_TO_WSTG",
    "DEFAULT_MAX_RETRIES",
    "DEFAULT_ROOT",
    "EXPECTED_WSTG_VERSION",
    "OWASP_WSTG_TAG",
    "PROMPT_VERSION",
    "REQUIRED_WSTG_REFERENCE",
    "TACTIC_SCHEMA_VERSION",
    "WSTG_DOC_PATHS",
    "AdmittedTactic",
    "CompatibilityFingerprint",
    "EnvironmentFingerprint",
    "FakeTacticAuthor",
    "FileTacticRegistry",
    "GithubWstgAdapter",
    "RecordedWstgAdapter",
    "RegistryError",
    "ResolvedTactic",
    "StrandsTacticAuthor",
    "TacticAuthor",
    "TacticAuthorError",
    "TacticDocument",
    "TacticMetadata",
    "TacticRegistry",
    "TacticResolutionError",
    "TacticState",
    "WstgAdapter",
    "WstgRetrievalError",
    "WstgSnapshot",
    "admit_tactic",
    "bundled_schema_sha256",
    "environment_fingerprint",
    "reference_for",
    "resolve_tactic",
    "retrieve_snapshot",
    "validate_snapshot",
]
