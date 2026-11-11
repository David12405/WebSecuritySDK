"""Deterministic InputCandidate extraction and normalization (M2-T02).

Consumes canonical Module 1 outputs wrapped in Module2AnalysisRequest and produces
deduplicated, strictly record-grounded InputCandidate records with stable INP-001..N IDs.

Trust Boundary:
`caller_asserted_evidence_ids` and `caller_asserted_observation_ids` (or their aliases
`verified_evidence_ids` / `verified_observation_ids`) represent trusted caller-provided
assertions (e.g. historical records validated by TargetStore or external evidence repository).
The extraction function does not independently query external databases or verify their
underlying storage integrity; it accepts them strictly as authoritative assertions from the caller.
"""

from __future__ import annotations

from .extractor import extract_input_candidates
from .models import (
    InputExtractionResult,
    input_identity_key,
    normalize_parameter_name,
)

__all__ = [
    "InputExtractionResult",
    "extract_input_candidates",
    "input_identity_key",
    "normalize_parameter_name",
]

