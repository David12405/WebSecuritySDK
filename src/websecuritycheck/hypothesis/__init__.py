"""Hypothesis generation over Module 2 correlation output.

Module 2 says two clues are related. This package says what that would mean
if it were true, and what would settle it - without ever asserting that it
is true. `generate` builds the hypotheses, `guard` re-checks them against the
relations they came from.
"""

from __future__ import annotations

from .generate import (
    CAPABILITY_FOR,
    SIGNALS_FOR,
    GenerationResult,
    InputChoice,
    InputSelector,
    SelectionRequest,
    generate_hypotheses,
    heuristic_selector,
)
from .guard import HypothesisGuardError, check_hypotheses, enforce
from .labels import describe, endpoint_labels, label_for
from .llm import LLMInputSelector, SelectionAnswer
from .slices import (
    CodeRange,
    SourceSlicer,
    describe_slices,
    handler_ranges,
    slices_for_records,
)

__all__ = [
    "CAPABILITY_FOR",
    "SIGNALS_FOR",
    "CodeRange",
    "GenerationResult",
    "HypothesisGuardError",
    "InputChoice",
    "InputSelector",
    "LLMInputSelector",
    "SelectionAnswer",
    "SelectionRequest",
    "SourceSlicer",
    "check_hypotheses",
    "describe",
    "describe_slices",
    "endpoint_labels",
    "enforce",
    "generate_hypotheses",
    "handler_ranges",
    "heuristic_selector",
    "label_for",
    "slices_for_records",
]
