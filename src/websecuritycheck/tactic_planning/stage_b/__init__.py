"""Stage B - per-hypothesis validation planning.

Combine one guarded hypothesis, the active tactic, and trusted target context
into a structured, admitted test plan for Module 3 - or a typed non-READY result
explaining why no plan was produced.
"""

from __future__ import annotations

from .coordinator import prepare_sql_injection_plan
from .models import (
    ExecutionLimits,
    GuardedHypothesisContext,
    PlanningContext,
    PlanningPreparationError,
    PlanningPreparationResult,
    PlanningStage,
    PlanningStatus,
    ResolvedRequestTemplate,
    StopCondition,
    StructuredTestPlan,
    TacticRef,
    TargetBinding,
    TestCase,
    TestCaseDraft,
    TestPlanDraft,
)
from .planner import (
    PROMPT_VERSION,
    DefaultRequestTemplateResolver,
    FakePlanner,
    Planner,
    PlannerError,
    RequestTemplateResolver,
    StrandsPlanner,
    prompt_for,
)
from .validation import assemble_plan, validate_plan

__all__ = [
    "PROMPT_VERSION",
    "DefaultRequestTemplateResolver",
    "ExecutionLimits",
    "FakePlanner",
    "GuardedHypothesisContext",
    "Planner",
    "PlannerError",
    "PlanningContext",
    "PlanningPreparationError",
    "PlanningPreparationResult",
    "PlanningStage",
    "PlanningStatus",
    "RequestTemplateResolver",
    "ResolvedRequestTemplate",
    "StopCondition",
    "StrandsPlanner",
    "StructuredTestPlan",
    "TacticRef",
    "TargetBinding",
    "TestCase",
    "TestCaseDraft",
    "TestPlanDraft",
    "assemble_plan",
    "prepare_sql_injection_plan",
    "prompt_for",
    "validate_plan",
]
