"""Opt-in live source -> test-plan integration: Module 2 -> hypothesis -> Stage A/B.

This is the full vertical the two halves of the project meet on: tanbrando's
deterministic Module 2 (Opengrep + AST taint over real source) produces a sealed
envelope, the hypothesis layer turns its correlations into guarded SQLi
hypotheses, and Stage A/B turns each hypothesis into an admitted test plan.

It runs Module 2 live (Opengrep scans the Cloudflare `api` target's source), but
reuses the captured Module 1 request so no network probe is needed. Opengrep has
no Windows build, so this runs in WSL, where the captured request's `/mnt/d/...`
source path resolves.

By default Stage A/B uses the real LLM (gpt-4o, reading OPENAI_API_KEY from .env)
and the official OWASP WSTG source over the network. Set WEBSEC_PLAN_LLM=0 and
WEBSEC_WSTG_SOURCE=recorded for a deterministic, offline, no-cost run. The LLM
path skips (not fails) when no API key is configured.

Run (from the repo root, inside WSL; needs `openai` installed in the interpreter):

    RUN_LIVE_M1_M2=1 \
    WEBSEC_OPENGREP_PATH=opengrep \
    WEBSEC_OPENGREP_RULESET="$(pwd)/tests/test_analysis/rules/cloudflare-workers-injection.yml" \
    python -m pytest tests/test_tactic_planning/test_source_to_plan_live.py -s

Without RUN_LIVE_M1_M2 it skips, so the default offline suite is unaffected.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from test_analysis.m1_m2_live_support import (
    LiveDependencyError,
    resolve_primary_ruleset,
    trust_policy,
)

from websecuritycheck.analysis.opengrep_adapter import (
    LocalOpengrepAdapter,
    compute_ruleset_sha256,
)
from websecuritycheck.domain.analysis_models import (
    Module2AnalysisRequest,
    VulnerabilityCategory,
)
from websecuritycheck.hypothesis import generate_hypotheses
from websecuritycheck.pipeline import run_module2
from websecuritycheck.tactic_planning.stage_a import (
    FakeTacticAuthor,
    FileTacticRegistry,
    GithubWstgAdapter,
    RecordedWstgAdapter,
    StrandsTacticAuthor,
)
from websecuritycheck.tactic_planning.stage_b import (
    FakePlanner,
    PlanningStatus,
    StrandsPlanner,
    prepare_sql_injection_plan,
)

from ._factories import (
    WSTG_DIR,
    enabled_policy,
    reference_tactic_document,
    valid_plan_draft,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
REQUEST_API = (
    REPO_ROOT / "tests" / "test_analysis" / "captured_envelopes" / "request_api.json"
)

LIVE_REQUIRED = pytest.mark.skipif(
    os.getenv("RUN_LIVE_M1_M2") != "1",
    reason="set RUN_LIVE_M1_M2=1 to run the authorized WHITEBOX source->plan test",
)


def _load_dotenv() -> None:
    """Read KEY=value lines from .env into the environment (no overwrite)."""
    env_path = REPO_ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


@pytest.mark.live_m1_m2
@pytest.mark.opengrep_cli
@LIVE_REQUIRED
def test_source_to_plan_api(tmp_path: Path) -> None:
    try:
        ruleset = resolve_primary_ruleset()
    except LiveDependencyError as exc:
        pytest.skip(str(exc))

    request = Module2AnalysisRequest.model_validate(
        json.loads(REQUEST_API.read_text(encoding="utf-8"))
    )
    if not request.source_repo_path or not Path(request.source_repo_path).is_dir():
        pytest.skip(
            f"source not reachable at {request.source_repo_path}; run in WSL where "
            "the captured /mnt/d path resolves"
        )

    # --- Module 2 live: Opengrep + AST taint over the real source ------------- #
    policy = trust_policy(compute_ruleset_sha256(ruleset))
    envelope = asyncio.run(
        run_module2(
            request,
            trust_policy=policy,
            analyzer=LocalOpengrepAdapter(ruleset_path=ruleset),
        )
    )

    # --- Hypotheses from the freshly analysed envelope ------------------------ #
    generation = generate_hypotheses(envelope.output, envelope.correlation.records)
    sqli = [
        h
        for h in generation.hypotheses
        if h.vulnerability_category == VulnerabilityCategory.SQL_INJECTION
    ]
    assert sqli, "the Cloudflare api target should yield a SQL_INJECTION hypothesis"

    # --- Stage A/B: author the tactic and plan each hypothesis ---------------- #
    # Defaults to the real LLM (gpt-4o) and the official OWASP WSTG source.
    # Opt out for a deterministic, offline, no-cost run with:
    #   WEBSEC_PLAN_LLM=0 WEBSEC_WSTG_SOURCE=recorded
    use_llm = os.getenv("WEBSEC_PLAN_LLM", "1") != "0"
    wstg_source = os.getenv("WEBSEC_WSTG_SOURCE", "github")

    if use_llm:
        _load_dotenv()
        if not os.environ.get("OPENAI_API_KEY"):
            pytest.skip("set OPENAI_API_KEY (or WEBSEC_PLAN_LLM=0) for the LLM path")
        model_name = os.getenv("WEBSEC_MODEL", "openai:gpt-4o")
        author = StrandsTacticAuthor(model_name)
        planner = StrandsPlanner(model_name)
    else:
        model_name = "fake:deterministic"
        author = FakeTacticAuthor(reference_tactic_document())
        planner = FakePlanner(valid_plan_draft())

    adapter = GithubWstgAdapter() if wstg_source == "github" else RecordedWstgAdapter(WSTG_DIR)
    registry = FileTacticRegistry(tmp_path / "registry")
    safety = enabled_policy()
    print(f"[source->plan] author/planner={'gpt-4o' if use_llm else 'deterministic'}, "
          f"wstg={wstg_source}")

    planned = 0
    for hypothesis in sqli:
        result = prepare_sql_injection_plan(
            generation,
            hypothesis.hypothesis_id,
            envelope,
            request,
            registry=registry,
            author=author,
            planner=planner,
            wstg_adapter=adapter,
            safety_policy=safety,
            model_name=model_name,
        )
        assert result.status == PlanningStatus.READY, (
            f"{hypothesis.hypothesis_id}: {result.status.value} "
            f"{[e.code for e in result.errors]}"
        )
        plan = result.plan
        assert plan is not None
        assert plan.target_binding.input_ref == hypothesis.input_ref
        assert plan.test_cases
        planned += 1
        print(
            f"[source->plan] {hypothesis.hypothesis_id} {hypothesis.input_ref} "
            f"-> {plan.plan_id} ({len(plan.test_cases)} test cases, "
            f"tactic {plan.tactic_ref.tactic_version})"
        )

    assert planned == len(sqli)
