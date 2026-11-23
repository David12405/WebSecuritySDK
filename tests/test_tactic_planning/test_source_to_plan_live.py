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

Run (from the repo root, inside WSL; needs `openai` installed in the interpreter).
Set WEBSEC_REPORT_PATH to also emit a printable HTML report of every plan:

    RUN_LIVE_M1_M2=1 \
    WEBSEC_OPENGREP_PATH=opengrep \
    WEBSEC_OPENGREP_RULESET="$(pwd)/tests/test_analysis/rules/cloudflare-workers-injection.yml" \
    WEBSEC_REPORT_PATH="$(pwd)/source_to_plan_report.html" \
    python -m pytest tests/test_tactic_planning/test_source_to_plan_live.py -s

WEBSEC_TARGETS picks which captured Cloudflare targets to plan against, as a
comma-separated list of `TARGET_CASES` names; it defaults to `api`. Each target
needs its `request_<name>.json` fixture, which `test_pipeline_capture.py` writes
on a live capture run. `basic` carries no SQL-injection rule, so it skips rather
than fails - this vertical only plans SQLi:

    WEBSEC_TARGETS=api,spa ... python -m pytest ... -s

With more than one target WEBSEC_REPORT_PATH gains a per-target suffix, so the
runs do not overwrite each other's report.

Without RUN_LIVE_M1_M2 it skips, so the default offline suite is unaffected.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from test_analysis.m1_m2_live_support import (
    TARGET_CASES,
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
    build_m3_handoff,
    format_test_plan,
    prepare_sql_injection_plan,
    render_report_html,
)

from ._factories import (
    WSTG_DIR,
    enabled_policy,
    reference_tactic_document,
    valid_plan_draft,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURE_DIR = REPO_ROOT / "tests" / "test_analysis" / "captured_envelopes"


def _selected_targets() -> list[str]:
    """Target names from WEBSEC_TARGETS, defaulting to the one captured target."""
    known = {case.name for case in TARGET_CASES}
    raw = os.getenv("WEBSEC_TARGETS", "api")
    names = [name.strip() for name in raw.split(",") if name.strip()]
    unknown = sorted(set(names) - known)
    if unknown:
        raise ValueError(
            f"WEBSEC_TARGETS names unknown target(s) {unknown}; "
            f"choose from {sorted(known)}"
        )
    return names


def _report_path_for(target: str, selected: list[str]) -> Path | None:
    """Per-target report path, so a multi-target run keeps every report."""
    raw = os.getenv("WEBSEC_REPORT_PATH")
    if not raw:
        return None
    path = Path(raw)
    if len(selected) == 1:
        return path
    return path.with_name(f"{path.stem}_{target}{path.suffix}")

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
@pytest.mark.parametrize("target", _selected_targets())
def test_source_to_plan(target: str, tmp_path: Path) -> None:
    selected = _selected_targets()
    case = next(item for item in TARGET_CASES if item.name == target)

    # This vertical plans SQLi only, so a target whose ruleset cannot produce a
    # SQL-injection finding has nothing to plan - skip instead of failing the
    # "should yield a SQL_INJECTION hypothesis" assertion below.
    if not any("sql-injection" in rule for rule in case.expected_rule_ids):
        pytest.skip(
            f"target {target} carries no SQL-injection rule "
            f"({sorted(case.expected_rule_ids)}); nothing for this SQLi vertical to plan"
        )

    request_path = CAPTURE_DIR / f"request_{target}.json"
    if not request_path.exists():
        pytest.skip(
            f"no captured request at {request_path}; run test_pipeline_capture.py "
            f"with RUN_LIVE_M1_M2=1 to capture target {target} first"
        )

    try:
        ruleset = resolve_primary_ruleset()
    except LiveDependencyError as exc:
        pytest.skip(str(exc))

    request = Module2AnalysisRequest.model_validate(
        json.loads(request_path.read_text(encoding="utf-8"))
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
    assert sqli, f"the Cloudflare {target} target should yield a SQL_INJECTION hypothesis"

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
    print(f"[source->plan] target={target}, "
          f"author/planner={'gpt-4o' if use_llm else 'deterministic'}, "
          f"wstg={wstg_source}")

    handoffs = []
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
        handoffs.append(
            build_m3_handoff(plan, envelope=envelope, request=request, hypothesis=hypothesis)
        )
        print(f"\n[source->plan] {hypothesis.hypothesis_id} ({hypothesis.input_ref}):")
        print(format_test_plan(plan))

    assert len(handoffs) == len(sqli)

    # Full live run -> a printable HTML report for review, when a path is given.
    report_path = _report_path_for(target, selected)
    if report_path:
        scope = request.target_model.scope_rules
        html = render_report_html(
            handoffs, target=str(scope.target) if scope else None
        )
        report_path.write_text(html, encoding="utf-8")
        print(f"\n[source->plan] wrote HTML report for {len(handoffs)} plan(s) to {report_path}")
