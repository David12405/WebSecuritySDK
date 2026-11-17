"""A structured SQLi test plan from a guarded hypothesis - Stage A + Stage B.

    python examples/run_structured_plan.py
    python examples/run_structured_plan.py --llm        # real OpenAI author + planner
    python examples/run_structured_plan.py --json plan.json

Module 2 ends with grounded hypotheses. This script carries one of them across
the bridge: Stage A resolves (or authors) the reusable SQLi tactic from the
bundled OWASP WSTG snapshot, and Stage B binds the hypothesis to the tactic and
the target context to produce a structured, admitted test plan for Module 3.

The default needs no network or credentials: a recorded WSTG snapshot, the
approved reference tactic as the authored result, and a deterministic planner
stand in for the service and the model. `--llm` swaps in the real OpenAI-backed
author and planner (reads `.env` for `OPENAI_API_KEY`, like run_check.py).

The scenario is a small synthetic SQLi hypothesis built inline, so the whole
pipeline runs from one file.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from websecuritycheck.analysis.correlation import (  # noqa: E402
    CorrelationKind,
    CorrelationRecord,
    CorrelationResult,
    CorrelationStatus,
    IndependenceAssessment,
    IndependenceStatus,
    Module2CorrelationEnvelope,
)
from websecuritycheck.analysis.correlation.models import CorrelationCoverage  # noqa: E402
from websecuritycheck.analysis.cve import InjectionSubtype  # noqa: E402
from websecuritycheck.domain.analysis_models import (  # noqa: E402
    ConfidenceLevel,
    InputCandidate,
    Module2AnalysisRequest,
    Module2Output,
    SinkCandidate,
    SinkKind,
    SinkRelationship,
    VulnerabilityCategory,
)
from websecuritycheck.domain.enums import DiscoverySource, InputLocation  # noqa: E402
from websecuritycheck.domain.models import (  # noqa: E402
    AssessmentConfig,
    EndpointDefinition,
    ExecutionPolicy,
    HttpExecutionPolicy,
    ObservedParameter,
    ScopeApprovalRecord,
    TargetModel,
)
from websecuritycheck.hypothesis import generate_hypotheses  # noqa: E402
from websecuritycheck.hypothesis.labels import endpoint_labels  # noqa: E402
from websecuritycheck.tactic_planning.contracts import SQLiSafetyPolicy, SQLiTechnique  # noqa: E402
from websecuritycheck.tactic_planning.stage_a import (  # noqa: E402
    FakeTacticAuthor,
    FileTacticRegistry,
    GithubWstgAdapter,
    RecordedWstgAdapter,
    StrandsTacticAuthor,
    TacticDocument,
)
from websecuritycheck.tactic_planning.stage_b import (  # noqa: E402
    StrandsPlanner,
    format_test_plan,
    prepare_sql_injection_plan,
)
from websecuritycheck.tactic_planning.stage_b.models import (  # noqa: E402
    StopCondition,
    TestCaseDraft,
    TestPlanDraft,
)

ENDPOINT_ID = "a" * 12
WSTG_DIR = REPO_ROOT / "tests" / "fixtures" / "wstg"
REF_TACTIC = REPO_ROOT / "tactics" / "sqli" / "sqli_testing.yaml"
NOW = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)


def load_env(path: Path = REPO_ROOT / ".env") -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def reference_tactic() -> TacticDocument:
    import yaml

    data = yaml.safe_load(REF_TACTIC.read_text(encoding="utf-8"))
    data["references"] = [
        "WSTG-v42-INPV-05" if ref == "WSTG-INJT-05" else ref for ref in data["references"]
    ]
    return TacticDocument.model_validate(data)


def build_scenario():
    """A small synthetic guarded SQLi hypothesis plus its M1/M2 context."""
    inp = InputCandidate(
        input_id="INP-001",
        endpoint_id=ENDPOINT_ID,
        location=InputLocation.QUERY,
        parameter_name="id",
        data_type="string",
        evidence_refs=["EVD-004"],
    )
    sink = SinkCandidate(
        sink_id="SNK-001",
        sink_kind=SinkKind.SQL_QUERY,
        file_path="app/db.py",
        start_line=10,
        rule_id="python-sql-raw-concat",
        has_static_taint_flow=True,
        dataflow_steps=["id -> cursor.execute"],
        confidence=ConfidenceLevel.HIGH,
        evidence_refs=["EVD-004"],
    )
    output = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=NOW,
        inputs=[inp],
        sink_candidates=[sink],
    )
    record = CorrelationRecord(
        correlation_id="COR-" + "a" * 16,
        kind=CorrelationKind.INPUT_SINK,
        status=CorrelationStatus.VERIFIED,
        confidence=ConfidenceLevel.HIGH,
        injection_subtype=InjectionSubtype.SQL_INJECTION,
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        endpoint_id=ENDPOINT_ID,
        input_ref="INP-001",
        sink_ref="SNK-001",
        sink_relationship=SinkRelationship.STATIC_TAINT_FLOW_FOUND,
        relation_evidence_refs=["EVD-004"],
        independent_relation_source_count=2,
        independence=IndependenceAssessment(
            status=IndependenceStatus.INDEPENDENT, distinct_execution_count=2
        ),
        rationale="Parameter 'id' flows into a raw SQL string.",
    )
    generation = generate_hypotheses(output, [record])
    envelope = Module2CorrelationEnvelope(
        output=output,
        correlation=CorrelationResult(
            records=(record,),
            coverage=CorrelationCoverage(
                input_sink_enabled=True,
                sink_cve_enabled=False,
                chain_enabled=False,
                cve_technology_enabled=False,
                blocking_dependencies=(),
            ),
            trust_policy_fingerprint="demo",
            trust_policy_is_default=True,
        ),
    )
    endpoint = EndpointDefinition(
        endpoint_id=ENDPOINT_ID,
        origin="https://lab.example.com",
        path="/api/search",
        method="GET",
        observed_parameters=[ObservedParameter(name="id", location=InputLocation.QUERY)],
        discovery_sources=[DiscoverySource.HTTP_OBSERVATION],
    )
    assessment = AssessmentConfig(
        assessment_id="ASM-001",
        target="https://lab.example.com",
        authorized_scope=["https://lab.example.com"],
        scope_approval=ScopeApprovalRecord(),
        execution_policy=ExecutionPolicy(
            http_policy=HttpExecutionPolicy(timeout_seconds=120, request_budget=1000)
        ),
    )
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id="TGT-001",
            assessment_id="ASM-001",
            last_updated=NOW,
            endpoints=[endpoint],
            scope_rules=assessment,
        )
    )
    return generation, envelope, request


class DeterministicPlanner:
    """A no-model planner: baseline, error-based, then optional time-based."""

    def plan(self, context, *, attempt: int = 0, feedback=()) -> TestPlanDraft:
        policy = context.safety_policy
        return TestPlanDraft(
            test_cases=[
                TestCaseDraft(
                    tactic_step_ref="baseline",
                    capability_id="HTTP_REQUEST",
                    purpose="Establish a reproducible baseline and auth/stability check.",
                    sample_count=2,
                    max_requests=2,
                    timeout_seconds=15,
                    stop_conditions=[StopCondition.BASELINE_NOT_READY, StopCondition.AUTH_FAILURE],
                ),
                TestCaseDraft(
                    tactic_step_ref="primary_detection",
                    capability_id="SQLI_DETECTION",
                    technique=SQLiTechnique.ERROR,
                    purpose="Error-based detection contrasted against the baseline.",
                    depends_on=[0],
                    max_requests=min(120, policy.primary_detection_max_requests),
                    timeout_seconds=90,
                    evidence_requirements=["SQL error signature differential vs control"],
                    stop_conditions=[StopCondition.TARGET_UNSTABLE, StopCondition.RATE_LIMITED],
                ),
                TestCaseDraft(
                    tactic_step_ref="optional_time_detection",
                    capability_id="SQLI_DETECTION",
                    technique=SQLiTechnique.TIME,
                    purpose="Optional time-based detection if stability and budget allow.",
                    depends_on=[0],
                    max_requests=min(80, policy.time_detection_max_requests),
                    timeout_seconds=90,
                    optional=True,
                    evidence_requirements=["Repeatable delay contrast vs stable baseline"],
                    stop_conditions=[StopCondition.TARGET_UNSTABLE],
                ),
            ],
            expected_terminal_outcomes=["CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE"],
            limitations=["TIME testing is conditional on baseline stability and budget."],
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--llm", action="store_true", help="use the real OpenAI author and planner"
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("WEBSEC_MODEL", "openai:gpt-4o"),
        help="provider:model-id for --llm (default: %(default)s)",
    )
    parser.add_argument(
        "envelope",
        nargs="?",
        help="path to a captured Module2CorrelationEnvelope JSON; omit for the "
        "built-in synthetic demo scenario",
    )
    parser.add_argument(
        "--request",
        help="captured Module 1 request JSON (defaults to request_<name>.json "
        "beside the envelope); supplies endpoints, scope, and auth for planning",
    )
    parser.add_argument(
        "--hypothesis",
        help="plan only this hypothesis id (e.g. HYP-001); default plans every "
        "SQL_INJECTION hypothesis in the envelope",
    )
    parser.add_argument(
        "--wstg-source",
        choices=["recorded", "github"],
        default="recorded",
        help="recorded: bundled offline snapshot (default); github: fetch the "
        "canonical document live from the official OWASP WSTG repo (tag v4.2)",
    )
    parser.add_argument("--json", dest="json_path", help="write the admitted plan(s) to this file")
    return parser.parse_args()


def load_captured(envelope_path: Path, request_path: Path | None):
    """Load a captured envelope + request and generate its hypotheses."""
    data = json.loads(envelope_path.read_text(encoding="utf-8"))
    output = Module2Output.model_validate(data["output"])
    correlation = CorrelationResult.model_validate(data["correlation"])
    envelope = Module2CorrelationEnvelope(output=output, correlation=correlation)

    if request_path is None and envelope_path.name.startswith("envelope_"):
        sibling = envelope_path.with_name("request_" + envelope_path.name[len("envelope_"):])
        request_path = sibling if sibling.is_file() else None
    if request_path is None or not Path(request_path).is_file():
        raise SystemExit(
            "need the Module 1 request (endpoints + scope) to plan: pass --request, "
            "or keep request_<name>.json beside the envelope"
        )
    request = Module2AnalysisRequest.model_validate(
        json.loads(Path(request_path).read_text(encoding="utf-8"))
    )
    labels = endpoint_labels(request)
    generation = generate_hypotheses(output, correlation.records, endpoint_labels=labels)
    return generation, envelope, request, labels


def print_result(result, *, label: str = "") -> None:
    if label:
        print(f"\n{'=' * 72}\n{label}")
    print(f"status: {result.status.value}")
    for line in result.trace:
        print(f"  trace: {line}")
    for err in result.errors:
        print(f"  error [{err.stage.value}/{err.code}]: {err.message}")
    for limit in result.limitations:
        print(f"  limitation: {limit}")
    plan = result.plan
    if plan is None:
        print("  (no plan produced)")
        return
    print(format_test_plan(plan))


def main() -> int:
    args = parse_args()
    load_env()

    if args.envelope:
        generation, envelope, request, labels = load_captured(
            Path(args.envelope), Path(args.request) if args.request else None
        )
        sqli = [
            h
            for h in generation.hypotheses
            if h.vulnerability_category == VulnerabilityCategory.SQL_INJECTION
            and (args.hypothesis is None or h.hypothesis_id == args.hypothesis)
        ]
        if not sqli:
            print("no matching SQL_INJECTION hypothesis in this envelope")
            return 1
        print(f"loaded {len(generation.hypotheses)} hypotheses; "
              f"planning {len(sqli)} SQL_INJECTION")
    else:
        generation, envelope, request = build_scenario()
        labels = {}
        sqli = [generation.hypotheses[0]]
        print("no envelope given: using the built-in synthetic demo scenario")

    policy = SQLiSafetyPolicy(enabled=True)  # authorized for active testing
    if args.llm:
        author = StrandsTacticAuthor(args.model)
        planner = StrandsPlanner(args.model)
        print(f"using model {args.model} for Stage A author and Stage B planner")
    else:
        author = FakeTacticAuthor(reference_tactic())
        planner = DeterministicPlanner()
        print("offline mode: reference-tactic author + deterministic planner")

    # One shared registry across hypotheses: the first authors the tactic, the
    # rest reuse it warm (no WSTG, no model) - visible in the trace.
    registry = FileTacticRegistry(REPO_ROOT / ".websec" / "tactic-registry")
    if args.wstg_source == "github":
        adapter = GithubWstgAdapter()
        print("WSTG source: official OWASP repo (github, tag v4.2)")
    else:
        adapter = RecordedWstgAdapter(WSTG_DIR)
    plans = []
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
            safety_policy=policy,
            model_name=args.model if args.llm else "fake:deterministic",
            now=None if args.llm else NOW,
        )
        endpoint = labels.get(hypothesis.target_endpoint_id, hypothesis.target_endpoint_id)
        label = f"{hypothesis.hypothesis_id}  {hypothesis.input_ref}  {endpoint}"
        print_result(result, label=label)
        if result.plan is not None:
            plans.append(result.plan)

    if args.json_path and plans:
        Path(args.json_path).write_text(
            json.dumps([p.model_dump(mode="json") for p in plans], indent=2, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {len(plans)} plan(s) to {args.json_path}")
    return 0 if plans else 1


if __name__ == "__main__":
    raise SystemExit(main())
