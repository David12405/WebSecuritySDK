"""Hypotheses from a captured Module 2 envelope.

    python examples/run_hypothesis.py tests/test_analysis/captured_envelopes/envelope_api.json
    python examples/run_hypothesis.py envelope_api.json --llm
    python examples/run_hypothesis.py envelope_api.json --compare
    python examples/run_hypothesis.py envelope_api.json --json hypotheses.json

Module 2 stops at "these clues are related". This turns each relation into a
statement worth testing, and a proposal saying what would settle it.

The default needs no credentials: the deterministic generator runs on its
own, which is the point - a model is an improvement over the baseline, not a
dependency of it. `--llm` swaps in a model for the one genuinely uncertain
decision (which parameter of an endpoint reaches a sink), and `--compare`
runs both so you can see whether it earned its place.

Reads `.env` for the provider key, like `run_check.py`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
# Module 2's sink extraction reads a helper from the Layer 6 tool package,
# which lives beside `src/` rather than inside it.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from websecuritycheck.analysis.correlation import CorrelationResult  # noqa: E402
from websecuritycheck.domain.analysis_models import (  # noqa: E402
    Module2AnalysisRequest,
    Module2Output,
)
from websecuritycheck.hypothesis import (  # noqa: E402
    GenerationResult,
    LLMInputSelector,
    check_hypotheses,
    generate_hypotheses,
    heuristic_selector,
)
from websecuritycheck.hypothesis.labels import describe, endpoint_labels  # noqa: E402
from websecuritycheck.hypothesis.slices import (  # noqa: E402
    SourceSlicer,
    describe_slices,
    slices_for_records,
)


def load_env(path: Path = REPO_ROOT / ".env") -> None:
    """Read `KEY=value` lines into the environment, without overwriting it."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("envelope", help="path to a captured Module2CorrelationEnvelope JSON")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="let a model choose which parameters reach a sink (needs credentials)",
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help="run the deterministic and model-backed selectors side by side",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("WEBSEC_MODEL", "openai:gpt-4o"),
        help="provider:model-id for --llm/--compare (default: %(default)s)",
    )
    parser.add_argument(
        "--max-inputs",
        type=int,
        default=3,
        help="most parameters to flag per sink (default: %(default)s)",
    )
    parser.add_argument(
        "--request",
        help=(
            "captured Module 1 request, so endpoints read as 'POST /api/search' "
            "rather than a hash. Defaults to request_<name>.json beside the envelope."
        ),
    )
    parser.add_argument(
        "--source-root",
        help=(
            "the scanned repository, so the handler's source can be quoted into "
            "the prompt instead of only its file and line (e.g. "
            "test-targets/cloudflare/targets/api)"
        ),
    )
    parser.add_argument("--json", dest="json_path", help="write the hypotheses to this file")
    return parser.parse_args()


def load_envelope(path: Path) -> tuple[Module2Output, CorrelationResult]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return (
        Module2Output.model_validate(data["output"]),
        CorrelationResult.model_validate(data["correlation"]),
    )


def load_labels(envelope_path: Path, explicit: str | None) -> dict[str, str]:
    """Endpoint id -> "METHOD /path", if the Module 1 request can be found.

    The envelope carries only hashes; the paths live in the request's target
    model. A capture writes the two side by side, so the common case needs no
    flag - and when neither is there, every endpoint simply prints as its id.
    """
    path = Path(explicit) if explicit else _sibling_request(envelope_path)
    if path is None or not path.is_file():
        return {}
    request = Module2AnalysisRequest.model_validate(
        json.loads(path.read_text(encoding="utf-8"))
    )
    return endpoint_labels(request)


def _sibling_request(envelope_path: Path) -> Path | None:
    name = envelope_path.name
    if not name.startswith("envelope_"):
        return None
    return envelope_path.with_name("request_" + name[len("envelope_") :])


def report(
    label: str,
    result: GenerationResult,
    output: Module2Output,
    correlation: CorrelationResult,
    labels: dict[str, str] | None = None,
) -> None:
    names = {item.input_id: item.parameter_name for item in output.inputs}
    print(f"\n{label}  -  {len(result.hypotheses)} hypothesis(es)")
    print("=" * 72)
    for hypothesis in result.hypotheses:
        proposal = hypothesis.validation_proposals[0]
        parameter = names.get(hypothesis.input_ref or "", hypothesis.input_ref or "-")
        print(
            f"{hypothesis.hypothesis_id}  {hypothesis.vulnerability_category.value}"
            f"  confidence={hypothesis.confidence.value}"
            f"  priority={proposal.priority}"
        )
        print(
            f"    parameter {parameter!r} ({hypothesis.input_ref})"
            f"  sink {hypothesis.sink_ref}"
        )
        # The path, with the id kept beside it: a reader needs the first and
        # anyone cross-checking Module 2 or Module 3 needs the second.
        print(f"    endpoint  {describe(hypothesis.target_endpoint_id, labels)}")
        print(f"    relationship  {hypothesis.sink_relationship.value}")
        print(f"    validate with {proposal.suggested_capability.value}")
        print(f"    why           {hypothesis.rationale}")
        for item in hypothesis.missing_evidence:
            print(f"    still missing {item}")

    for limitation in result.limitations:
        print(f"  [not generated] {limitation}")

    violations = check_hypotheses(
        result.hypotheses, output, correlation.records, result.provenance
    )
    if violations:
        # The guard catching something here is the interesting case: it means
        # the generator produced a claim its own source record does not
        # support, and that must never reach Module 3.
        print(f"\n  GUARD REJECTED {len(violations)}:")
        for violation in violations:
            print(f"    - {violation}")
    else:
        print("\n  guard: clean")


def summarise_difference(
    baseline: GenerationResult,
    model_run: GenerationResult,
    output: Module2Output,
    labels: dict[str, str] | None = None,
) -> None:
    """Say plainly what the model changed, so it can be judged on that."""
    names = {item.input_id: item.parameter_name for item in output.inputs}

    def picked(result: GenerationResult) -> set[tuple[str, str]]:
        return {
            (item.target_endpoint_id or "", item.input_ref or "")
            for item in result.hypotheses
        }

    def say(endpoint: str, input_ref: str) -> str:
        return f"{names.get(input_ref, input_ref)!r} ({input_ref}) on {describe(endpoint, labels)}"

    before, after = picked(baseline), picked(model_run)
    print("\nDifference")
    print("=" * 72)
    if before == after:
        print("  none - the model chose exactly what the heuristic did")
        return
    for endpoint, input_ref in sorted(before - after):
        print(f"  dropped by the model: {say(endpoint, input_ref)}")
    for endpoint, input_ref in sorted(after - before):
        print(f"  added by the model:   {say(endpoint, input_ref)}")


def main() -> int:
    args = parse_args()
    load_env()

    path = Path(args.envelope)
    if not path.is_file():
        print(f"no such envelope: {path}", file=sys.stderr)
        return 2
    output, correlation = load_envelope(path)
    labels = load_labels(path, args.request)
    if not labels:
        print(
            "note: no Module 1 request found, so endpoints print as ids. Pass "
            "--request, or re-run the capture to write one beside the envelope."
        )

    if not correlation.records:
        print("this envelope has no correlation records, so there is nothing to turn")
        print("into a hypothesis. That is an answer about the analysis, not the target.")
        for limitation in output.limitations:
            print(f"  limitation: {limitation}")
        return 0

    slices: dict[str, str] = {}
    if args.source_root:
        slicer = SourceSlicer(args.source_root)
        slices = slices_for_records(output, correlation.records, slicer)
        print(f"read {describe_slices(slices)} from {args.source_root}")
        for error in slicer.errors:
            print(f"  could not read: {error}")

    baseline = generate_hypotheses(
        output,
        correlation.records,
        select_inputs=heuristic_selector,
        max_inputs_per_sink=args.max_inputs,
        endpoint_labels=labels,
        code_slices=slices,
    )
    chosen = baseline

    if args.llm or args.compare:
        selector = LLMInputSelector(args.model)
        model_run = generate_hypotheses(
            output,
            correlation.records,
            select_inputs=selector,
            max_inputs_per_sink=args.max_inputs,
            endpoint_labels=labels,
            code_slices=slices,
        )
        if args.compare:
            report(
                "DETERMINISTIC (heuristic selector)", baseline, output, correlation, labels
            )
            report(f"MODEL ({args.model})", model_run, output, correlation, labels)
            summarise_difference(baseline, model_run, output, labels)
        else:
            report(f"MODEL ({args.model})", model_run, output, correlation, labels)
        for key, reason in selector.reasons.items():
            print(f"  model note [{key}]: {reason}")
        for error in selector.errors:
            # Falling back is legitimate; doing it quietly is not.
            print(f"  model unavailable, used the heuristic instead: {error}")
        chosen = model_run
    else:
        report("DETERMINISTIC (heuristic selector)", baseline, output, correlation, labels)

    if args.json_path:
        Path(args.json_path).write_text(
            json.dumps(
                [item.model_dump(mode="json") for item in chosen.hypotheses],
                indent=2,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nwrote {len(chosen.hypotheses)} hypothesis(es) to {args.json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
