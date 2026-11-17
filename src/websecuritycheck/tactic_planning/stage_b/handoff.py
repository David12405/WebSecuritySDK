"""Build and render a self-contained Module 3 hand-off report.

A `StructuredTestPlan` carries opaque references (endpoint_ref, input_ref,
sink_ref) by design, so the plan alone does not spell out which URL, parameter,
or source line to test. `build_m3_handoff` resolves those references against the
Module 2 envelope and the Module 1 request into one bundle; `render_report_html`
turns a list of bundles into a single, printable HTML report for review.

Credentials stay opaque: only the endpoint URL, parameter, and source sink are
resolved - the request template and auth remain references the Module 3 adapter
resolves at execution time.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import Any

from ...analysis.correlation import Module2CorrelationEnvelope
from ...domain.analysis_models import Hypothesis, Module2AnalysisRequest
from .models import StructuredTestPlan


def build_m3_handoff(
    plan: StructuredTestPlan,
    *,
    envelope: Module2CorrelationEnvelope,
    request: Module2AnalysisRequest,
    hypothesis: Hypothesis,
) -> dict[str, Any]:
    """Resolve a plan's opaque references into a self-contained hand-off bundle."""
    output = envelope.output
    endpoints = {ep.endpoint_id: ep for ep in request.target_model.endpoints}
    inputs = {item.input_id: item for item in output.inputs}
    sinks = {item.sink_id: item for item in output.sink_candidates}

    endpoint = endpoints.get(plan.target_binding.endpoint_ref)
    input_candidate = inputs.get(plan.target_binding.input_ref)
    sink = sinks.get(hypothesis.sink_ref) if hypothesis.sink_ref else None

    return {
        "plan": plan.model_dump(mode="json"),
        "hypothesis": {
            "id": hypothesis.hypothesis_id,
            "category": hypothesis.vulnerability_category.value,
            "confidence": hypothesis.confidence.value,
            "sink_relationship": hypothesis.sink_relationship.value,
            "rationale": hypothesis.rationale,
        },
        "resolved_target": {
            "endpoint": (
                {
                    "ref": endpoint.endpoint_id,
                    "method": endpoint.method,
                    "url": f"{endpoint.origin}{endpoint.path}",
                    "required_auth_role": endpoint.required_auth_role,
                }
                if endpoint
                else None
            ),
            "input": (
                {
                    "ref": input_candidate.input_id,
                    "parameter": input_candidate.parameter_name,
                    "location": input_candidate.location.value,
                    "data_type": input_candidate.data_type,
                }
                if input_candidate
                else None
            ),
            "sink": (
                {
                    "ref": sink.sink_id,
                    "file": sink.file_path,
                    "line": sink.start_line,
                    "end_line": sink.end_line,
                    "kind": sink.sink_kind.value,
                    "rule_id": sink.rule_id,
                }
                if sink
                else None
            ),
            "request_template_ref": plan.target_binding.request_template_ref,
            "auth_ref": plan.target_binding.auth_ref,
        },
    }


def _e(value: Any) -> str:
    return html.escape(str(value)) if value is not None else "-"


def _case_row(case: dict[str, Any]) -> str:
    technique = case.get("technique") or ""
    cap = _e(case["capability_id"]) + (f" / {_e(technique)}" if technique else "")
    deps = ", ".join(case.get("dependencies") or []) or "-"
    args = case.get("capability_arguments") or {}
    args_text = ", ".join(f"{_e(k)}={_e(v)}" for k, v in args.items()) or "-"
    signals = ", ".join(case.get("expected_signals") or []) or "-"
    evidence = "; ".join(case.get("evidence_requirements") or []) or "-"
    stops = ", ".join(case.get("stop_conditions") or []) or "-"
    opt = "optional" if case.get("optional") else "mandatory"
    opt_cls = "opt" if case.get("optional") else "req"
    return (
        "<tr>"
        f"<td class='mono'>{_e(case['test_case_id'])}</td>"
        f"<td><span class='cap'>{cap}</span><br><span class='muted mono'>{_e(case['tactic_step_ref'])}</span></td>"
        f"<td>{_e(case['purpose'])}</td>"
        f"<td class='mono'>{_e(deps)}</td>"
        f"<td class='mono'>{_e(args_text)}</td>"
        f"<td>{_e(signals)}</td>"
        f"<td>{_e(evidence)}</td>"
        f"<td class='mono'>{_e(stops)}</td>"
        f"<td class='num'>{_e(case['max_requests'])} req<br>{_e(case['timeout_seconds'])}s</td>"
        f"<td><span class='badge {opt_cls}'>{opt}</span></td>"
        "</tr>"
    )


def _handoff_section(bundle: dict[str, Any], index: int) -> str:
    plan = bundle["plan"]
    hyp = bundle["hypothesis"]
    target = bundle["resolved_target"]
    endpoint = target["endpoint"] or {}
    inp = target["input"] or {}
    sink = target["sink"] or {}

    limits = plan["execution_limits"]
    outcomes = ", ".join(plan.get("expected_terminal_outcomes") or []) or "-"
    rows = "".join(_case_row(case) for case in plan["test_cases"])
    limitations = "".join(f"<li>{_e(item)}</li>" for item in plan.get("limitations") or [])
    code_loc = (
        f"{_e(sink.get('file'))}:{_e(sink.get('line'))}" if sink else "not traced"
    )

    return f"""
    <section class="plan">
      <h2>{index}. {_e(hyp['category'])} &mdash; {_e(plan['plan_id'])}</h2>
      <div class="grid">
        <div class="fact"><span class="label">Endpoint</span>
          <span class="value mono">{_e(endpoint.get('method'))} {_e(endpoint.get('url'))}</span></div>
        <div class="fact"><span class="label">Parameter</span>
          <span class="value mono">{_e(inp.get('parameter'))} <span class="muted">({_e(inp.get('location'))})</span></span></div>
        <div class="fact"><span class="label">Vulnerable code</span>
          <span class="value mono">{code_loc} <span class="muted">({_e(sink.get('kind'))})</span></span></div>
        <div class="fact"><span class="label">Confidence</span>
          <span class="value">{_e(hyp['confidence'])} &middot; {_e(hyp['sink_relationship'])}</span></div>
        <div class="fact"><span class="label">Hypothesis</span>
          <span class="value mono">{_e(hyp['id'])}</span></div>
        <div class="fact"><span class="label">Tactic</span>
          <span class="value mono">{_e(plan['tactic_ref']['tactic_id'])} v{_e(plan['tactic_ref']['tactic_version'])}</span></div>
      </div>
      <p class="why"><strong>Why:</strong> {_e(hyp['rationale'])}</p>
      <p class="muted small">Budget ceiling: aggregate &le; {_e(limits['aggregate_max_requests'])} requests,
         detection timeout &le; {_e(limits['detection_timeout_seconds'])}s &middot;
         request template: <span class="mono">{_e(target['request_template_ref'])}</span>
         (resolved by Module 3) &middot; auth: {_e(target['auth_ref'])}</p>
      <table>
        <thead><tr>
          <th>Case</th><th>Capability / step</th><th>Purpose</th><th>Depends</th>
          <th>Arguments</th><th>Signals</th><th>Evidence required</th>
          <th>Stop if</th><th>Budget</th><th></th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p class="small muted">Expected terminal outcomes (Module 3): {_e(outcomes)}</p>
      {f'<ul class="limits">{limitations}</ul>' if limitations else ''}
    </section>"""


def render_report_html(
    handoffs: list[dict[str, Any]],
    *,
    title: str = "SQL Injection Test Plan",
    target: str | None = None,
    generated_at: datetime | None = None,
) -> str:
    """Render a printable HTML report from one or more hand-off bundles."""
    generated_at = generated_at or datetime.now(UTC)
    sections = "".join(_handoff_section(b, i + 1) for i, b in enumerate(handoffs))
    n_cases = sum(len(b["plan"]["test_cases"]) for b in handoffs)
    meta = " &middot; ".join(
        part
        for part in [
            f"Target: <span class='mono'>{_e(target)}</span>" if target else "",
            f"{len(handoffs)} plan(s), {n_cases} test case(s)",
            f"Generated {generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        ]
        if part
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>
  :root {{ --fg:#1b1f24; --muted:#6b7280; --line:#e5e7eb; --bg:#ffffff;
           --accent:#1f4e79; --req:#b91c1c; --opt:#92740a; --chip:#eef2ff; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
          color: var(--fg); background: #f3f4f6; margin: 0; padding: 24px; }}
  .sheet {{ max-width: 1150px; margin: 0 auto; background: var(--bg);
            box-shadow: 0 1px 4px rgba(0,0,0,.08); border-radius: 10px; padding: 32px 36px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; color: var(--accent); }}
  h2 {{ font-size: 17px; margin: 28px 0 10px; border-bottom: 2px solid var(--line); padding-bottom: 6px; }}
  .meta {{ color: var(--muted); font-size: 13px; margin-bottom: 8px; }}
  .note {{ background: #fff7ed; border: 1px solid #fed7aa; color: #7c2d12;
           padding: 10px 14px; border-radius: 8px; font-size: 13px; margin: 14px 0 8px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(230px,1fr)); gap: 10px 20px; margin: 12px 0; }}
  .fact {{ display: flex; flex-direction: column; }}
  .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }}
  .value {{ font-size: 14px; }}
  .why {{ font-size: 14px; margin: 8px 0; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }}
  .muted {{ color: var(--muted); }}
  .small {{ font-size: 12px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 10px 0; font-size: 12.5px; }}
  th, td {{ border: 1px solid var(--line); padding: 7px 9px; text-align: left; vertical-align: top; }}
  th {{ background: #f8fafc; font-size: 11px; text-transform: uppercase; letter-spacing: .03em; color: #374151; }}
  td.num {{ white-space: nowrap; text-align: right; }}
  .cap {{ font-weight: 600; }}
  .badge {{ display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; }}
  .badge.req {{ background: #fee2e2; color: var(--req); }}
  .badge.opt {{ background: #fef9c3; color: var(--opt); }}
  .limits {{ font-size: 12.5px; color: var(--muted); margin: 6px 0 0 18px; }}
  footer {{ color: var(--muted); font-size: 12px; margin-top: 28px; border-top: 1px solid var(--line); padding-top: 12px; }}
  @media print {{ body {{ background: #fff; padding: 0; }} .sheet {{ box-shadow: none; }} section.plan {{ page-break-inside: avoid; }} }}
</style>
</head>
<body>
  <div class="sheet">
    <h1>{_e(title)}</h1>
    <div class="meta">{meta}</div>
    <div class="note"><strong>Status: test plan (not yet executed).</strong>
      This is the structured hand-off to Module 3. Each test case is a bounded,
      policy-checked step to run; no requests have been sent and no vulnerability
      is confirmed. Credentials remain opaque references resolved at execution time.</div>
    {sections}
    <footer>Generated by WebSecuritySDK &middot; Stage A/B (tactic authoring + validation planning).
      Module 3 executes each case, records evidence, and decides the final outcome.</footer>
  </div>
</body>
</html>
"""
