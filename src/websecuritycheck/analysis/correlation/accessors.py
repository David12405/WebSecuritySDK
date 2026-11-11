"""Multi-axial injection sink classification and taint source accessor parsing."""

from __future__ import annotations

import json
import re

from websecuritycheck.domain.analysis_models import (
    CweId,
    Module2AnalysisRequest,
    SinkCandidate,
    SinkKind,
)
from websecuritycheck.domain.enums import InputLocation
from websecuritycheck.domain.models import ArtifactManifest, EvidenceArtifactRecord

from ..cve import (
    DIRECT_INJECTION_CWES,
    EXCLUDED_CWES,
    InjectionScopeStatus,
    InjectionSubtype,
)
from ..sinks import (
    SinkCorrelationMetadata,
    normalize_sink_file_path,
    verify_sink_evidence_integrity,
)
from .models import InjectionSinkScope, TaintSourceAccessor
from .policy import (
    SINK_KIND_INJECTION_CWES,
    AccessorResolution,
    ApprovedRuleSpec,
    CorrelationTrustPolicy,
    FlowTrust,
    RuleMode,
    RuleProvenanceStatus,
)
from .verifiers import verify_ast_taint_provenance


def classify_injection_sink(
    sink: SinkCandidate,
    manifest: ArtifactManifest,
    evidence_record: EvidenceArtifactRecord,
    metadata: SinkCorrelationMetadata | None,
    *,
    request: Module2AnalysisRequest,
    trust_policy: CorrelationTrustPolicy,
) -> InjectionSinkScope:
    """Evaluate a SinkCandidate along scope, rule provenance, and taint trust axes."""
    sink_id = sink.sink_id

    if not verify_sink_evidence_integrity(evidence_record, manifest):
        return InjectionSinkScope(
            sink_id=sink_id,
            scope_status=InjectionScopeStatus.EXCLUDED,
            scope_basis="INTEGRITY_CHECK",
            rule_provenance=RuleProvenanceStatus.CONFLICT,
            flow_trust=FlowTrust.CONFLICT,
            reason="Evidence integrity verification failed",
        )

    if sink.sink_kind in {SinkKind.HTML_OUTPUT, SinkKind.PATH_ACCESS}:
        return InjectionSinkScope(
            sink_id=sink_id,
            scope_status=InjectionScopeStatus.EXCLUDED,
            scope_basis="SINK_KIND",
            rule_provenance=RuleProvenanceStatus.UNVERIFIED,
            flow_trust=FlowTrust.PATTERN_ONLY,
            reason=f"SinkKind {sink.sink_kind.value} is outside OWASP A05: Injection scope",
        )

    manifest_cwes = set()
    manifest_meta = manifest.metadata or {}
    meta_cwes = manifest_meta.get("cwe_ids")
    if isinstance(meta_cwes, list):
        manifest_cwes.update(str(c) for c in meta_cwes)
    if metadata:
        manifest_cwes.update(str(c) for c in metadata.cwe_ids)

    if any(c in EXCLUDED_CWES for c in manifest_cwes):
        return InjectionSinkScope(
            sink_id=sink_id,
            scope_status=InjectionScopeStatus.EXCLUDED,
            scope_basis="EXCLUDED_CWES",
            rule_provenance=RuleProvenanceStatus.UNVERIFIED,
            flow_trust=FlowTrust.PATTERN_ONLY,
            reason=(
                f"Sink finding contains excluded CWE(s): {sorted(manifest_cwes & EXCLUDED_CWES)}"
            ),
        )

    prov = evidence_record.provenance or {}
    ruleset_sha256 = str(prov.get("ruleset_sha256") or "").lower().strip()
    exec_ref = str(evidence_record.execution_ref or "").strip()
    source_repo_ref = str(prov.get("source_repository_ref") or "").strip()
    source_rev = str(prov.get("source_revision") or "").strip()
    source_tree_sha256 = str(prov.get("source_tree_sha256") or "").strip()
    taint_origin = str(prov.get("taint_origin") or "").strip()
    ast_prov = prov.get("ast_taint_provenance")

    all_rule_ids = set()
    if metadata:
        all_rule_ids.update(metadata.all_rule_ids)
    all_rule_ids.add(sink.rule_id)

    approved_rs = None
    for rs in trust_policy.approved_rulesets:
        if rs.sha256.lower() == ruleset_sha256:
            approved_rs = rs
            break

    provenance_gaps: list[str] = []
    if not ruleset_sha256:
        provenance_gaps.append("MISSING_RULESET_SHA256")
    elif approved_rs is None:
        provenance_gaps.append(f"UNAPPROVED_RULESET_DIGEST:{ruleset_sha256}")

    if not exec_ref:
        provenance_gaps.append("MISSING_EXECUTION_REF")

    scope_rules = request.target_model.scope_rules
    approved_repo = scope_rules.source_repository_ref if scope_rules else None
    if not source_repo_ref:
        provenance_gaps.append("MISSING_SOURCE_REPO_REF")
    elif approved_repo and normalize_sink_file_path(source_repo_ref) != normalize_sink_file_path(
        approved_repo
    ):
        provenance_gaps.append("REPO_REF_MISMATCH")

    if not source_rev:
        provenance_gaps.append("MISSING_SOURCE_REVISION")

    matched_specs: dict[str, ApprovedRuleSpec] = {}
    if approved_rs is not None:
        rules_by_id = {r.rule_id: r for r in approved_rs.rules}
        for rid in all_rule_ids:
            if rid in rules_by_id:
                matched_specs[rid] = rules_by_id[rid]
            else:
                provenance_gaps.append(f"UNAPPROVED_RULE:{rid}")

    rule_prov_status = (
        RuleProvenanceStatus.VERIFIED
        if approved_rs is not None and not provenance_gaps
        else RuleProvenanceStatus.UNVERIFIED
    )

    target_subtype: InjectionSubtype | None = None
    scope_status = InjectionScopeStatus.UNKNOWN
    scope_basis = "UNRESOLVED"
    corrob_cwes: list[CweId] = []

    if rule_prov_status == RuleProvenanceStatus.VERIFIED:
        primary_spec = matched_specs.get(sink.rule_id)
        if primary_spec:
            target_subtype = primary_spec.subtype
            corrob_cwes = sorted(primary_spec.cwe_ids)
            scope_status = InjectionScopeStatus.ALLOWED
            scope_basis = "APPROVED_REGISTRY"
    else:
        allowed_cwes = SINK_KIND_INJECTION_CWES.get(sink.sink_kind, frozenset())
        matched_manifest_cwes = manifest_cwes & allowed_cwes
        if matched_manifest_cwes:
            sample_cwe = sorted(matched_manifest_cwes)[0]
            if sample_cwe in DIRECT_INJECTION_CWES:
                target_subtype = DIRECT_INJECTION_CWES[sample_cwe]
                corrob_cwes = [CweId(c) for c in sorted(matched_manifest_cwes)]
                scope_status = InjectionScopeStatus.ALLOWED
                scope_basis = "MANIFEST_CWE_ONLY"
            elif sink.sink_kind == SinkKind.ORM_QUERY:
                target_subtype = InjectionSubtype.ORM_QUERY_INJECTION
                corrob_cwes = [CweId(c) for c in sorted(matched_manifest_cwes)]
                scope_status = InjectionScopeStatus.ALLOWED
                scope_basis = "MANIFEST_CWE_ONLY"
        elif not manifest_cwes:
            scope_status = InjectionScopeStatus.UNKNOWN
            scope_basis = "KEYWORD_ONLY_CLASSIFICATION"

    manifest_content = manifest.content or "{}"
    has_steps = False
    try:
        parsed_payload = json.loads(manifest_content)
        dataflow_steps = parsed_payload.get("dataflow_steps") or []
        has_steps = bool(dataflow_steps)
    except Exception:
        has_steps = bool(sink.dataflow_steps)

    if rule_prov_status == RuleProvenanceStatus.VERIFIED:
        primary_spec = matched_specs.get(sink.rule_id)
        if (
            primary_spec
            and primary_spec.mode == RuleMode.SEARCH
            and (sink.has_static_taint_flow or has_steps)
        ):
            flow_trust = FlowTrust.CONFLICT
        elif (
            primary_spec
            and primary_spec.mode == RuleMode.TAINT
            and sink.has_static_taint_flow
            and has_steps
        ):
            if taint_origin == "ast_intraprocedural":
                ast_ok, ast_reason = verify_ast_taint_provenance(ast_prov, trust_policy)
                if ast_ok:
                    flow_trust = FlowTrust.TRUSTED_TAINT
                else:
                    flow_trust = FlowTrust.UNTRUSTED_TAINT
                    provenance_gaps.append(ast_reason)
            else:
                flow_trust = FlowTrust.TRUSTED_TAINT
        else:
            flow_trust = FlowTrust.PATTERN_ONLY
    else:
        if sink.has_static_taint_flow and has_steps:
            flow_trust = FlowTrust.UNTRUSTED_TAINT
        else:
            flow_trust = FlowTrust.PATTERN_ONLY

    return InjectionSinkScope(
        sink_id=sink_id,
        scope_status=scope_status,
        scope_basis=scope_basis,
        subtype=target_subtype,
        corroborating_cwe_ids=tuple(corrob_cwes),
        rule_provenance=rule_prov_status,
        provenance_gaps=tuple(sorted(provenance_gaps)),
        flow_trust=flow_trust,
        source_revision=source_rev or None,
        source_tree_sha256=source_tree_sha256 or None,
        source_repository_ref=source_repo_ref or None,
        reason=(
            f"Evaluated sink {sink_id}: scope={scope_status.value} ({scope_basis}), "
            f"provenance={rule_prov_status.value}, flow_trust={flow_trust.value}"
        ),
    )


_MEMBER_SUFFIX = r"(?:\.[A-Za-z0-9_]+|\[\s*['\"][A-Za-z0-9_.-]+['\"]\s*\])+"
_PROP_SEG_RE = re.compile(r"\.([A-Za-z0-9_]+)|\[\s*['\"]([A-Za-z0-9_.-]+)['\"]\s*\]")

_FLASK_ARGS_RE = re.compile(
    r"""request\.(?:args|form|cookies|headers|view_args)(?:\.get\(|\[)\s*['"]([A-Za-z0-9_-]+)['"]"""
)
_FLASK_JSON_RE = re.compile(
    rf"""(?:request\.json|request\.get_json\(\))(?:\.get\(\s*['"]([A-Za-z0-9_.-]+)['"]|({_MEMBER_SUFFIX}))"""
)
_DJANGO_GET_POST_RE = re.compile(
    r"""request\.(?:GET|POST|COOKIES)(?:\.get\(|\[)\s*['"]([A-Za-z0-9_-]+)['"]"""
)
_DJANGO_META_RE = re.compile(r"""request\.META\[\s*['"]HTTP_([A-Za-z0-9_]+)['"]\s*\]""")
_EXPRESS_PROP_RE = re.compile(rf"""req\.(query|params|cookies|headers|body)({_MEMBER_SUFFIX})""")
_EXPRESS_GET_RE = re.compile(r"""req\.get\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)""")
_FETCH_SEARCH_PARAMS_RE = re.compile(
    r"""(?:\b[A-Za-z_$][\w$]*\.)?searchParams\.get\(\s*['"]([A-Za-z0-9_.-]+)['"]\s*\)"""
)
_FETCH_FORM_DATA_RE = re.compile(r"""\b(?:formData|form)\.get\(\s*['"]([A-Za-z0-9_.-]+)['"]\s*\)""")
_FETCH_HEADERS_RE = re.compile(
    r"""(?:\b(?:request|req)\.)?headers\.get\(\s*['"]([A-Za-z0-9_-]+)['"]\s*\)"""
)
_ROUTE_PATH_PARAM_RE = re.compile(
    r"""\b(?:route|path)\.params(?:\.([A-Za-z0-9_-]+)|\[\s*['"]([A-Za-z0-9_-]+)['"]\s*\])"""
)
_JS_BODY_PROP_RE = re.compile(rf"""\b(?:body|data|payload)({_MEMBER_SUFFIX})""")
_DYNAMIC_ACCESSOR_RE = re.compile(
    r"""(?x)
    request\.(?:args|form|values)\[\s*[A-Za-z_][A-Za-z0-9_]*\s*\]
    | (?:\b[A-Za-z_$][\w$]*\.)?searchParams\.get\(\s*[A-Za-z_$][\w$]*\s*\)
    | \b(?:formData|form)\.get\(\s*[A-Za-z_$][\w$]*\s*\)
    | (?:\b(?:request|req)\.)?headers\.get\(\s*[A-Za-z_$][\w$]*\s*\)
    | \b(?:await\s+)?(?:request|req)\.(?:json|text|formData)\(\)
"""
)


def _join_member_suffix(suffix: str) -> str:
    parts = [m.group(1) or m.group(2) for m in _PROP_SEG_RE.finditer(suffix)]
    return ".".join(p for p in parts if p)


def parse_taint_source_accessor(snippet: str | None) -> TaintSourceAccessor:
    """Parse a taint source snippet for input location and parameter name using strict grammar."""
    if not snippet or not snippet.strip():
        return TaintSourceAccessor(resolution=AccessorResolution.UNSUPPORTED)

    clean_snip = snippet.strip()
    if "<redacted>" in clean_snip.lower():
        return TaintSourceAccessor(resolution=AccessorResolution.REDACTED)

    if clean_snip.endswith("...") or clean_snip.startswith("..."):
        return TaintSourceAccessor(resolution=AccessorResolution.TRUNCATED)

    m = _FLASK_ARGS_RE.search(clean_snip)
    if m:
        param = m.group(1)
        loc = InputLocation.QUERY
        if "form" in clean_snip:
            loc = InputLocation.FORM
        elif "cookies" in clean_snip:
            loc = InputLocation.COOKIE
        elif "headers" in clean_snip:
            loc = InputLocation.HEADER
        elif "view_args" in clean_snip:
            loc = InputLocation.PATH
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({loc}),
            parameter_name=param,
            pattern_id="flask_request_args",
        )

    m = _FLASK_JSON_RE.search(clean_snip)
    if m:
        param = m.group(1) or _join_member_suffix(m.group(2) or "")
        if param:
            return TaintSourceAccessor(
                resolution=AccessorResolution.RESOLVED,
                locations=frozenset({InputLocation.JSON_BODY}),
                parameter_name=param,
                pattern_id="flask_request_json",
            )

    m = _DJANGO_GET_POST_RE.search(clean_snip)
    if m:
        param = m.group(1)
        loc = InputLocation.QUERY
        if "POST" in clean_snip:
            loc = InputLocation.FORM
        elif "COOKIES" in clean_snip:
            loc = InputLocation.COOKIE
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({loc}),
            parameter_name=param,
            pattern_id="django_request_get_post",
        )

    m = _DJANGO_META_RE.search(clean_snip)
    if m:
        header_name = m.group(1).replace("_", "-").casefold()
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.HEADER}),
            parameter_name=header_name,
            pattern_id="django_request_meta",
        )

    m = _EXPRESS_PROP_RE.search(clean_snip)
    if m:
        prop_kind = m.group(1)
        param = _join_member_suffix(m.group(2))
        loc_map = {
            "query": frozenset({InputLocation.QUERY}),
            "params": frozenset({InputLocation.PATH}),
            "cookies": frozenset({InputLocation.COOKIE}),
            "headers": frozenset({InputLocation.HEADER}),
            "body": frozenset(
                {InputLocation.FORM, InputLocation.JSON_BODY, InputLocation.MULTIPART}
            ),
        }
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=loc_map.get(prop_kind, frozenset()),
            parameter_name=param,
            pattern_id="express_req_property",
        )

    m = _EXPRESS_GET_RE.search(clean_snip)
    if m:
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.HEADER}),
            parameter_name=m.group(1),
            pattern_id="express_req_get",
        )

    m = _ROUTE_PATH_PARAM_RE.search(clean_snip)
    if m:
        param = m.group(1) or m.group(2)
        return TaintSourceAccessor(
            resolution=AccessorResolution.RESOLVED,
            locations=frozenset({InputLocation.PATH}),
            parameter_name=param,
            pattern_id="route_path_param",
        )

    for regex, loc, pid in (
        (_FETCH_SEARCH_PARAMS_RE, InputLocation.QUERY, "fetch_search_params_get"),
        (_FETCH_FORM_DATA_RE, InputLocation.FORM, "fetch_form_data_get"),
        (_FETCH_HEADERS_RE, InputLocation.HEADER, "fetch_headers_get"),
    ):
        m = regex.search(clean_snip)
        if m:
            return TaintSourceAccessor(
                resolution=AccessorResolution.RESOLVED,
                locations=frozenset({loc}),
                parameter_name=m.group(1),
                pattern_id=pid,
            )

    m = _JS_BODY_PROP_RE.search(clean_snip)
    if m:
        param = _join_member_suffix(m.group(1))
        if param:
            return TaintSourceAccessor(
                resolution=AccessorResolution.RESOLVED,
                locations=frozenset({InputLocation.JSON_BODY}),
                parameter_name=param,
                pattern_id="js_body_property",
            )

    if _DYNAMIC_ACCESSOR_RE.search(clean_snip):
        return TaintSourceAccessor(resolution=AccessorResolution.DYNAMIC_KEY)

    return TaintSourceAccessor(resolution=AccessorResolution.UNSUPPORTED)


__all__ = [
    "_join_member_suffix",
    "classify_injection_sink",
    "parse_taint_source_accessor",
]
