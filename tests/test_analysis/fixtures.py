"""Reusable canonical Module 1 test fixtures for Module 2 testing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from websecuritycheck.domain.analysis_models import Module2AnalysisRequest
from websecuritycheck.domain.enums import (
    ArtifactType,
    DiscoverySource,
    InputLocation,
    ObservationSource,
    ObservationType,
    TechnologyCategory,
    TestingMode,
)
from websecuritycheck.domain.models import (
    ArtifactManifest,
    AssessmentConfig,
    EndpointDefinition,
    EndpointObservationPayload,
    EvidenceArtifactRecord,
    Id,
    ObservationRecord,
    ObservedParameter,
    ScopeApprovalRecord,
    TargetModel,
    TechnologyObservationPayload,
    TechnologyRecord,
)
from websecuritycheck.identity import stable_hash
from websecuritycheck.recon.endpoints import (
    normalize_method,
    normalize_origin,
    normalize_path,
)

# Suppress PytestCollectionWarning for TestingMode enum
TestingMode.__test__ = False

FIXED_TIME = datetime(2026, 11, 4, 10, 0, 0, tzinfo=UTC)


def make_evidence_record(
    evidence_id: str = "EVD-001",
    *,
    assessment_id: str = "ASM-001",
    artifact_type: ArtifactType = ArtifactType.HTTP_RAW_EXCHANGE,
    artifact_ref: str = "raw-http-req-1",
    storage_uri: str = "memory://evd-1",
    size_bytes: int = 100,
) -> EvidenceArtifactRecord:
    """Build a canonical EvidenceArtifactRecord for offline testing."""
    return EvidenceArtifactRecord(
        evidence_id=evidence_id,
        assessment_id=assessment_id,
        artifact_type=artifact_type,
        artifact_ref=artifact_ref,
        storage_uri=storage_uri,
        sha256_hash="0" * 64,
        size_bytes=size_bytes,
        captured_at=FIXED_TIME,
    )


def make_endpoint(
    origin: str = "https://shop.lab.local",
    path: str = "/api/products",
    method: str = "GET",
    *,
    observed_parameters: list[ObservedParameter] | None = None,
    discovery_sources: list[DiscoverySource] | None = None,
    evidence_refs: list[str] | None = None,
    observation_refs: list[str] | None = None,
) -> EndpointDefinition:
    """Build a canonical EndpointDefinition with matching 12-hex endpoint_id."""
    norm_origin = normalize_origin(origin)
    norm_path = normalize_path(path)
    norm_method = normalize_method(method)
    ep_id = stable_hash(norm_origin, norm_path, norm_method)

    return EndpointDefinition(
        endpoint_id=ep_id,
        origin=norm_origin,
        path=norm_path,
        method=norm_method,
        observed_parameters=observed_parameters or [],
        discovery_sources=discovery_sources or [DiscoverySource.API_SPEC],
        evidence_refs=[Id(ref) for ref in (evidence_refs or ["EVD-001"])],
        observation_refs=[Id(ref) for ref in (observation_refs or ["OBS-001"])],
    )


def make_shop_analysis_request() -> Module2AnalysisRequest:
    """Build a canonical multi-endpoint Module2AnalysisRequest with backing records."""
    evd1 = make_evidence_record("EVD-001", artifact_type=ArtifactType.HTTP_RAW_EXCHANGE)
    evd2 = make_evidence_record("EVD-002", artifact_type=ArtifactType.TOOL_RAW_OUTPUT)

    ep_products = make_endpoint(
        origin="https://shop.lab.local",
        path="/api/products",
        method="GET",
        observed_parameters=[
            ObservedParameter(
                name="sort_by",
                location=InputLocation.QUERY,
                data_type="string",
                required=False,
                evidence_refs=[Id("EVD-001")],
                observation_refs=[Id("OBS-001")],
            ),
            ObservedParameter(
                name="X-Api-Version",
                location=InputLocation.HEADER,
                data_type="string",
                required=False,
                evidence_refs=[Id("EVD-001")],
            ),
        ],
        discovery_sources=[DiscoverySource.API_SPEC, DiscoverySource.HTTP_OBSERVATION],
        evidence_refs=["EVD-001"],
        observation_refs=["OBS-001"],
    )

    ep_orders = make_endpoint(
        origin="https://shop.lab.local",
        path="/api/orders/{order_id}",
        method="GET",
        observed_parameters=[
            ObservedParameter(
                name="order_id",
                location=InputLocation.PATH,
                data_type="integer",
                required=True,
                evidence_refs=[Id("EVD-001")],
            )
        ],
        discovery_sources=[DiscoverySource.API_SPEC],
        evidence_refs=["EVD-001"],
    )

    ep_login = make_endpoint(
        origin="https://shop.lab.local",
        path="/api/login",
        method="POST",
        observed_parameters=[
            ObservedParameter(
                name="username",
                location=InputLocation.JSON_BODY,
                data_type="string",
                required=True,
                evidence_refs=[Id("EVD-001")],
            ),
            ObservedParameter(
                name="password",
                location=InputLocation.JSON_BODY,
                data_type="string",
                required=True,
                evidence_refs=[Id("EVD-001")],
            ),
        ],
        discovery_sources=[DiscoverySource.HTTP_OBSERVATION],
        evidence_refs=["EVD-001"],
    )

    obs1 = ObservationRecord(
        observation_id="OBS-001",
        assessment_id="ASM-001",
        observation_type=ObservationType.ENDPOINT,
        payload=EndpointObservationPayload(
            origin="https://shop.lab.local",
            path="/api/products",
            method="GET",
            parameters=[
                ObservedParameter(
                    name="sort_by",
                    location=InputLocation.QUERY,
                    data_type="string",
                    required=False,
                    evidence_refs=[Id("EVD-001")],
                    observation_refs=[Id("OBS-001")],
                )
            ],
        ),
        source_type=ObservationSource.HTTP_OBSERVATION,
        evidence_refs=["EVD-001"],
        observed_at=FIXED_TIME,
    )

    obs2 = ObservationRecord(
        observation_id="OBS-002",
        assessment_id="ASM-001",
        observation_type=ObservationType.TECHNOLOGY,
        payload=TechnologyObservationPayload(
            name="Apache",
            category=TechnologyCategory.WEB_SERVER,
            version="2.4.49",
        ),
        source_type=ObservationSource.WHATWEB,
        evidence_refs=["EVD-002"],
        observed_at=FIXED_TIME,
    )

    tech = TechnologyRecord(
        category=TechnologyCategory.WEB_SERVER,
        name="Apache",
        version="2.4.49",
        evidence_refs=[Id("EVD-002")],
        observation_refs=[Id("OBS-002")],
    )

    target_model = TargetModel(
        target_id=Id("TGT-001"),
        assessment_id=Id("ASM-001"),
        last_updated=FIXED_TIME,
        endpoints=[ep_products, ep_orders, ep_login],
        technologies=[tech],
    )

    return Module2AnalysisRequest(
        target_model=target_model,
        observations=[obs1, obs2],
        evidence_records=[evd1, evd2],
        source_repo_path="src/repo",
    )


def make_scope_rules(
    *,
    assessment_id: str = "ASM-001",
    target: str = "https://shop.lab.local",
    authorized_scope: list[str] | None = None,
    testing_mode: TestingMode = TestingMode.GRAYBOX,
    source_repository_ref: str | None = "/repo/shop",
) -> AssessmentConfig:
    """Build an AssessmentConfig with approved source_repository_ref."""
    return AssessmentConfig(
        assessment_id=Id(assessment_id),
        target=target,  # type: ignore[arg-type]
        authorized_scope=authorized_scope or ["shop.lab.local"],
        scope_approval=ScopeApprovalRecord(
            is_approved=True,
            approved_by="Security Lead",
            approval_timestamp=datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC),
            scope_signature_hash="0" * 64,
        ),
        testing_mode=testing_mode,
        source_repository_ref=source_repository_ref,
    )


def make_shop_analysis_request_with_scope(
    *,
    source_repo_path: str | None = "/repo/shop",
    source_repository_ref: str | None = "/repo/shop",
    testing_mode: TestingMode = TestingMode.GRAYBOX,
) -> Module2AnalysisRequest:
    """Build Module2AnalysisRequest with configured scope_rules for static analysis testing."""
    req = make_shop_analysis_request()
    scope_rules = make_scope_rules(
        testing_mode=testing_mode,
        source_repository_ref=source_repository_ref,
    )
    req.target_model.scope_rules = scope_rules
    req.source_repo_path = source_repo_path
    return req


def make_semgrep_finding(
    rule_id: str = "python.django.security.injection.sql-injection",
    file: str = "app/routes.py",
    start_line: int = 42,
    *,
    end_line: int | None = 42,
    start_column: int | None = 5,
    end_column: int | None = 40,
    snippet: str | None = "cursor.execute(user_query)",
    message: str | None = "Unsanitized user input into SQL query",
    severity: str | None = "ERROR",
    cwe: list[str] | str | None = "CWE-89: SQL Injection",
    confidence: str | None = "HIGH",
    dataflow_trace: dict | None = None,
    extra_metadata: dict | None = None,
) -> dict:
    """Build a normalized Semgrep finding dictionary."""
    meta = {"confidence": confidence}
    if cwe is not None:
        meta["cwe"] = cwe if isinstance(cwe, list) else [cwe]
    if extra_metadata:
        meta.update(extra_metadata)

    finding = {
        "rule_id": rule_id,
        "file": file,
        "start_line": start_line,
        "end_line": end_line,
        "start_column": start_column,
        "end_column": end_column,
        "message": message,
        "severity": severity,
        "snippet": snippet,
        "metadata": meta,
        "dataflow_trace": dataflow_trace,
    }
    return finding


def make_semgrep_envelope(
    findings: list[dict] | None = None,
    *,
    tool: str = "semgrep",
    version: str = "1.90.0",
    ruleset: str = "local-approved",
    path: str = ".",
    truncated: bool = False,
    errors: list | None = None,
) -> dict:
    """Build a Layer 6 Semgrep envelope payload."""
    finding_list = findings if findings is not None else []
    return {
        "summary": f"Semgrep completed with {len(finding_list)} findings",
        "data": {
            "tool": tool,
            "version": version,
            "ruleset": ruleset,
            "status": "completed",
            "path": path,
            "files_scanned": 10,
            "findings": finding_list,
            "errors": errors or [],
        },
        "truncated": truncated,
    }


def make_technology_record(
    name: str = "Django",
    version: str | None = "3.2.12",
    category: TechnologyCategory = TechnologyCategory.FRAMEWORK,
    *,
    evidence_refs: list[str] | None = None,
    observation_refs: list[str] | None = None,
) -> TechnologyRecord:
    """Build a canonical TechnologyRecord for testing."""
    return TechnologyRecord(
        category=category,
        name=name,
        version=version,
        evidence_refs=[Id(r) for r in (evidence_refs or ["EVD-001"])],
        observation_refs=[Id(r) for r in (observation_refs or ["OBS-001"])],
    )


def make_taint_semgrep_finding(
    rule_id: str = "python.sqlalchemy.security.audit.sqli.raw-sql",
    file: str = "app/routes.py",
    start_line: int = 42,
    *,
    source_file: str = "app/routes.py",
    source_line: int = 10,
    source_snippet: str = "request.args.get('sort')",
    sink_snippet: str = "cursor.execute(user_query)",
    cwe: list[str] | str | None = "CWE-89: SQL Injection",
    confidence: str | None = "HIGH",
    extra_metadata: dict | None = None,
) -> dict:
    """Build a normalized Semgrep finding with a realistic dataflow_trace."""
    dataflow_trace = {
        "taint_source": [
            {
                "location": {
                    "path": source_file,
                    "start": {"line": source_line, "col": 5},
                    "end": {"line": source_line, "col": 35},
                },
                "content": source_snippet,
            }
        ],
        "intermediate_vars": [
            {
                "location": {
                    "path": file,
                    "start": {"line": 20, "col": 5},
                    "end": {"line": 20, "col": 25},
                },
                "content": "user_query = f'SELECT * FROM items WHERE id = {val}'",
            }
        ],
        "taint_sink": [
            {
                "location": {
                    "path": file,
                    "start": {"line": start_line, "col": 5},
                    "end": {"line": start_line, "col": 35},
                },
                "content": sink_snippet,
            }
        ],
    }
    return make_semgrep_finding(
        rule_id=rule_id,
        file=file,
        start_line=start_line,
        snippet=sink_snippet,
        cwe=cwe,
        confidence=confidence,
        dataflow_trace=dataflow_trace,
        extra_metadata=extra_metadata,
    )


def make_route_binding_artifact(
    endpoint_id: str = "EP-001",
    method: str = "GET",
    path: str = "/api/items",
    file_path: str = "app/routes.py",
    start_line: int = 1,
    end_line: int = 50,
    *,
    evidence_id: str = "EVD-050",
    assessment_id: str = "ASM-001",
    source_tool_id: str = "route_extractor",
    execution_ref: str = "EXEC-010",
    extraction_method: str = "flask_route_visitor",
    extraction_method_digest: str = "a" * 64,
    source_repository_ref: str = "C:/repo",
    source_revision: str = "rev-001",
) -> tuple[EvidenceArtifactRecord, ArtifactManifest, Any]:
    """Build a canonical RouteHandlerBinding artifact, manifest, and reference."""
    import hashlib
    import json

    from websecuritycheck.analysis.correlation import RouteBindingArtifactRef
    from websecuritycheck.domain.analysis_models import EvidenceId
    from websecuritycheck.domain.models import ArtifactManifest, EvidenceArtifactRecord

    payload = {
        "schema": "websecuritycheck.route_binding_artifact.v1",
        "assessment_id": assessment_id,
        "endpoint_id": endpoint_id,
        "method": method.upper(),
        "path": path,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": end_line,
    }
    content_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    content_bytes = content_str.encode("utf-8")
    sha256_hash = hashlib.sha256(content_bytes).hexdigest()

    manifest = ArtifactManifest(
        artifact_ref=f"route-binding-{endpoint_id.lower()}",
        artifact_type=ArtifactType.SOURCE_ARTIFACT,
        content=content_str,
        sha256_hash=sha256_hash,
        size_bytes=len(content_bytes),
        media_type="application/json",
    )

    evd = EvidenceArtifactRecord(
        evidence_id=Id(evidence_id),
        assessment_id=Id(assessment_id),
        artifact_type=ArtifactType.SOURCE_ARTIFACT,
        artifact_ref=f"route-binding-{endpoint_id.lower()}",
        sha256_hash=sha256_hash,
        size_bytes=len(content_bytes),
        media_type="application/json",
        captured_at=FIXED_TIME,
        execution_ref=Id(execution_ref),
        source_tool_id=source_tool_id,
        provenance={
            "extraction_method": extraction_method,
            "extraction_method_digest": extraction_method_digest,
            "source_repository_ref": source_repository_ref,
            "source_revision": source_revision,
        },
    )

    art_ref = RouteBindingArtifactRef(
        evidence_ref=EvidenceId(evidence_id),
        manifest=manifest,
    )
    return evd, manifest, art_ref


def make_test_trust_policy(
    *,
    rule_ids: list[str] | None = None,
    ruleset_sha256: str = "b" * 64,
    producer_id: str = "route_extractor",
    approved_method: str = "flask_route_visitor",
    approved_method_digest: str = "a" * 64,
    vulnerable_apis: list[dict] | None = None,
) -> Any:
    """Build a non-empty CorrelationTrustPolicy for unit tests."""
    from websecuritycheck.analysis.correlation import (
        ApprovedRulesetEntry,
        ApprovedRuleSpec,
        ApprovedVulnerableApiEntry,
        CorrelationTrustPolicy,
        RuleMode,
        TrustedRouteProducer,
    )
    from websecuritycheck.analysis.cve import InjectionSubtype
    from websecuritycheck.domain.analysis_models import CweId, SinkKind

    r_ids = rule_ids or ["python.sqlalchemy.security.audit.sqli.raw-sql"]
    rule_specs = [
        ApprovedRuleSpec(
            rule_id=rid,
            mode=RuleMode.TAINT,
            sink_kind=SinkKind.SQL_QUERY,
            subtype=InjectionSubtype.SQL_INJECTION,
            cwe_ids=frozenset({CweId("CWE-89")}),
        )
        for rid in r_ids
    ]

    ruleset_entry = ApprovedRulesetEntry(
        ruleset_id="test-ruleset",
        sha256=ruleset_sha256,
        review_ref="REV-001",
        rules=tuple(rule_specs),
    )

    producer_entry = TrustedRouteProducer(
        producer_id=producer_id,
        approved_methods=frozenset({approved_method}),
        approved_method_digests=frozenset({approved_method_digest}),
        review_ref="REV-002",
    )

    api_entries = []
    if vulnerable_apis:
        for v in vulnerable_apis:
            api_entries.append(
                ApprovedVulnerableApiEntry(
                    cve_id=v["cve_id"],
                    technology_name=v["technology_name"],
                    ruleset_sha256=ruleset_sha256,
                    rule_ids=frozenset(v["rule_ids"]),
                    review_ref=v.get("review_ref", "REV-003"),
                    advisory_ref=v.get("advisory_ref", "ADV-001"),
                    rationale=v.get("rationale", "Test vulnerable API binding"),
                )
            )

    return CorrelationTrustPolicy(
        approved_rulesets=(ruleset_entry,),
        trusted_route_producers=(producer_entry,),
        approved_vulnerable_apis=tuple(api_entries),
    )
