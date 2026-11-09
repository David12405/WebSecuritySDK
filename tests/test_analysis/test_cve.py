"""Unit and integration tests for M2-T04: Injection-Focused CVE Matching & Candidate Extraction."""

from __future__ import annotations

import asyncio
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from websecuritycheck.analysis.cve import (
    CPEProductEntry,
    CVEAdvisoryRecord,
    CVEProviderError,
    InjectionScopePolicy,
    InjectionScopeStatus,
    InjectionSubtype,
    LocalSeedCVEProvider,
    ProductMatchKind,
    TrustedInjectionClassification,
    VersionApplicability,
    aextract_cve_candidates,
    evaluate_version_applicability,
    extract_cve_candidates,
)
from websecuritycheck.analysis.inputs import extract_input_candidates
from websecuritycheck.analysis.sinks import extract_sink_candidates
from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    Module2AnalysisRequest,
    Module2Output,
    validate_module2_handoff,
)
from websecuritycheck.domain.enums import (
    ArtifactType,
    ObservationSource,
    ObservationType,
    TechnologyCategory,
    TestingMode,
)
from websecuritycheck.domain.models import (
    EndpointDefinition,
    EndpointObservationPayload,
    EvidenceArtifactRecord,
    Id,
    NetworkServiceObservationPayload,
    ObservationRecord,
    ObservedParameter,
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

from .fixtures import (
    FIXED_TIME,
    make_evidence_record,
    make_scope_rules,
    make_semgrep_envelope,
    make_semgrep_finding,
    make_technology_record,
)


@pytest.fixture
def tmp_path():
    with tempfile.TemporaryDirectory(prefix="m2_t04_") as td:
        yield Path(td).resolve()


def _make_request(
    technologies: list[TechnologyRecord] | None = None,
    observations: list[ObservationRecord] | None = None,
    evidence_records: list[EvidenceArtifactRecord] | None = None,
    endpoints: list[EndpointDefinition] | None = None,
    source_repo_path: str | None = "/repo/shop",
) -> Module2AnalysisRequest:
    evd = evidence_records or [make_evidence_record("EVD-001")]
    techs = technologies or [make_technology_record("Django", "3.2.12")]

    norm_origin = normalize_origin("https://shop.lab.local")
    norm_path = normalize_path("/api/products")
    norm_method = normalize_method("GET")
    ep_id = stable_hash(norm_origin, norm_path, norm_method)

    eps = endpoints or [
        EndpointDefinition(
            endpoint_id=ep_id,
            origin=norm_origin,
            path=norm_path,
            method=norm_method,
            observed_parameters=[
                ObservedParameter(
                    name="q",
                    location="QUERY",  # type: ignore[arg-type]
                    evidence_refs=[Id("EVD-001")],
                )
            ],
            evidence_refs=[Id("EVD-001")],
        )
    ]

    target_model = TargetModel(
        target_id=Id("TGT-001"),
        assessment_id=Id("ASM-001"),
        last_updated=FIXED_TIME,
        technologies=techs,
        endpoints=eps,
        scope_rules=make_scope_rules(
            testing_mode=TestingMode.GRAYBOX,
            source_repository_ref=source_repo_path,
        ),
    )

    return Module2AnalysisRequest(
        target_model=target_model,
        observations=observations or [],
        evidence_records=evd,
        source_repo_path=source_repo_path,
    )


# ---------------------------------------------------------------------------
# Test 1 — CVE thuộc SQL Injection được chấp nhận kèm environmental_preconditions
# ---------------------------------------------------------------------------


def test_sql_injection_cve_accepted_with_preconditions() -> None:
    tech = make_technology_record("Django", "3.2.12", TechnologyCategory.FRAMEWORK)
    req = _make_request(technologies=[tech])

    result = extract_cve_candidates(req)
    cve_ids = {c.cve_id for c in result.cve_candidates}

    assert "CVE-2022-28346" in cve_ids
    assert "CVE-2022-34265" in cve_ids

    cand_28346 = next(c for c in result.cve_candidates if c.cve_id == "CVE-2022-28346")
    assert cand_28346.is_confirmed is False
    assert cand_28346.cwe_id == "CWE-89"
    assert cand_28346.target_technology.name == "Django"
    assert cand_28346.target_technology.version == "3.2.12"

    meta_28346 = next(m for m in result.correlation_metadata if m.cve_id == "CVE-2022-28346")
    assert meta_28346.injection_subtype == InjectionSubtype.SQL_INJECTION
    assert len(meta_28346.environmental_preconditions) >= 1
    assert "QuerySet.annotate" in meta_28346.environmental_preconditions[0]


# ---------------------------------------------------------------------------
# Test 2 — CVE thuộc OS Command Injection / Code Injection / SSTI / NoSQLi
# ---------------------------------------------------------------------------


def test_command_code_ssti_nosql_injections_accepted() -> None:
    tech_php = make_technology_record("PHP", "8.2.15", TechnologyCategory.RUNTIME)
    tech_spring = make_technology_record("Spring Framework", "5.3.15", TechnologyCategory.FRAMEWORK)
    tech_jinja = make_technology_record("Jinja2", "2.10.0", TechnologyCategory.FRAMEWORK)
    tech_mongo = make_technology_record(
        "Spring Data MongoDB", "3.3.2", TechnologyCategory.FRAMEWORK
    )

    req = _make_request(technologies=[tech_php, tech_spring, tech_jinja, tech_mongo])
    result = extract_cve_candidates(req)

    cve_subtypes = {m.cve_id: m.injection_subtype for m in result.correlation_metadata}

    assert cve_subtypes["CVE-2024-4577"] == InjectionSubtype.OS_COMMAND_INJECTION
    assert cve_subtypes["CVE-2022-22965"] == InjectionSubtype.CODE_INJECTION
    assert cve_subtypes["CVE-2019-10906"] == InjectionSubtype.SSTI
    assert cve_subtypes["CVE-2022-22980"] == InjectionSubtype.NOSQL_INJECTION

    # Verify every candidate is unconfirmed
    for c in result.cve_candidates:
        assert c.is_confirmed is False


# ---------------------------------------------------------------------------
# Test 3 — CVE không thuộc Injection bị từ chối (EXCLUDED)
# ---------------------------------------------------------------------------


class MockExcludedCVEProvider:
    is_complete_source = True

    def resolve_product(
        self, normalized_name: str, category: TechnologyCategory
    ) -> tuple[ProductMatchKind, CPEProductEntry | None]:
        return ProductMatchKind.EXACT, CPEProductEntry(
            vendor="apache",
            product="http_server",
            cpe_prefix="cpe:2.3:a:apache:http_server",
            exact_names=("apache",),
            allowed_categories=(TechnologyCategory.WEB_SERVER, TechnologyCategory.OTHER),
        )

    def query_by_product(self, vendor: str, product: str) -> list[CVEAdvisoryRecord]:
        return [
            CVEAdvisoryRecord(
                cve_id="CVE-2021-41773",
                vendor="apache",
                product="http_server",
                cpe_prefix="cpe:2.3:a:apache:http_server",
                affected_range="==2.4.49",
                primary_cwe_id="CWE-22",  # Path Traversal
                cwe_ids=("CWE-22",),
                summary="Apache Path Traversal",
                advisory_source="NVD",
                published_date="2021-10-05",
            ),
            CVEAdvisoryRecord(
                cve_id="CVE-2020-9999",
                vendor="apache",
                product="http_server",
                cpe_prefix="cpe:2.3:a:apache:http_server",
                affected_range="==2.4.49",
                primary_cwe_id="CWE-79",  # XSS
                cwe_ids=("CWE-79",),
                summary="Apache XSS",
                advisory_source="NVD",
                published_date="2020-01-01",
            ),
            CVEAdvisoryRecord(
                cve_id="CVE-2021-8888",
                vendor="apache",
                product="http_server",
                cpe_prefix="cpe:2.3:a:apache:http_server",
                affected_range="==2.4.49",
                primary_cwe_id="CWE-918",  # SSRF
                cwe_ids=("CWE-918",),
                summary="Apache SSRF",
                advisory_source="NVD",
                published_date="2021-01-01",
            ),
        ]


def test_excluded_cwes_rejected_as_excluded() -> None:
    tech = make_technology_record("Apache", "2.4.49", TechnologyCategory.WEB_SERVER)
    req = _make_request(technologies=[tech])

    result = extract_cve_candidates(req, provider=MockExcludedCVEProvider())  # type: ignore[arg-type]
    assert len(result.cve_candidates) == 0

    excluded_diag = [d for d in result.diagnostics if d.outcome == "EXCLUDED"]
    assert len(excluded_diag) == 3


# ---------------------------------------------------------------------------
# Test 4 — Kiểm thử Trust Boundary của InjectionScopePolicy chống Provider Spoofing
# ---------------------------------------------------------------------------


def test_injection_scope_policy_spoofing_resistance() -> None:
    policy = InjectionScopePolicy()

    # Provider attempts to claim CWE-22 (Path Traversal) is SQL_INJECTION
    spoofed_adv = CVEAdvisoryRecord(
        cve_id="CVE-2021-41773",
        vendor="apache",
        product="http_server",
        cpe_prefix="cpe:2.3:a:apache:http_server",
        affected_range="==2.4.49",
        primary_cwe_id="CWE-22",
        cwe_ids=("CWE-22",),
        injection_subtype=InjectionSubtype.SQL_INJECTION,  # Spoofed
        injection_rationale="Malicious claim that traversal is SQLi",
        summary="Spoofed advisory",
        advisory_source="Untrusted",
        published_date="2021-10-05",
    )
    eval_res = policy.evaluate(spoofed_adv)
    assert eval_res.status == InjectionScopeStatus.EXCLUDED

    # Provider attempts to claim context-dependent CWE-74 is Injection without trusted allowlist
    cwe74_adv = CVEAdvisoryRecord(
        cve_id="CVE-2023-1111",
        vendor="custom",
        product="custom",
        cpe_prefix="cpe:2.3:a:custom:custom",
        affected_range="==1.0.0",
        primary_cwe_id="CWE-74",
        cwe_ids=("CWE-74",),
        injection_subtype=InjectionSubtype.SQL_INJECTION,
        summary="CWE-74 advisory",
        advisory_source="Untrusted",
        published_date="2023-01-01",
    )
    eval_74 = policy.evaluate(cwe74_adv)
    assert eval_74.status == InjectionScopeStatus.UNKNOWN

    # Provider gives CWE-89 (SQLi) but specifies OS_COMMAND_INJECTION subtype
    conflicting_adv = CVEAdvisoryRecord(
        cve_id="CVE-2023-2222",
        vendor="custom",
        product="custom",
        cpe_prefix="cpe:2.3:a:custom:custom",
        affected_range="==1.0.0",
        primary_cwe_id="CWE-89",
        cwe_ids=("CWE-89",),
        injection_subtype=InjectionSubtype.OS_COMMAND_INJECTION,  # Conflicts with CWE-89
        summary="Conflicting advisory",
        advisory_source="Untrusted",
        published_date="2023-01-01",
    )
    eval_conf = policy.evaluate(conflicting_adv)
    assert eval_conf.status == InjectionScopeStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Test 5 — CVE có nhiều CWE (Multi-CWE) được kiểm soát qua TrustedInjectionClassification
# ---------------------------------------------------------------------------


def test_multi_cwe_trusted_classification_control() -> None:
    custom_trusted = {
        "CVE-2022-22980": TrustedInjectionClassification(
            cve_id="CVE-2022-22980",  # type: ignore[arg-type]
            expected_cwe_ids=frozenset({"CWE-917", "CWE-943"}),  # type: ignore[arg-type]
            canonical_subtype=InjectionSubtype.NOSQL_INJECTION,
            policy_rationale="Trusted Spring Data MongoDB NoSQL injection",
        )
    }
    policy = InjectionScopePolicy(trusted_classifications=custom_trusted)  # type: ignore[arg-type]

    # Authorized multi-CWE
    adv_trusted = CVEAdvisoryRecord(
        cve_id="CVE-2022-22980",
        vendor="vmware",
        product="spring_data_mongodb",
        cpe_prefix="cpe:2.3:a:vmware:spring_data_mongodb",
        affected_range=">=3.3.0, <=3.3.4",
        primary_cwe_id="CWE-917",
        cwe_ids=("CWE-917", "CWE-943"),
        summary="MongoDB SpEL",
        advisory_source="VMware",
        published_date="2022-06-20",
    )
    eval_trusted = policy.evaluate(adv_trusted)
    assert eval_trusted.status == InjectionScopeStatus.ALLOWED
    assert eval_trusted.subtype == InjectionSubtype.NOSQL_INJECTION
    assert eval_trusted.used_trusted_allowlist is True

    # Unknown multi-CWE (CWE-287 Auth Bypass + CWE-89 SQLi) not in allowlist
    adv_untrusted = CVEAdvisoryRecord(
        cve_id="CVE-2024-9999",
        vendor="acme",
        product="app",
        cpe_prefix="cpe:2.3:a:acme:app",
        affected_range="==1.0.0",
        primary_cwe_id="CWE-89",
        cwe_ids=("CWE-287", "CWE-89"),
        summary="Mixed auth + SQLi",
        advisory_source="NVD",
        published_date="2024-01-01",
    )
    eval_untrusted = policy.evaluate(adv_untrusted)
    assert eval_untrusted.status == InjectionScopeStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Test 6 — Khớp sai TechnologyCategory hoặc tên sản phẩm mơ hồ (AMBIGUOUS)
# ---------------------------------------------------------------------------


def test_category_mismatch_and_ambiguous_name() -> None:
    provider = LocalSeedCVEProvider()

    # Django with wrong category (e.g. DATABASE instead of FRAMEWORK)
    kind, _ = provider.resolve_product("django", TechnologyCategory.DATABASE)
    assert kind == ProductMatchKind.UNMAPPED

    # Ambiguous alias matching
    class AmbiguousProvider:
        is_complete_source = True

        def resolve_product(
            self, normalized_name: str, category: TechnologyCategory
        ) -> tuple[ProductMatchKind, CPEProductEntry | None]:
            return ProductMatchKind.AMBIGUOUS, None

        def query_by_product(self, vendor: str, product: str) -> list[CVEAdvisoryRecord]:
            return []

    tech = make_technology_record("AmbiguousProduct", "1.0.0")
    req = _make_request(technologies=[tech])
    res = extract_cve_candidates(req, provider=AmbiguousProvider())  # type: ignore[arg-type]
    assert len(res.cve_candidates) == 0
    assert any(d.stage == "product_matching" for d in res.diagnostics)


# ---------------------------------------------------------------------------
# Test 7 — Toán học khoảng [major.minor.0, major.(minor+1).0) cho major.minor
# ---------------------------------------------------------------------------


def test_version_applicability_interval_math() -> None:
    # 7a: Exact 3-part point evaluation
    st, _ = evaluate_version_applicability("3.2.12", ">=3.2.0, <3.2.13")
    assert st == VersionApplicability.AFFECTED

    st, _ = evaluate_version_applicability("3.2.13", ">=3.2.0, <3.2.13")
    assert st == VersionApplicability.NOT_AFFECTED

    # 7b: Entire minor branch affected ([3.2.0, 3.3.0))
    st, _ = evaluate_version_applicability("3.2", ">=3.2.0, <3.3.0")
    assert st == VersionApplicability.AFFECTED

    # Contiguous OR clauses spanning entire branch: [3.2.0, 3.2.5) U [3.2.5, 3.3.0)
    st, _ = evaluate_version_applicability("3.2", ">=3.2.0, <3.2.5; >=3.2.5, <3.3.0")
    assert st == VersionApplicability.AFFECTED

    # 7c: Entire minor branch unaffected
    st, _ = evaluate_version_applicability("3.1", ">=3.2.0, <3.2.13")
    assert st == VersionApplicability.NOT_AFFECTED

    st, _ = evaluate_version_applicability("3.3", ">=3.2.0, <3.2.13")
    assert st == VersionApplicability.NOT_AFFECTED

    st, _ = evaluate_version_applicability("3.2", "<3.2.0")
    assert st == VersionApplicability.NOT_AFFECTED

    # 7d: Partial minor branch intersection -> UNKNOWN
    # Branch 3.2 only affected up to 3.2.12; patches >= 3.2.13 are unaffected
    st, reason = evaluate_version_applicability("3.2", ">=3.2.0, <3.2.13")
    assert st == VersionApplicability.UNKNOWN
    assert "Partial minor branch" in reason

    # Missing 3.2.0 from range: (>3.2.0, <3.3.0)
    st, _ = evaluate_version_applicability("3.2", ">3.2.0, <3.3.0")
    assert st == VersionApplicability.UNKNOWN


# ---------------------------------------------------------------------------
# Test 8 — Distro backport & non-standard suffixes không tạo false positive
# ---------------------------------------------------------------------------


def test_distro_backport_version_unknown() -> None:
    # Linux distribution package version with patch suffix
    st, reason = evaluate_version_applicability("8.1.2-1ubuntu2.14", ">=8.1.0, <8.1.29")
    assert st == VersionApplicability.UNKNOWN
    assert "distro/backport" in reason

    st, reason = evaluate_version_applicability("3.2.12-deb11u1", ">=3.2.0, <3.2.13")
    assert st == VersionApplicability.UNKNOWN

    st, _ = evaluate_version_applicability("3.x", ">=3.2.0, <3.3.0")
    assert st == VersionApplicability.UNKNOWN

    st, _ = evaluate_version_applicability("v3.2.12", ">=3.2.0, <3.2.13")
    assert st == VersionApplicability.AFFECTED


# ---------------------------------------------------------------------------
# Test 9 — Seed catalog thiếu coverage có limitation message
# ---------------------------------------------------------------------------


def test_seed_catalog_coverage_limitation() -> None:
    provider = LocalSeedCVEProvider()
    assert provider.is_complete_source is False

    tech = make_technology_record("Django", "3.2.12")
    req = _make_request(technologies=[tech])
    res = extract_cve_candidates(req, provider=provider)

    expected_lim = "LocalSeedCVEProvider is an offline MVP seed catalog"
    assert any(expected_lim in lim for lim in res.limitations)


# ---------------------------------------------------------------------------
# Test 10 — Kiểm chứng tính độc lập thực sự của Evidence (Provenance Independence)
# ---------------------------------------------------------------------------


def test_provenance_independence_scoring() -> None:
    # Case A: Two observation references from the SAME tool execution
    obs1 = ObservationRecord(
        observation_id="OBS-001",
        assessment_id="ASM-001",
        observation_type=ObservationType.TECHNOLOGY,
        payload=TechnologyObservationPayload(
            name="Django",
            category=TechnologyCategory.FRAMEWORK,
            version="3.2.12",
        ),
        source_type=ObservationSource.WHATWEB,
        source_tool_id="whatweb_scanner",
        execution_ref="EXEC-001",
        evidence_refs=["EVD-001"],
        observed_at=FIXED_TIME,
    )
    obs2 = ObservationRecord(
        observation_id="OBS-002",
        assessment_id="ASM-001",
        observation_type=ObservationType.TECHNOLOGY,
        payload=TechnologyObservationPayload(
            name="Django",
            category=TechnologyCategory.FRAMEWORK,
            version="3.2.12",
        ),
        source_type=ObservationSource.WHATWEB,
        source_tool_id="whatweb_scanner",
        execution_ref="EXEC-001",
        evidence_refs=["EVD-001"],
        observed_at=FIXED_TIME,
    )
    tech_same = make_technology_record(
        "Django",
        "3.2.12",
        evidence_refs=["EVD-001"],
        observation_refs=["OBS-001", "OBS-002"],
    )
    req_same = _make_request(
        technologies=[tech_same],
        observations=[obs1, obs2],
        evidence_records=[make_evidence_record("EVD-001")],
    )
    res_same = extract_cve_candidates(req_same)
    cand_same = next(c for c in res_same.cve_candidates if c.cve_id == "CVE-2022-28346")
    meta_same = next(m for m in res_same.correlation_metadata if m.cve_id == "CVE-2022-28346")
    assert meta_same.independent_source_count == 1
    assert cand_same.confidence == ConfidenceLevel.MEDIUM

    # Case B: Truly distinct tools (WhatWeb observation + Nmap service observation)
    evd2 = make_evidence_record("EVD-002")
    obs_nmap = ObservationRecord(
        observation_id="OBS-003",
        assessment_id="ASM-001",
        observation_type=ObservationType.NETWORK_SERVICE,
        payload=NetworkServiceObservationPayload(
            address="127.0.0.1",
            port=8000,
            protocol="tcp",
            state="open",
            product="Django",
            version="3.2.12",
        ),
        source_type=ObservationSource.NMAP,
        source_tool_id="nmap_scanner",
        execution_ref="EXEC-002",
        evidence_refs=["EVD-002"],
        observed_at=FIXED_TIME,
    )
    tech_indep = make_technology_record(
        "Django",
        "3.2.12",
        evidence_refs=["EVD-001"],
        observation_refs=["OBS-001"],
    )
    req_indep = _make_request(
        technologies=[tech_indep],
        observations=[obs1, obs_nmap],
        evidence_records=[make_evidence_record("EVD-001"), evd2],
    )
    res_indep = extract_cve_candidates(req_indep)
    cand_indep = next(c for c in res_indep.cve_candidates if c.cve_id == "CVE-2022-28346")
    meta_indep = next(m for m in res_indep.correlation_metadata if m.cve_id == "CVE-2022-28346")
    assert meta_indep.independent_source_count == 2
    assert cand_indep.confidence == ConfidenceLevel.HIGH


# ---------------------------------------------------------------------------
# Test 11 — Deterministic ordering, ID assignment và Deduplication
# ---------------------------------------------------------------------------


def test_deterministic_ordering_and_deduplication() -> None:
    tech1 = make_technology_record("Django", "3.2.12", TechnologyCategory.FRAMEWORK)
    tech2 = make_technology_record("WordPress", "5.8.0", TechnologyCategory.CMS)

    req_forward = _make_request(technologies=[tech1, tech2])
    req_reversed = _make_request(technologies=[tech2, tech1])

    res_f = extract_cve_candidates(req_forward)
    res_r = extract_cve_candidates(req_reversed)

    # Identical candidate IDs and order
    ids_f = [c.cve_candidate_id for c in res_f.cve_candidates]
    ids_r = [c.cve_candidate_id for c in res_r.cve_candidates]
    assert ids_f == ids_r
    assert ids_f == ["CVC-001", "CVC-002", "CVC-003"]

    cve_f = [(c.target_technology.canonical_key, c.cve_id) for c in res_f.cve_candidates]
    cve_r = [(c.target_technology.canonical_key, c.cve_id) for c in res_r.cve_candidates]
    assert cve_f == cve_r


# ---------------------------------------------------------------------------
# Test 12 — End-to-end compatibility với M2-T01, M2-T02, M2-T03 và validate_module2_handoff()
# ---------------------------------------------------------------------------


def test_end_to_end_module2_handoff_validation() -> None:
    evd_http = make_evidence_record("EVD-001", artifact_type=ArtifactType.HTTP_RAW_EXCHANGE)
    evd_semgrep = make_evidence_record(
        "EVD-002",
        artifact_type=ArtifactType.SOURCE_ARTIFACT,
        artifact_ref="source-file-1",
    )

    norm_origin = normalize_origin("https://shop.lab.local")
    norm_path = normalize_path("/api/products")
    norm_method = normalize_method("GET")
    ep_id = stable_hash(norm_origin, norm_path, norm_method)

    ep = EndpointDefinition(
        endpoint_id=ep_id,
        origin=norm_origin,
        path=norm_path,
        method=norm_method,
        observed_parameters=[
            ObservedParameter(
                name="category",
                location="QUERY",  # type: ignore[arg-type]
                evidence_refs=[Id("EVD-001")],
                observation_refs=[Id("OBS-001")],
            )
        ],
        evidence_refs=[Id("EVD-001")],
        observation_refs=[Id("OBS-001")],
    )

    obs_ep = ObservationRecord(
        observation_id="OBS-001",
        assessment_id="ASM-001",
        observation_type=ObservationType.ENDPOINT,
        payload=EndpointObservationPayload(
            origin=norm_origin,
            path=norm_path,
            method=norm_method,
            parameters=[
                ObservedParameter(
                    name="category",
                    location="QUERY",  # type: ignore[arg-type]
                    evidence_refs=[Id("EVD-001")],
                    observation_refs=[Id("OBS-001")],
                )
            ],
        ),
        source_type=ObservationSource.HTTP_OBSERVATION,
        evidence_refs=["EVD-001"],
        observed_at=FIXED_TIME,
    )

    obs_tech = ObservationRecord(
        observation_id="OBS-002",
        assessment_id="ASM-001",
        observation_type=ObservationType.TECHNOLOGY,
        payload=TechnologyObservationPayload(
            name="Django",
            category=TechnologyCategory.FRAMEWORK,
            version="3.2.12",
        ),
        source_type=ObservationSource.WHATWEB,
        evidence_refs=["EVD-001"],
        observed_at=FIXED_TIME,
    )

    tech = make_technology_record(
        "Django",
        "3.2.12",
        TechnologyCategory.FRAMEWORK,
        evidence_refs=["EVD-001"],
        observation_refs=["OBS-002"],
    )

    req = _make_request(
        technologies=[tech],
        observations=[obs_ep, obs_tech],
        evidence_records=[evd_http, evd_semgrep],
        endpoints=[ep],
        source_repo_path="/repo/shop",
    )

    # 1. Run M2-T02 (inputs)
    inp_res = extract_input_candidates(req)
    assert len(inp_res.inputs) >= 1

    # 2. Run M2-T03 (sinks) with synthetic semgrep output
    finding = make_semgrep_finding(
        rule_id="python.django.security.injection.sql-injection",
        file="app/views.py",
        start_line=10,
        snippet="cursor.execute(query)",
        confidence="HIGH",
    )
    envelope = make_semgrep_envelope(findings=[finding])
    sink_res = extract_sink_candidates(req, envelope)
    assert len(sink_res.sink_candidates) >= 1

    # 3. Run M2-T04 (cve_candidates)
    cve_res = extract_cve_candidates(req)
    assert len(cve_res.cve_candidates) >= 1

    # 4. Construct Module2Output
    output = Module2Output(
        assessment_id="ASM-001",  # type: ignore[arg-type]
        target_id="TGT-001",  # type: ignore[arg-type]
        generated_at=datetime.now(UTC),
        inputs=list(inp_res.inputs),
        sink_candidates=list(sink_res.sink_candidates),
        cve_candidates=list(cve_res.cve_candidates),
        hypotheses=[],
        analysis_evidence_records=list(sink_res.analysis_evidence_records),
    )

    # 5. Execute handoff validation — must pass with ZERO errors!
    validate_module2_handoff(output, req)


# ---------------------------------------------------------------------------
# Test 13 — Provider Error Handling
# ---------------------------------------------------------------------------


def test_provider_errors_fail_closed(tmp_path) -> None:
    # Missing file
    with pytest.raises(CVEProviderError):
        LocalSeedCVEProvider(catalog_path=tmp_path / "nonexistent.json")

    # Malformed JSON
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(CVEProviderError):
        LocalSeedCVEProvider(catalog_path=bad_json)

    # Bad affected_range syntax
    bad_syntax = tmp_path / "bad_syntax.json"
    bad_syntax.write_text(
        """{
        "catalog_version": "1.0",
        "published_date": "2026-01-01",
        "provider_name": "test",
        "products": [],
        "advisories": [{
            "cve_id": "CVE-2022-28346",
            "vendor": "a", "product": "b", "cpe_prefix": "cpe:2.3:a:a:b",
            "affected_range": "INVALID_SYNTAX_OPERATOR",
            "summary": "Valid summary description",
            "advisory_source": "src",
            "published_date": "2022"
        }]
    }""",
        encoding="utf-8",
    )
    LocalSeedCVEProvider(catalog_path=bad_syntax)
    with pytest.raises(CVEProviderError):
        evaluate_version_applicability("1.0.0", "INVALID_SYNTAX")


# ---------------------------------------------------------------------------
# Test 14 — Async candidate extraction
# ---------------------------------------------------------------------------


def test_coroutine_candidate_extraction() -> None:
    tech = make_technology_record("Django", "3.2.12")
    req = _make_request(technologies=[tech])

    res = asyncio.run(aextract_cve_candidates(req))
    assert len(res.cve_candidates) >= 2
    assert all(isinstance(c.is_confirmed, bool) and not c.is_confirmed for c in res.cve_candidates)
