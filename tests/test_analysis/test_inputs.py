"""Comprehensive unit tests for Module 2 Input Candidate Extraction (M2-T02)."""

from __future__ import annotations

import random

from test_analysis.fixtures import (
    FIXED_TIME,
    make_endpoint,
    make_evidence_record,
    make_shop_analysis_request,
)
from websecuritycheck.analysis.inputs import (
    extract_input_candidates,
)
from websecuritycheck.domain.analysis_models import (
    Module2AnalysisRequest,
    Module2Output,
    validate_module2_handoff,
)
from websecuritycheck.domain.enums import (
    DiscoverySource,
    InputLocation,
    ObservationSource,
    ObservationType,
)
from websecuritycheck.domain.models import (
    AuthenticationObservationPayload,
    HttpExchangeObservationPayload,
    Id,
    ObservationRecord,
    ObservedParameter,
    TargetModel,
)


def test_extract_all_supported_input_locations():
    """Verify deterministic extraction across all 9 canonical InputLocation enum values."""
    evd = make_evidence_record("EVD-001")
    locations = [
        (InputLocation.QUERY, "q"),
        (InputLocation.PATH, "user_id"),
        (InputLocation.FORM, "username"),
        (InputLocation.JSON_BODY, "email"),
        (InputLocation.XML_BODY, "payload"),
        (InputLocation.HEADER, "X-Auth-Token"),
        (InputLocation.COOKIE, "session_id"),
        (InputLocation.MULTIPART, "avatar"),
        (InputLocation.DOM, "query_selector"),
    ]
    params = [
        ObservedParameter(
            name=name,
            location=loc,
            data_type="string",
            evidence_refs=[Id("EVD-001")],
        )
        for loc, name in locations
    ]
    endpoint = make_endpoint(
        path="/api/test-inputs",
        method="POST",
        observed_parameters=params,
        evidence_refs=["EVD-001"],
    )
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id=Id("TGT-001"),
            assessment_id=Id("ASM-001"),
            last_updated=FIXED_TIME,
            endpoints=[endpoint],
        ),
        evidence_records=[evd],
    )
    result = extract_input_candidates(request)
    extracted_locations = {inp.location for inp in result.inputs}
    assert extracted_locations == {loc for loc, _ in locations}
    assert len(result.inputs) == 9
    assert all(inp.sample_value is None for inp in result.inputs)


def test_strict_evidence_grounding_rejects_bare_target_model_ids():
    """Verify bare TargetModel ID strings are rejected unless backed by records."""
    endpoint = make_endpoint(
        path="/api/unbacked",
        observed_parameters=[
            ObservedParameter(
                name="sort",
                location=InputLocation.QUERY,
                evidence_refs=[Id("EVD-001")],
            )
        ],
        evidence_refs=["EVD-001"],
    )
    # No evidence_records or observations provided
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id=Id("TGT-001"),
            assessment_id=Id("ASM-001"),
            last_updated=FIXED_TIME,
            endpoints=[endpoint],
        ),
        evidence_records=[],
        observations=[],
    )
    # Bare request without verified evidence records or caller assertions yields 0 inputs
    result = extract_input_candidates(request)
    assert len(result.inputs) == 0
    assert any("No authoritative evidence_records" in lim for lim in result.limitations)

    # When caller provides trusted assertion for EVD-001, extraction succeeds
    result_with_assertion = extract_input_candidates(
        request, caller_asserted_evidence_ids={"EVD-001"}
    )
    assert len(result_with_assertion.inputs) == 1
    assert result_with_assertion.inputs[0].parameter_name == "sort"

    # Alternatively, passing verified_evidence_ids alias works identically
    result_with_alias = extract_input_candidates(request, verified_evidence_ids={"EVD-001"})
    assert len(result_with_alias.inputs) == 1


def test_no_blind_endpoint_evidence_inheritance_for_observed_parameters():
    """Verify an ObservedParameter never blindly inherits parent EndpointDefinition evidence."""
    evd = make_evidence_record("EVD-001")
    endpoint = make_endpoint(
        path="/api/strict-param",
        observed_parameters=[
            # This param has NO verified refs on its own
            ObservedParameter(
                name="debug",
                location=InputLocation.QUERY,
                evidence_refs=[],
                observation_refs=[],
            ),
            # This param HAS verified refs
            ObservedParameter(
                name="search",
                location=InputLocation.QUERY,
                evidence_refs=[Id("EVD-001")],
            ),
        ],
        evidence_refs=["EVD-001"],
    )
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id=Id("TGT-001"),
            assessment_id=Id("ASM-001"),
            last_updated=FIXED_TIME,
            endpoints=[endpoint],
        ),
        evidence_records=[evd],
    )
    result = extract_input_candidates(request)
    param_names = [inp.parameter_name for inp in result.inputs]
    assert "search" in param_names
    assert "debug" not in param_names
    assert any("Skipped ungrounded parameter 'debug'" in lim for lim in result.limitations)


def test_unverified_metadata_never_pollutes_or_overrides_verified_metadata():
    """Verify unverified parameter metadata is isolated and cannot corrupt verified metadata."""
    evd = make_evidence_record("EVD-001")
    # Endpoint has verified parameter "id" as integer
    ep = make_endpoint(
        path="/api/items",
        observed_parameters=[
            ObservedParameter(
                name="id",
                location=InputLocation.QUERY,
                data_type="integer",
                required=True,
                evidence_refs=[Id("EVD-001")],
            ),
            # Duplicate declaration but unverified with contradictory data_type="string"
            ObservedParameter(
                name="id",
                location=InputLocation.QUERY,
                data_type="string",
                required=False,
                evidence_refs=[Id("EVD-999")],  # unresolvable
            ),
        ],
        evidence_refs=["EVD-001"],
    )
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id=Id("TGT-001"),
            assessment_id=Id("ASM-001"),
            last_updated=FIXED_TIME,
            endpoints=[ep],
        ),
        evidence_records=[evd],
    )
    result = extract_input_candidates(request)
    assert len(result.inputs) == 1
    # Verified data_type remains "integer" and was NOT corrupted into None or conflicting
    assert result.inputs[0].data_type == "integer"
    assert result.inputs[0].required is True
    assert not any("Conflicting data_type" in w for w in result.warnings)


def test_path_template_grounding_rules_and_concrete_route_matching():
    """Verify concrete HTTP observations match route templates unambiguously."""
    evd = make_evidence_record("EVD-001")
    ep_template = make_endpoint(
        origin="https://shop.lab.local",
        path="/api/orders/{order_id}",
        method="GET",
        discovery_sources=[DiscoverySource.CRAWLER],  # Not an API spec source
        evidence_refs=[],
        observation_refs=[],
    )
    # Validated concrete HTTP observation GET /api/orders/98765
    obs = ObservationRecord(
        observation_id="OBS-001",
        assessment_id="ASM-001",
        observation_type=ObservationType.ENDPOINT,
        payload=HttpExchangeObservationPayload(
            method="GET",
            url="https://shop.lab.local/api/orders/98765?sort=asc",
            status=200,
        ),
        source_type=ObservationSource.HTTP_OBSERVATION,
        evidence_refs=["EVD-001"],
        observed_at=FIXED_TIME,
    )
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id=Id("TGT-001"),
            assessment_id=Id("ASM-001"),
            last_updated=FIXED_TIME,
            endpoints=[ep_template],
        ),
        evidence_records=[evd],
        observations=[obs],
    )
    result = extract_input_candidates(request)
    # Concrete observation grounds both template parameter 'order_id' and query parameter 'sort'
    names = {inp.parameter_name for inp in result.inputs}
    assert "order_id" in names
    assert "sort" in names
    order_id_input = next(inp for inp in result.inputs if inp.parameter_name == "order_id")
    assert order_id_input.location is InputLocation.PATH
    assert order_id_input.required is True
    assert "OBS-001" in order_id_input.observation_refs


def test_ambiguous_template_matching_is_safely_rejected():
    """Verify multiple matching route templates are rejected as ambiguous."""
    evd = make_evidence_record("EVD-001")
    ep1 = make_endpoint(
        origin="https://shop.lab.local",
        path="/api/{category}/details",
        method="GET",
        evidence_refs=["EVD-001"],
    )
    ep2 = make_endpoint(
        origin="https://shop.lab.local",
        path="/api/items/{action}",
        method="GET",
        evidence_refs=["EVD-001"],
    )
    # Both templates match /api/items/details
    obs = ObservationRecord(
        observation_id="OBS-001",
        assessment_id="ASM-001",
        observation_type=ObservationType.ENDPOINT,
        payload=HttpExchangeObservationPayload(
            method="GET",
            url="https://shop.lab.local/api/items/details?filter=1",
            status=200,
        ),
        source_type=ObservationSource.HTTP_OBSERVATION,
        evidence_refs=["EVD-001"],
        observed_at=FIXED_TIME,
    )
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id=Id("TGT-001"),
            assessment_id=Id("ASM-001"),
            last_updated=FIXED_TIME,
            endpoints=[ep1, ep2],
        ),
        evidence_records=[evd],
        observations=[obs],
    )
    result = extract_input_candidates(request)
    assert any("ambiguously matched multiple route templates" in lim for lim in result.limitations)


def test_conservative_cookie_policy_skips_authentication_observations():
    """Verify AuthenticationObservationPayload cookie_names are not attributed to endpoints."""
    evd = make_evidence_record("EVD-001")
    ep = make_endpoint(
        origin="https://shop.lab.local",
        path="/login",
        method="POST",
        observed_parameters=[
            ObservedParameter(
                name="declared_cookie",
                location=InputLocation.COOKIE,
                evidence_refs=[Id("EVD-001")],
            )
        ],
        evidence_refs=["EVD-001"],
    )
    auth_obs = ObservationRecord(
        observation_id="OBS-001",
        assessment_id="ASM-001",
        observation_type=ObservationType.AUTHENTICATION,
        payload=AuthenticationObservationPayload(
            subject="https://shop.lab.local/login",
            cookie_names=["session_id", "csrf_token"],
        ),
        source_type=ObservationSource.HTTP_OBSERVATION,
        evidence_refs=["EVD-001"],
        observed_at=FIXED_TIME,
    )
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id=Id("TGT-001"),
            assessment_id=Id("ASM-001"),
            last_updated=FIXED_TIME,
            endpoints=[ep],
        ),
        evidence_records=[evd],
        observations=[auth_obs],
    )
    result = extract_input_candidates(request)
    cookie_inputs = [inp for inp in result.inputs if inp.location is InputLocation.COOKIE]
    assert len(cookie_inputs) == 1
    assert cookie_inputs[0].parameter_name == "declared_cookie"
    assert any("Skipped AuthenticationObservationPayload" in lim for lim in result.limitations)


def test_header_lowercasing_and_case_preservation_for_other_locations():
    """Verify HTTP headers are case-folded to lowercase while other locations preserve case."""
    evd = make_evidence_record("EVD-001")
    ep = make_endpoint(
        path="/api/case",
        observed_parameters=[
            ObservedParameter(
                name="X-Api-Key",
                location=InputLocation.HEADER,
                evidence_refs=[Id("EVD-001")],
            ),
            ObservedParameter(
                name="x-api-key",
                location=InputLocation.HEADER,
                evidence_refs=[Id("EVD-001")],
            ),
            ObservedParameter(
                name="userId",
                location=InputLocation.QUERY,
                evidence_refs=[Id("EVD-001")],
            ),
            ObservedParameter(
                name="userid",
                location=InputLocation.QUERY,
                evidence_refs=[Id("EVD-001")],
            ),
        ],
        evidence_refs=["EVD-001"],
    )
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id=Id("TGT-001"),
            assessment_id=Id("ASM-001"),
            last_updated=FIXED_TIME,
            endpoints=[ep],
        ),
        evidence_records=[evd],
    )
    result = extract_input_candidates(request)
    headers = [inp for inp in result.inputs if inp.location is InputLocation.HEADER]
    queries = [inp for inp in result.inputs if inp.location is InputLocation.QUERY]
    # Headers deduplicated to lowercase
    assert len(headers) == 1
    assert headers[0].parameter_name == "x-api-key"
    # Query parameters preserve distinct casing
    assert len(queries) == 2
    assert {q.parameter_name for q in queries} == {"userId", "userid"}


def test_sample_values_always_omitted_in_mvp():
    """Verify raw parameter values in observations are never copied into sample_value."""
    request = make_shop_analysis_request()
    result = extract_input_candidates(request)
    assert len(result.inputs) > 0
    assert all(inp.sample_value is None for inp in result.inputs)


def test_conflicting_metadata_and_required_flag_merging():
    """Verify conflicting data types reset to None with warning, and required=True dominates."""
    evd = make_evidence_record("EVD-001")
    ep = make_endpoint(
        path="/api/merge",
        observed_parameters=[
            ObservedParameter(
                name="page",
                location=InputLocation.QUERY,
                data_type="integer",
                required=False,
                evidence_refs=[Id("EVD-001")],
            ),
            ObservedParameter(
                name="page",
                location=InputLocation.QUERY,
                data_type="string",
                required=True,
                evidence_refs=[Id("EVD-001")],
            ),
        ],
        evidence_refs=["EVD-001"],
    )
    request = Module2AnalysisRequest(
        target_model=TargetModel(
            target_id=Id("TGT-001"),
            assessment_id=Id("ASM-001"),
            last_updated=FIXED_TIME,
            endpoints=[ep],
        ),
        evidence_records=[evd],
    )
    result = extract_input_candidates(request)
    assert len(result.inputs) == 1
    inp = result.inputs[0]
    assert inp.data_type is None
    assert inp.required is True
    assert any("Conflicting data_type" in w for w in result.warnings)


def test_full_result_determinism_permutation_invariance_and_m2_t01_handoff():
    """Verify exact result determinism across input permutations and compatibility with M2-T01."""
    base_request = make_shop_analysis_request()
    reference_result = extract_input_candidates(base_request)

    for seed in (42, 1337, 9999):
        rng = random.Random(seed)
        shuffled_eps = list(base_request.target_model.endpoints)
        rng.shuffle(shuffled_eps)
        shuffled_obs = list(base_request.observations)
        rng.shuffle(shuffled_obs)
        shuffled_evd = list(base_request.evidence_records)
        rng.shuffle(shuffled_evd)

        permuted_request = Module2AnalysisRequest(
            target_model=TargetModel(
                target_id=base_request.target_model.target_id,
                assessment_id=base_request.target_model.assessment_id,
                last_updated=base_request.target_model.last_updated,
                endpoints=shuffled_eps,
                technologies=base_request.target_model.technologies,
            ),
            observations=shuffled_obs,
            evidence_records=shuffled_evd,
            source_repo_path=base_request.source_repo_path,
        )
        permuted_result = extract_input_candidates(permuted_request)

        # Entire result object is identical
        assert permuted_result.inputs == reference_result.inputs
        assert permuted_result.limitations == reference_result.limitations
        assert permuted_result.warnings == reference_result.warnings

    # Validate handoff compatibility into Module2Output
    output = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=FIXED_TIME,
        inputs=reference_result.inputs,
        limitations=reference_result.limitations,
        warnings=reference_result.warnings,
    )
    validated_output = validate_module2_handoff(output, base_request)
    assert len(validated_output.inputs) == len(reference_result.inputs)
