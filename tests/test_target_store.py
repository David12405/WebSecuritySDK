from datetime import UTC, datetime, timedelta

import pytest

from websecuritycheck.analysis.inputs import extract_input_candidates
from websecuritycheck.domain import (
    ArtifactManifest,
    ArtifactType,
    AssessmentConfig,
    InputLocation,
    ScopeApprovalRecord,
    TestingMode,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from websecuritycheck.memory import SQLiteTargetStore
from websecuritycheck.recon import (
    build_module2_request,
    process_tool_result,
    validate_assessment_config,
)


def test_sqlite_store_round_trips_snapshot_and_journal(tmp_path):
    with SQLiteTargetStore(tmp_path / "targets.db") as store:
        execution = ToolExecutionResult(
            execution_id=store.allocate_execution_id("ASM-001"),
            assessment_id="ASM-001",
            tool_id="probe_http",
            target="https://example.com/x",
            result_type="HTTPProbeResult",
            result_data={"data": {"url": "https://example.com/x", "status": 200}},
            status=ToolExecutionStatus.COMPLETED,
            started_at=datetime.now(UTC),
        )
        processing = process_tool_result(execution)
        store.persist(execution, processing)
        model = store.load_target("ASM-001", "https://example.com/x")
        assert model is not None
        assert model.revision == 1
        assert store.allocate_execution_id("ASM-001") == "EXEC-002"

    with SQLiteTargetStore(tmp_path / "targets.db") as store:
        model = store.load_target("ASM-001", "https://example.com/x")
        assert model is not None
        assert model.endpoints[0].endpoint_id


def _probe(store, assessment, url):
    """One tool execution persisted the way the adapter does it."""
    execution = ToolExecutionResult(
        execution_id=store.allocate_execution_id(assessment),
        assessment_id=assessment,
        tool_id="probe_http",
        target=url,
        result_type="HTTPProbeResult",
        result_data={"data": {"url": url, "status": 200}},
        status=ToolExecutionStatus.COMPLETED,
        started_at=datetime.now(UTC),
    )
    current = store.load_target(assessment, url)
    target_id = store.target_id_for(assessment, url)
    processing = process_tool_result(execution, current_target_model=current, target_id=target_id)
    store.persist(execution, processing)


def test_one_site_is_one_target_however_many_urls_are_probed(tmp_path):
    """The fragmentation fix: a site's URLs collapse onto one TargetModel.

    Keyed on the raw URL, probing three paths made three separate targets and
    no model held the whole surface. Keyed on the origin, the three are
    endpoints of one model - which is what Module 2 reads.
    """
    with SQLiteTargetStore(tmp_path / "t.db") as store:
        for path in ("/", "/assets/app.js", "/api/users"):
            _probe(store, "ASM-001", f"https://site.test{path}")

        model = store.load_target("ASM-001", "https://site.test/")
        assert model is not None
        # Loading by any of the probed URLs returns the same single model.
        assert store.load_target("ASM-001", "https://site.test/api/users").target_id == (
            model.target_id
        )
        paths = sorted(ep.path for ep in model.endpoints)
        assert paths == ["/", "/api/users", "/assets/app.js"], paths


def test_two_sites_do_not_collide_on_one_target_id(tmp_path):
    """The overwrite fix: different sites get different ids, no contamination.

    Both used to default to TGT-001 and overwrite each other's snapshot.
    """
    with SQLiteTargetStore(tmp_path / "t.db") as store:
        _probe(store, "ASM-001", "https://alpha.test/")
        _probe(store, "ASM-001", "https://beta.test/")

        alpha = store.load_target("ASM-001", "https://alpha.test/")
        beta = store.load_target("ASM-001", "https://beta.test/")
        assert alpha is not None and beta is not None
        assert alpha.target_id != beta.target_id
        # alpha was not overwritten by beta: its endpoint is still its own.
        assert all("alpha.test" in ep.origin for ep in alpha.endpoints)
        assert all("beta.test" in ep.origin for ep in beta.endpoints)


def _approved_assessment(
    assessment_id: str = "ASM-001",
    *,
    authorized_scope: list[str] | None = None,
    excluded_scope: list[str] | None = None,
    is_approved: bool = True,
) -> AssessmentConfig:
    approval = (
        ScopeApprovalRecord(
            is_approved=True,
            approved_by="sec-lead",
            approval_timestamp=datetime.now(UTC) - timedelta(minutes=1),
            scope_signature_hash="a" * 64,
        )
        if is_approved
        else ScopeApprovalRecord(is_approved=False)
    )
    return AssessmentConfig(
        assessment_id=assessment_id,
        target="https://site.test/",
        authorized_scope=authorized_scope or ["https://site.test"],
        excluded_scope=excluded_scope or [],
        scope_approval=approval,
        testing_mode=TestingMode.BLACKBOX,
    )


def test_sqlite_store_prevents_id_collisions_and_builds_module2_request(tmp_path):
    assessment = _approved_assessment()
    with SQLiteTargetStore(tmp_path / "m1_m2.db") as store:
        # First execution emits BROWSER_BEHAVIOR (not referenced by TargetModel.endpoints).
        exec1 = ToolExecutionResult(
            execution_id=store.allocate_execution_id("ASM-001"),
            assessment_id="ASM-001",
            tool_id="explore_browser",
            target="https://site.test/",
            result_type="BROWSER_FLOW",
            result_data={
                "data": {
                    "final_url": "https://site.test/",
                    "actions": [{"action_id": "ACT-001", "kind": "click"}],
                }
            },
            artifact_manifests=[
                ArtifactManifest(
                    artifact_ref="browser-trace-1",
                    artifact_type=ArtifactType.BROWSER_TRACE,
                    content="trace-1",
                )
            ],
            status=ToolExecutionStatus.COMPLETED,
            started_at=datetime.now(UTC),
        )
        evd_ids, obs_ids = store.load_allocated_ids("ASM-001")
        p1 = process_tool_result(
            exec1,
            assessment=assessment,
            target_id=store.target_id_for("ASM-001", "https://site.test/"),
            existing_evidence_ids=evd_ids,
            existing_observation_ids=obs_ids,
        )
        store.persist(exec1, p1)

        # Second execution must not collide with EVD-001 / OBS-001 from exec1.
        exec2 = ToolExecutionResult(
            execution_id=store.allocate_execution_id("ASM-001"),
            assessment_id="ASM-001",
            tool_id="probe_http",
            target="https://site.test/search?q=test",
            result_type="HTTPProbeResult",
            result_data={
                "data": {
                    "url": "https://site.test/search?q=test",
                    "method": "GET",
                    "status": 200,
                }
            },
            artifact_manifests=[
                ArtifactManifest(
                    artifact_ref="http-exchange-2",
                    artifact_type=ArtifactType.HTTP_RAW_EXCHANGE,
                    content="exchange-2",
                )
            ],
            status=ToolExecutionStatus.COMPLETED,
            started_at=datetime.now(UTC),
        )
        evd_ids, obs_ids = store.load_allocated_ids("ASM-001")
        p2 = process_tool_result(
            exec2,
            current_target_model=store.load_target("ASM-001", "https://site.test/"),
            assessment=assessment,
            target_id=store.target_id_for("ASM-001", "https://site.test/"),
            existing_evidence_ids=evd_ids,
            existing_observation_ids=obs_ids,
        )
        store.persist(exec2, p2)

        assert [r.evidence_id for r in p1.evidence_records] == ["EVD-001"]
        assert [r.evidence_id for r in p2.evidence_records] == ["EVD-002"]
        assert [r.observation_id for r in p1.observation_records] == ["OBS-001"]
        assert [r.observation_id for r in p2.observation_records] == ["OBS-002"]

        m2_request = build_module2_request(
            store, "ASM-001", "https://site.test/", require_scope_approval=True
        )
        assert len(m2_request.observations) == 2
        assert len(m2_request.evidence_records) == 2

        extracted = extract_input_candidates(m2_request)
        assert [(c.location, c.parameter_name) for c in extracted.inputs] == [
            (InputLocation.QUERY, "q")
        ]


def test_build_module2_request_fails_closed_when_approval_required_and_missing(tmp_path):
    with SQLiteTargetStore(tmp_path / "unapproved.db") as store:
        _probe(store, "ASM-001", "https://site.test/items?id=1")
        with pytest.raises(ValueError, match="approved scope is required"):
            build_module2_request(
                store, "ASM-001", "https://site.test/", require_scope_approval=True
            )

        unapproved = _approved_assessment(is_approved=False)
        with pytest.raises(ValueError, match="must be approved"):
            build_module2_request(
                store,
                "ASM-001",
                "https://site.test/",
                assessment=unapproved,
                require_scope_approval=True,
            )


def test_validate_assessment_config_enforces_scope_invariants_without_broadening():
    valid = _approved_assessment(excluded_scope=["https://site.test/admin"])
    validate_assessment_config(
        valid,
        expected_assessment_id="ASM-001",
        target="https://site.test/api",
        configured_scope=["https://site.test"],
        require_approved=True,
    )

    with pytest.raises(ValueError, match="outside authorized_scope"):
        validate_assessment_config(valid, configured_scope=["https://other.test"])

    with pytest.raises(ValueError, match="excluded_scope"):
        validate_assessment_config(valid, target="https://site.test/admin/users")
