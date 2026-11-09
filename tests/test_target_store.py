from datetime import UTC, datetime

from websecuritycheck.domain import ToolExecutionResult, ToolExecutionStatus
from websecuritycheck.memory import SQLiteTargetStore
from websecuritycheck.recon import process_tool_result


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
