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
