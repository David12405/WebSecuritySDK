"""Long-term memory: the pure diff, and the SQLite store around it.

No agent and no network. The diff is tested as a function over two lists of
findings and a set of tool names - the failure it exists to prevent is a
fixed/unverified mix-up, and that is decided entirely by those inputs. The
store is tested against a real sqlite file in `tmp_path`, because the one
thing worth checking is that a run written now is read back as the baseline
later.
"""

from __future__ import annotations

from datetime import UTC, datetime

from _builders import finding
from websecuritycheck.memory.diff import diff_runs
from websecuritycheck.memory.history import RunHistory
from websecuritycheck.results.models import CheckOutput, CheckResult

# --------------------------------------------------------------------------
# diff_runs - the pure decision
# --------------------------------------------------------------------------


def test_a_first_time_finding_is_new() -> None:
    now = finding(title="CSP header missing", location="content-security-policy")
    diff = diff_runs(
        [], [now], tools_ok={"get_response_headers"}, check_tools=["get_response_headers"]
    )
    assert diff.new == [now.id]
    assert diff.fixed == [] and diff.unchanged == [] and diff.unverified == []


def test_a_finding_in_both_runs_is_unchanged() -> None:
    before = finding(title="CSP header missing", location="content-security-policy")
    after = finding(title="CSP header missing", location="content-security-policy")
    assert before.id == after.id  # same check, location, title -> same stable id
    diff = diff_runs(
        [before], [after], tools_ok={"get_response_headers"}, check_tools=["get_response_headers"]
    )
    assert diff.unchanged == [before.id]
    assert diff.new == [] and diff.fixed == [] and diff.unverified == []


def test_a_gone_finding_is_fixed_when_its_tool_ran() -> None:
    """Named tool, and it measured this run: the finding is genuinely gone."""
    gone = finding(
        title="CSP header missing",
        location="content-security-policy",
        source_tool="get_response_headers",
    )
    diff = diff_runs(
        [gone], [], tools_ok={"get_response_headers"}, check_tools=["get_response_headers"]
    )
    assert diff.fixed == [gone.id]
    assert diff.unverified == []


def test_a_gone_finding_is_unverified_when_its_tool_failed() -> None:
    """The tool that would re-find it did not run: not a fix, an unknown."""
    gone = finding(
        title="CSP header missing",
        location="content-security-policy",
        source_tool="get_response_headers",
    )
    diff = diff_runs([gone], [], tools_ok=set(), check_tools=["get_response_headers"])
    assert diff.unverified == [gone.id]
    assert diff.fixed == []


def test_an_unattributed_gone_finding_needs_every_tool_to_have_run() -> None:
    """With no source tool, a fix can only be claimed if all tools measured.

    One of the two tools ran, so the finding might have come from the one
    that did not: `unverified`, not `fixed`.
    """
    gone = finding(title="Something", location="somewhere", source_tool="")
    diff = diff_runs([gone], [], tools_ok={"tool_a"}, check_tools=["tool_a", "tool_b"])
    assert diff.unverified == [gone.id] and diff.fixed == []

    both = diff_runs([gone], [], tools_ok={"tool_a", "tool_b"}, check_tools=["tool_a", "tool_b"])
    assert both.fixed == [gone.id] and both.unverified == []


def test_the_previous_run_id_is_carried() -> None:
    diff = diff_runs([], [], tools_ok=set(), check_tools=[], previous_run_id="abc123")
    assert diff.previous_run_id == "abc123"


def test_the_diff_can_name_every_finding_including_the_gone_ones() -> None:
    """A fixed finding's title is not in this run's result, so the diff carries it.

    Without the label map a reader of `fixed` gets a bare hash for a finding
    that is no longer anywhere in `CheckResult.findings`.
    """
    gone = finding(
        title="CSP header missing",
        location="content-security-policy",
        source_tool="get_response_headers",
    )
    kept = finding(title="HSTS header missing", location="strict-transport-security")
    diff = diff_runs(
        [gone, kept],
        [kept],
        tools_ok={"get_response_headers"},
        check_tools=["get_response_headers"],
    )
    assert diff.fixed == [gone.id]
    assert diff.label(gone.id) == "CSP header missing"  # resolvable though gone
    assert diff.label(kept.id) == "HSTS header missing"


# --------------------------------------------------------------------------
# RunHistory - persistence
# --------------------------------------------------------------------------


def _result(target: str, check: str, *, findings=(), tools_ran=1, run_id="r1") -> CheckResult:
    return CheckResult.build(
        check=check,
        target=target,
        output=CheckOutput(findings=[f for f in findings]),
        errors=[],
        trace=[],
        run_id=run_id,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        tools_ran=tools_ran,
    )


def test_a_saved_run_is_read_back_as_the_baseline(tmp_path) -> None:
    db = tmp_path / "history.db"
    from _builders import draft

    with RunHistory(db) as store:
        store.save(_result("https://x.test", "headers", findings=[draft()], run_id="first"))
        baseline = store.baseline("https://x.test", "headers")

    assert baseline is not None
    assert baseline.run_id == "first"
    assert len(baseline.findings) == 1
    assert baseline.findings[0].id  # a real Finding, id and all, round-tripped


def test_the_baseline_is_the_most_recent_measuring_run(tmp_path) -> None:
    db = tmp_path / "history.db"
    with RunHistory(db) as store:
        store.save(_result("https://x.test", "headers", run_id="old"))
        store.save(_result("https://x.test", "headers", run_id="new"))
        assert store.baseline("https://x.test", "headers").run_id == "new"


def test_a_run_that_measured_nothing_is_not_a_baseline(tmp_path) -> None:
    """Saved for history, skipped as a baseline: its empty findings mean
    'did not look', not 'found nothing'."""
    db = tmp_path / "history.db"
    with RunHistory(db) as store:
        store.save(_result("https://x.test", "headers", run_id="good", tools_ran=1))
        store.save(_result("https://x.test", "headers", run_id="blind", tools_ran=0))
        assert store.baseline("https://x.test", "headers").run_id == "good"
        assert len(store.history("https://x.test", "headers")) == 2


def test_runs_are_scoped_to_their_target_and_check(tmp_path) -> None:
    db = tmp_path / "history.db"
    with RunHistory(db) as store:
        store.save(_result("https://a.test", "headers", run_id="a"))
        store.save(_result("https://b.test", "headers", run_id="b"))
        store.save(_result("https://a.test", "tls", run_id="c"))
        assert store.baseline("https://a.test", "headers").run_id == "a"
        assert store.baseline("https://b.test", "headers").run_id == "b"
        assert store.baseline("https://a.test", "tls").run_id == "c"
        assert store.baseline("https://a.test", "cors") is None


def test_the_store_creates_its_file_and_parent(tmp_path) -> None:
    db = tmp_path / "nested" / "dir" / "history.db"
    with RunHistory(db):
        pass
    assert db.exists()


# --------------------------------------------------------------------------
# The runner wiring (_remember) - read baseline, set diff, save, without an agent
# --------------------------------------------------------------------------


def test_remember_diffs_against_the_baseline_and_saves(tmp_path) -> None:
    from _builders import draft
    from websecuritycheck.checks import HEADERS
    from websecuritycheck.config import Settings
    from websecuritycheck.engine.runner import _remember

    db = tmp_path / "history.db"
    settings = Settings(model="openai:gpt-4o-mini", scope=["https://x.test"], history_db=db)

    # First run finds a CSP problem; no baseline yet, so no diff.
    first = _result("https://x.test", "headers", findings=[draft()], run_id="first")
    _remember(first, HEADERS, settings, tools_ok={"get_response_headers"})
    assert first.diff is None

    # Second run is clean. The tool ran, so the gone finding is a real fix.
    second = _result("https://x.test", "headers", findings=[], run_id="second")
    _remember(second, HEADERS, settings, tools_ok={"get_response_headers"})

    assert second.diff is not None
    assert second.diff.previous_run_id == "first"
    assert second.diff.fixed and second.diff.unverified == []

    # Both runs are on record.
    with RunHistory(db) as store:
        assert len(store.history("https://x.test", "headers")) == 2


def test_unverified_is_carried_across_runs_until_remeasured(tmp_path) -> None:
    """A finding whose tool keeps failing stays unverified, run after run.

    This is the whole reason for the ledger: a pairwise diff against the last
    run's reported findings would lose the finding the moment a later baseline
    no longer listed it. Here `tool_b` fails twice in a row, and the Y finding
    must stay unverified both times - then, once `tool_b` measures again and Y
    is gone, it becomes a real fix and leaves the ledger.
    """
    from _builders import draft
    from websecuritycheck.results.models import stable_id

    tools = ["tool_a", "tool_b"]
    x = draft(title="X problem", location="x", source_tool="tool_a")
    y = draft(title="Y problem", location="y", source_tool="tool_b")
    y_id = stable_id("deep", "y", "Y problem")

    db = tmp_path / "history.db"
    with RunHistory(db) as store:
        # Run 1: both tools measure, both problems present.
        store.reconcile(
            _result("https://t.test", "deep", findings=[x, y], tools_ran=2, run_id="r1"),
            tools_ok={"tool_a", "tool_b"},
            check_tools=tools,
        )

        # Run 2: tool_b fails. Y cannot be re-checked -> unverified, carried.
        d2 = store.reconcile(
            _result("https://t.test", "deep", findings=[x], tools_ran=1, run_id="r2"),
            tools_ok={"tool_a"},
            check_tools=tools,
        )
        assert y_id in d2.unverified and y_id not in d2.fixed

        # Run 3: tool_b fails again. Y is STILL unverified - it did not drop
        # out just because run 2 no longer reported it.
        d3 = store.reconcile(
            _result("https://t.test", "deep", findings=[x], tools_ran=1, run_id="r3"),
            tools_ok={"tool_a"},
            check_tools=tools,
        )
        assert y_id in d3.unverified

        # Run 4: tool_b measures again and Y is gone -> a real fix, off the ledger.
        d4 = store.reconcile(
            _result("https://t.test", "deep", findings=[x], tools_ran=2, run_id="r4"),
            tools_ok={"tool_a", "tool_b"},
            check_tools=tools,
        )
        assert y_id in d4.fixed and y_id not in d4.unverified
        open_ids = {o.finding.id for o in store.open_findings("https://t.test", "deep")}
        assert y_id not in open_ids  # settled, no longer carried


def test_the_ledger_marks_present_and_unverified(tmp_path) -> None:
    from _builders import draft

    tools = ["tool_a", "tool_b"]
    x = draft(title="X problem", location="x", source_tool="tool_a")
    y = draft(title="Y problem", location="y", source_tool="tool_b")

    db = tmp_path / "history.db"
    with RunHistory(db) as store:
        store.reconcile(
            _result("https://t.test", "deep", findings=[x, y], tools_ran=2, run_id="r1"),
            tools_ok={"tool_a", "tool_b"},
            check_tools=tools,
        )
        store.reconcile(
            _result("https://t.test", "deep", findings=[x], tools_ran=1, run_id="r2"),
            tools_ok={"tool_a"},
            check_tools=tools,
        )
        ledger = store.open_findings("https://t.test", "deep")
        by_status = {o.finding.title: o.status for o in ledger}
        assert by_status == {"X problem": "present", "Y problem": "unverified"}


def test_remember_does_nothing_without_a_history_db() -> None:
    from _builders import draft
    from websecuritycheck.checks import HEADERS
    from websecuritycheck.config import Settings
    from websecuritycheck.engine.runner import _remember

    settings = Settings(model="openai:gpt-4o-mini", scope=["https://x.test"])  # history_db None
    result = _result("https://x.test", "headers", findings=[draft()], run_id="only")
    _remember(result, HEADERS, settings, tools_ok={"get_response_headers"})
    assert result.diff is None  # no store, nothing remembered, no crash
