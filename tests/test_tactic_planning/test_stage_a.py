"""Stage A - tactic authoring, resolution, admission, and the file registry.

Offline throughout: a recorded WSTG snapshot and a `FakeTacticAuthor` stand in
for the service and the model, so nothing here needs a network or credentials.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
import yaml

from websecuritycheck.domain.analysis_models import VulnerabilityCategory
from websecuritycheck.tactic_planning.contracts import SQLiSafetyPolicy
from websecuritycheck.tactic_planning.stage_a import (
    FakeTacticAuthor,
    FileTacticRegistry,
    GithubWstgAdapter,
    RegistryError,
    TacticResolutionError,
    WstgRetrievalError,
    WstgSnapshot,
    admit_tactic,
    reference_for,
    resolve_tactic,
    retrieve_snapshot,
    validate_snapshot,
)

from ._factories import (
    NOW,
    enabled_policy,
    recorded_adapter,
    reference_tactic_document,
)

SQLI = VulnerabilityCategory.SQL_INJECTION


class _RaisingAdapter:
    """A WSTG adapter that fails if touched - proves the warm path skips WSTG."""

    def health(self) -> bool:  # pragma: no cover - should never be reached warm
        raise AssertionError("WSTG health checked on a warm reuse")

    def get_test_case(self, wstg_id: str) -> WstgSnapshot:  # pragma: no cover
        raise AssertionError("WSTG retrieved on a warm reuse")


class _StubAdapter:
    def __init__(self, snapshot: WstgSnapshot) -> None:
        self._snapshot = snapshot

    def health(self) -> bool:
        return True

    def get_test_case(self, wstg_id: str) -> WstgSnapshot:
        return self._snapshot


def _snapshot(**overrides) -> WstgSnapshot:
    base = {
        "requested_id": "WSTG-INPV-05",
        "returned_id": "WSTG-v42-INPV-05",
        "wstg_version": "v42",
        "content": "SQL injection testing methodology.",
    }
    base.update(overrides)
    return WstgSnapshot(**base)


# --------------------------------------------------------------------------- #
# WSTG mapping and retrieval
# --------------------------------------------------------------------------- #


def test_sqli_maps_to_inpv05():
    assert reference_for(SQLI) == ("WSTG-INPV-05", "WSTG-v42-INPV-05")


def test_recorded_snapshot_retrieves_and_checks_version():
    snapshot = retrieve_snapshot(recorded_adapter(), SQLI)
    assert snapshot.wstg_version == "v42"
    assert snapshot.returned_id == "WSTG-v42-INPV-05"
    assert snapshot.content.strip()


def test_truncated_content_rejected():
    with pytest.raises(WstgRetrievalError, match="truncated"):
        retrieve_snapshot(_StubAdapter(_snapshot(truncated=True)), SQLI)


def test_empty_content_rejected():
    with pytest.raises(WstgRetrievalError, match="empty"):
        retrieve_snapshot(_StubAdapter(_snapshot(content="   ")), SQLI)


def test_wrong_version_rejected():
    with pytest.raises(WstgRetrievalError, match="version"):
        retrieve_snapshot(_StubAdapter(_snapshot(wstg_version="v41")), SQLI)


def test_mismatched_returned_id_rejected():
    with pytest.raises(WstgRetrievalError, match="does not match"):
        retrieve_snapshot(_StubAdapter(_snapshot(returned_id="WSTG-v42-INPV-09")), SQLI)


# --------------------------------------------------------------------------- #
# Admission gates
# --------------------------------------------------------------------------- #


def test_corrected_reference_admits_clean():
    snapshot = retrieve_snapshot(recorded_adapter(), SQLI)
    violations = admit_tactic(
        reference_tactic_document(), snapshot=snapshot, safety_policy=enabled_policy()
    )
    assert violations == []


def test_unmodified_reference_fails_wstg_gate():
    """The supplied fixture uses WSTG-INJT-05 on purpose; it must be rejected."""
    snapshot = retrieve_snapshot(recorded_adapter(), SQLI)
    violations = admit_tactic(
        reference_tactic_document(fix_wstg=False), snapshot=snapshot, safety_policy=enabled_policy()
    )
    assert any("WSTG-v42-INPV-05" in v for v in violations)


def test_identity_gate_rejects_wrong_tactic_id():
    snapshot = retrieve_snapshot(recorded_adapter(), SQLI)
    doc = reference_tactic_document().model_copy(update={"tactic_id": "TACTIC-SQLI-999"})
    violations = admit_tactic(doc, snapshot=snapshot, safety_policy=enabled_policy())
    assert any("tactic_id" in v for v in violations)


def test_safety_gate_rejects_budget_over_ceiling():
    snapshot = retrieve_snapshot(recorded_adapter(), SQLI)
    doc = reference_tactic_document()
    steps = [s.model_copy() for s in doc.steps]
    for step in steps:
        if step.id == "primary_detection":
            step.suggested_inputs = step.suggested_inputs.model_copy(
                update={"max_requests": 5000}
            )
    doc = doc.model_copy(update={"steps": steps})
    violations = admit_tactic(doc, snapshot=snapshot, safety_policy=enabled_policy())
    assert any("exceeds ceiling" in v for v in violations)


# --------------------------------------------------------------------------- #
# Resolver: author, publish, reuse, invalidate
# --------------------------------------------------------------------------- #


def test_cold_registry_authors_and_publishes():
    with tempfile.TemporaryDirectory() as d:
        registry = FileTacticRegistry(d)
        author = FakeTacticAuthor(reference_tactic_document())
        resolved = resolve_tactic(
            SQLI,
            registry=registry,
            author=author,
            adapter=recorded_adapter(),
            safety_policy=enabled_policy(),
            model_name="fake:deterministic",
            now=NOW,
        )
        assert resolved.reused is False
        assert resolved.tactic.metadata.tactic_version == "0.1.0"
        root = Path(d)
        assert (root / "tactics" / "SQL_INJECTION" / "0.1.0.yaml").is_file()
        assert (root / "tactics" / "SQL_INJECTION" / "0.1.0.metadata.json").is_file()
        assert (root / "tactics" / "SQL_INJECTION" / "active.json").is_file()
        assert (root / "wstg" / "v42" / "WSTG-INPV-05" / "raw.json").is_file()
        assert (root / "manifest.json").is_file()


def test_warm_registry_reuses_without_wstg_or_model():
    with tempfile.TemporaryDirectory() as d:
        registry = FileTacticRegistry(d)
        author = FakeTacticAuthor(reference_tactic_document())
        resolve_tactic(
            SQLI,
            registry=registry,
            author=author,
            adapter=recorded_adapter(),
            safety_policy=enabled_policy(),
            model_name="fake",
            now=NOW,
        )
        # Second resolution must reuse: a raising adapter proves WSTG is untouched,
        # and the author call count proves the model is not invoked again.
        warm = resolve_tactic(
            SQLI,
            registry=registry,
            author=author,
            adapter=_RaisingAdapter(),
            safety_policy=enabled_policy(),
            model_name="fake",
            now=NOW,
        )
        assert warm.reused is True
        assert warm.tactic.metadata.tactic_version == "0.1.0"
        assert author.calls == 1


def test_fingerprint_change_invalidates_reuse():
    with tempfile.TemporaryDirectory() as d:
        registry = FileTacticRegistry(d)
        author = FakeTacticAuthor(reference_tactic_document())
        resolve_tactic(
            SQLI,
            registry=registry,
            author=author,
            adapter=recorded_adapter(),
            safety_policy=enabled_policy(),
            model_name="fake",
            now=NOW,
        )
        # A looser aggregate budget changes the safety fingerprint, so the active
        # tactic is no longer compatible and a new version is authored.
        changed = SQLiSafetyPolicy(enabled=True, aggregate_max_requests=300)
        second = resolve_tactic(
            SQLI,
            registry=registry,
            author=author,
            adapter=recorded_adapter(),
            safety_policy=changed,
            model_name="fake",
            now=NOW,
        )
        assert second.reused is False
        assert second.tactic.metadata.tactic_version == "0.1.1"
        assert registry.get_active("SQL_INJECTION").metadata.tactic_version == "0.1.1"


def test_retry_then_succeed_feeds_back_violations():
    bad = reference_tactic_document(fix_wstg=False)  # fails the WSTG gate
    good = reference_tactic_document()
    with tempfile.TemporaryDirectory() as d:
        registry = FileTacticRegistry(d)
        author = FakeTacticAuthor([bad, good])
        resolved = resolve_tactic(
            SQLI,
            registry=registry,
            author=author,
            adapter=recorded_adapter(),
            safety_policy=enabled_policy(),
            model_name="fake",
            now=NOW,
        )
        assert resolved.attempts == 2
        # The second attempt was handed the first attempt's violations.
        assert author.feedback_seen[1]
        assert any("WSTG" in msg for msg in author.feedback_seen[1])


def test_all_attempts_fail_publishes_nothing():
    bad = reference_tactic_document(fix_wstg=False)
    with tempfile.TemporaryDirectory() as d:
        registry = FileTacticRegistry(d)
        author = FakeTacticAuthor([bad, bad, bad])
        with pytest.raises(TacticResolutionError):
            resolve_tactic(
                SQLI,
                registry=registry,
                author=author,
                adapter=recorded_adapter(),
                safety_policy=enabled_policy(),
                model_name="fake",
                now=NOW,
            )
        assert registry.get_active("SQL_INJECTION") is None


def test_tampered_yaml_is_detected():
    with tempfile.TemporaryDirectory() as d:
        registry = FileTacticRegistry(d)
        author = FakeTacticAuthor(reference_tactic_document())
        resolve_tactic(
            SQLI,
            registry=registry,
            author=author,
            adapter=recorded_adapter(),
            safety_policy=enabled_policy(),
            model_name="fake",
            now=NOW,
        )
        tactic_file = Path(d) / "tactics" / "SQL_INJECTION" / "0.1.0.yaml"
        data = yaml.safe_load(tactic_file.read_text("utf-8"))
        data["safety_rules"].append("tampered rule inserted after admission")
        tactic_file.write_text(yaml.safe_dump(data), encoding="utf-8")
        with pytest.raises(RegistryError, match="hash mismatch"):
            registry.get_active("SQL_INJECTION")


# --------------------------------------------------------------------------- #
# Tier 2 WSTG snapshot cache
# --------------------------------------------------------------------------- #


def test_absent_snapshot_cache_returns_none():
    with tempfile.TemporaryDirectory() as d:
        registry = FileTacticRegistry(d)
        assert registry.get_wstg_snapshot("WSTG-INPV-05", "v42") is None


def test_reauthor_reuses_cached_snapshot_without_touching_source():
    with tempfile.TemporaryDirectory() as d:
        registry = FileTacticRegistry(d)
        author = FakeTacticAuthor(reference_tactic_document())
        resolve_tactic(
            SQLI,
            registry=registry,
            author=author,
            adapter=recorded_adapter(),
            safety_policy=enabled_policy(),
            model_name="fake",
            now=NOW,
        )
        # Publishing cached the snapshot. A policy change invalidates the tactic
        # (Tier 1 miss) but the WSTG content is unchanged, so Stage A must reuse
        # the stored snapshot - a raising adapter proves the source is untouched.
        changed = SQLiSafetyPolicy(enabled=True, aggregate_max_requests=300)
        second = resolve_tactic(
            SQLI,
            registry=registry,
            author=author,
            adapter=_RaisingAdapter(),
            safety_policy=changed,
            model_name="fake",
            now=NOW,
        )
        assert second.reused is False
        assert second.tactic.metadata.tactic_version == "0.1.1"
        assert any("snapshot cache hit" in line for line in second.trace)


# --------------------------------------------------------------------------- #
# GithubWstgAdapter (official OWASP repo)
# --------------------------------------------------------------------------- #


def test_github_adapter_builds_versioned_snapshot(monkeypatch):
    import httpx

    class _FakeResponse:
        text = "# Testing for SQL Injection\n\n|WSTG-INPV-05|\n\nMethodology text."

        def raise_for_status(self) -> None:
            return None

    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse())
    snapshot = GithubWstgAdapter().get_test_case("WSTG-INPV-05")
    assert snapshot.returned_id == "WSTG-v42-INPV-05"
    assert snapshot.wstg_version == "v42"
    assert "OWASP/wstg/v4.2" in snapshot.source_uri
    assert snapshot.license == "CC BY-SA 4.0"
    # The provenance checks accept it as the SQLi reference.
    validate_snapshot(snapshot, SQLI)


def test_github_adapter_unknown_id_rejected_without_network():
    with pytest.raises(WstgRetrievalError, match="document path"):
        GithubWstgAdapter().get_test_case("WSTG-INPV-99")


@pytest.mark.live_wstg
@pytest.mark.skipif(
    not os.environ.get("WEBSEC_LIVE_WSTG"),
    reason="set WEBSEC_LIVE_WSTG=1 to fetch from the official OWASP repo",
)
def test_github_adapter_live_fetch_is_authentic():
    """Opt-in: really fetch WSTG-INPV-05 from the official OWASP repo."""
    snapshot = retrieve_snapshot(GithubWstgAdapter(), SQLI)
    assert snapshot.wstg_version == "v42"
    assert "WSTG-INPV-05" in snapshot.content
    assert "SQL Injection" in snapshot.content
