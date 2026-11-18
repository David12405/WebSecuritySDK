"""Stage A entry: reuse an admitted tactic, or author one and publish it.

The warm path never touches WSTG or a model: if an active tactic's environment
fingerprint matches the current one, it is returned as-is. The cold path
retrieves the WSTG snapshot, asks the author for a candidate, runs the
deterministic admission gates, and publishes on the first clean attempt - feeding
each rejection's messages back to the author for a bounded number of retries. If
every attempt fails, nothing is published, the active tactic is untouched, and a
typed error is raised for the coordinator to turn into UNSUPPORTED/INCONCLUSIVE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ...domain.analysis_models import VulnerabilityCategory
from ..contracts import SQLiSafetyPolicy, capability_fingerprint
from .author import PROMPT_VERSION, TacticAuthor
from .models import (
    TACTIC_SCHEMA_VERSION,
    AdmittedTactic,
    CompatibilityFingerprint,
    EnvironmentFingerprint,
    TacticDocument,
    TacticMetadata,
    TacticState,
    bundled_schema_sha256,
)
from .registry import TacticRegistry
from .validation import admit_tactic
from .wstg import (
    EXPECTED_WSTG_VERSION,
    WstgAdapter,
    WstgSnapshot,
    reference_for,
    retrieve_snapshot,
    snapshot_metadata,
    validate_snapshot,
)

DEFAULT_MAX_RETRIES = 2


class TacticResolutionError(Exception):
    """Raised when no compatible tactic can be reused or authored."""

    def __init__(self, message: str, *, report: list[str] | None = None) -> None:
        super().__init__(message)
        self.report = report or []


@dataclass
class ResolvedTactic:
    tactic: AdmittedTactic
    reused: bool
    attempts: int
    trace: list[str] = field(default_factory=list)


def environment_fingerprint(
    category: VulnerabilityCategory,
    safety_policy: SQLiSafetyPolicy,
    *,
    wstg_version: str = EXPECTED_WSTG_VERSION,
) -> EnvironmentFingerprint:
    return EnvironmentFingerprint(
        vulnerability_category=category.value,
        wstg_version=wstg_version,
        tactic_schema_version=TACTIC_SCHEMA_VERSION,
        tactic_schema_sha256=bundled_schema_sha256(),
        capability_fingerprint=capability_fingerprint(),
        safety_policy_fingerprint=safety_policy.fingerprint(),
    )


def resolve_tactic(
    category: VulnerabilityCategory,
    *,
    registry: TacticRegistry,
    author: TacticAuthor,
    adapter: WstgAdapter,
    safety_policy: SQLiSafetyPolicy,
    model_name: str,
    max_retries: int = DEFAULT_MAX_RETRIES,
    now: datetime | None = None,
) -> ResolvedTactic:
    trace: list[str] = []
    env_fp = environment_fingerprint(category, safety_policy)

    active = registry.get_active(category.value)
    if active is not None and active.metadata.environment_fingerprint == env_fp.value():
        trace.append(f"reuse: active {active.metadata.tactic_version} matched environment")
        return ResolvedTactic(tactic=active, reused=True, attempts=0, trace=trace)

    if active is None:
        trace.append("author: cold registry; no active tactic")
    else:
        trace.append("author: active tactic incompatible with current environment")

    snapshot = _resolve_snapshot(category, registry=registry, adapter=adapter, trace=trace)

    feedback: list[str] = []
    last_report: list[str] = []
    for attempt in range(max_retries + 1):
        try:
            candidate = author.author(
                snapshot, safety_policy=safety_policy, attempt=attempt, feedback=feedback
            )
        except Exception as exc:
            trace.append(f"author: attempt {attempt} raised {type(exc).__name__}")
            last_report = [f"author error: {exc}"]
            feedback = last_report
            continue

        violations = admit_tactic(candidate, snapshot=snapshot, safety_policy=safety_policy)
        if not violations:
            admitted = _publish(
                candidate,
                snapshot=snapshot,
                env_fp=env_fp,
                category=category,
                safety_policy=safety_policy,
                registry=registry,
                model_name=model_name,
                attempts=attempt + 1,
                now=now or datetime.now(UTC),
            )
            trace.append(f"publish: {admitted.metadata.tactic_version}")
            return ResolvedTactic(
                tactic=admitted, reused=False, attempts=attempt + 1, trace=trace
            )

        trace.append(f"admit: attempt {attempt} rejected ({len(violations)} violation(s))")
        last_report = violations
        feedback = violations

    raise TacticResolutionError(
        f"tactic authoring failed after {max_retries + 1} attempt(s)", report=last_report
    )


def _resolve_snapshot(
    category: VulnerabilityCategory,
    *,
    registry: TacticRegistry,
    adapter: WstgAdapter,
    trace: list[str],
) -> WstgSnapshot:
    """Tier 2: reuse a persisted WSTG snapshot, else fetch it from the source.

    A stored snapshot for the current version is validated and reused, so a
    tactic-cache miss does not re-query WSTG when the content has not changed.
    """
    bare_id, _versioned = reference_for(category)
    cached = registry.get_wstg_snapshot(bare_id, EXPECTED_WSTG_VERSION)
    if cached is not None:
        snapshot = validate_snapshot(cached, category)
        trace.append(f"wstg: snapshot cache hit {snapshot.returned_id}")
        return snapshot
    snapshot = retrieve_snapshot(adapter, category)
    trace.append(f"wstg: fetched {snapshot.returned_id} from source ({snapshot.wstg_version})")
    return snapshot


def _publish(
    candidate: TacticDocument,
    *,
    snapshot: WstgSnapshot,
    env_fp: EnvironmentFingerprint,
    category: VulnerabilityCategory,
    safety_policy: SQLiSafetyPolicy,
    registry: TacticRegistry,
    model_name: str,
    attempts: int,
    now: datetime,
) -> AdmittedTactic:
    compatibility = CompatibilityFingerprint(
        vulnerability_category=category.value,
        wstg_version=snapshot.wstg_version,
        wstg_content_sha256=snapshot.content_hash(),
        tactic_schema_version=TACTIC_SCHEMA_VERSION,
        tactic_schema_sha256=bundled_schema_sha256(),
        capability_fingerprint=capability_fingerprint(),
        safety_policy_fingerprint=safety_policy.fingerprint(),
    )
    version = registry.next_version(category.value)
    metadata = TacticMetadata(
        tactic_id=candidate.tactic_id,
        tactic_version=version,
        schema_version=TACTIC_SCHEMA_VERSION,
        vulnerability_category=category.value,
        state=TacticState.ACTIVE,
        content_sha256=candidate.canonical_content_hash(),
        compatibility=compatibility,
        compatibility_fingerprint=compatibility.value(),
        environment_fingerprint=env_fp.value(),
        wstg_requested_id=snapshot.requested_id,
        wstg_version=snapshot.wstg_version,
        authoring_model=model_name,
        prompt_version=PROMPT_VERSION,
        authoring_attempts=attempts,
        created_at=now,
    )
    return registry.publish(
        candidate,
        metadata,
        snapshot=snapshot,
        snapshot_metadata=snapshot_metadata(snapshot, retrieved_at=now),
    )
