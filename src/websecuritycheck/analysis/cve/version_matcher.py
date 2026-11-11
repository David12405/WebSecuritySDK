"""Technology version normalization, interval math, and provenance independence."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Literal

from websecuritycheck.domain.models import (
    EvidenceArtifactRecord,
    ObservationRecord,
    TechnologyRecord,
)

from .models import CVEProviderError, VersionApplicability, VersionScheme

NUMERIC_DOT_RE = re.compile(r"^[vV]?(\d+)\.(\d+)(?:\.(\d+))?$")
ComparisonOp = Literal["==", ">=", ">", "<=", "<"]


def normalize_technology_fingerprint(name: str, version: str | None) -> tuple[str, str | None]:
    """Deterministically clean up technology name and version.

    Conservative: never strips OS or distro suffixes from version to avoid false positives.
    """
    cleaned_name = name.casefold().strip()
    cleaned_version = version.strip() if version else None

    if cleaned_version and f"/{cleaned_version}".casefold() in cleaned_name:
        cleaned_name = cleaned_name.split(f"/{cleaned_version}".casefold())[0].strip()
    elif "/" in cleaned_name:
        parts = cleaned_name.split("/", 1)
        if not cleaned_version and NUMERIC_DOT_RE.match(parts[1].strip()):
            cleaned_name = parts[0].strip()
            cleaned_version = parts[1].strip()

    return cleaned_name, cleaned_version


def _parse_numeric_dot_tuple(version_str: str) -> tuple[int, int, int | None] | None:
    """Parse a clean numeric dot string into (M, m, p).

    Returns None if any distro suffix, backport, wildcard, or invalid structure is present.
    """
    m = NUMERIC_DOT_RE.match(version_str.strip())
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) is not None else None
    return major, minor, patch


def _parse_condition(cond_str: str) -> tuple[ComparisonOp, tuple[int, int, int]]:
    cond = cond_str.strip()
    for op in (">=", "<=", "==", ">", "<"):
        if cond.startswith(op):
            target_str = cond[len(op) :].strip()
            parsed = _parse_numeric_dot_tuple(target_str)
            if parsed is None:
                raise CVEProviderError(f"Invalid version in affected_range condition: {cond_str}")
            maj, min_v, patch = parsed
            return op, (maj, min_v, patch if patch is not None else 0)
    raise CVEProviderError(f"Invalid condition operator in affected_range: {cond_str}")


def _condition_to_patch_interval(
    op: ComparisonOp, target: tuple[int, int, int], branch_maj: int, branch_min: int
) -> tuple[int, int | None] | None:
    """Map condition to [p_low, p_high] interval on p in [0, +inf) for (branch_maj, branch_min)."""
    target_maj, target_min, target_patch = target

    if (branch_maj, branch_min) != (target_maj, target_min):
        cmp_sample = (branch_maj, branch_min, 0)
        is_satisfied = {
            "==": cmp_sample == target,
            ">=": cmp_sample >= target,
            ">": cmp_sample > target,
            "<=": cmp_sample <= target,
            "<": cmp_sample < target,
        }.get(op, False)
        return (0, None) if is_satisfied else None

    if op == "==":
        return target_patch, target_patch
    if op == ">=":
        return target_patch, None
    if op == ">":
        return target_patch + 1, None
    if op == "<=":
        return 0, target_patch
    if op == "<":
        return None if target_patch == 0 else (0, target_patch - 1)
    return None


def _intersect_intervals(
    i1: tuple[int, int | None] | None, i2: tuple[int, int | None] | None
) -> tuple[int, int | None] | None:
    if i1 is None or i2 is None:
        return None
    low = max(i1[0], i2[0])
    if i1[1] is None and i2[1] is None:
        high = None
    elif i1[1] is None:
        high = i2[1]
    elif i2[1] is None:
        high = i1[1]
    else:
        high = min(i1[1], i2[1])

    if high is not None and low > high:
        return None
    return low, high


def _merge_intervals(
    intervals: Sequence[tuple[int, int | None]],
) -> list[tuple[int, int | None]]:
    """Merge overlapping or adjacent integer intervals on [0, +inf)."""
    if not intervals:
        return []

    sorted_ints = sorted(intervals, key=lambda x: x[0])
    merged: list[tuple[int, int | None]] = []

    for curr in sorted_ints:
        if not merged:
            merged.append(curr)
            continue

        prev_low, prev_high = merged[-1]
        curr_low, curr_high = curr

        if prev_high is None:
            continue

        if curr_low <= prev_high + 1:
            new_high = None if curr_high is None else max(prev_high, curr_high)
            merged[-1] = (prev_low, new_high)
        else:
            merged.append(curr)

    return merged


def evaluate_version_applicability(
    raw_version: str | None,
    affected_range: str,
    *,
    scheme: VersionScheme = VersionScheme.NUMERIC_DOT,
) -> tuple[VersionApplicability, str]:
    """Evaluate tri-state applicability of raw_version against affected_range.

    For 3-part versions (M.m.p), performs exact point evaluation.
    For 2-part versions (M.m), solves exact solution interval on [M.m.0, M.(m+1).0).
    """
    if scheme != VersionScheme.NUMERIC_DOT:
        return VersionApplicability.UNKNOWN, f"Unsupported version scheme: {scheme}"

    if not raw_version or not raw_version.strip():
        return VersionApplicability.UNKNOWN, "Missing or blank technology version"

    parsed = _parse_numeric_dot_tuple(raw_version)
    if parsed is None:
        return (
            VersionApplicability.UNKNOWN,
            "Non-standard version format or distro/backport suffix present",
        )

    maj, min_v, patch = parsed

    or_groups: list[list[tuple[ComparisonOp, tuple[int, int, int]]]] = []
    try:
        raw_or_groups = [g.strip() for g in affected_range.split(";") if g.strip()]
        if not raw_or_groups:
            raise CVEProviderError("affected_range is empty")
        for g_str in raw_or_groups:
            and_conds = [c.strip() for c in g_str.split(",") if c.strip()]
            if not and_conds:
                raise CVEProviderError(f"Empty clause in affected_range: {g_str}")
            or_groups.append([_parse_condition(cond) for cond in and_conds])
    except CVEProviderError:
        raise
    except Exception as exc:
        raise CVEProviderError(f"Failed to parse affected_range {affected_range!r}: {exc}") from exc

    if patch is not None:
        point = (maj, min_v, patch)
        for group in or_groups:
            if all(
                (op == "==" and point == target)
                or (op == ">=" and point >= target)
                or (op == ">" and point > target)
                or (op == "<=" and point <= target)
                or (op == "<" and point < target)
                for op, target in group
            ):
                return (
                    VersionApplicability.AFFECTED,
                    f"Version {raw_version} satisfies range clause",
                )

        return (
            VersionApplicability.NOT_AFFECTED,
            f"Version {raw_version} outside affected range",
        )

    satisfied_group_intervals: list[tuple[int, int | None]] = []

    for group in or_groups:
        group_interval: tuple[int, int | None] | None = (0, None)
        for op, target in group:
            cond_interval = _condition_to_patch_interval(op, target, maj, min_v)
            group_interval = _intersect_intervals(group_interval, cond_interval)
            if group_interval is None:
                break
        if group_interval is not None:
            satisfied_group_intervals.append(group_interval)

    merged_union = _merge_intervals(satisfied_group_intervals)

    if not merged_union:
        return (
            VersionApplicability.NOT_AFFECTED,
            f"Entire minor branch {maj}.{min_v} outside affected range",
        )

    if len(merged_union) == 1 and merged_union[0] == (0, None):
        return (
            VersionApplicability.AFFECTED,
            f"Entire minor branch {maj}.{min_v} is affected",
        )

    return (
        VersionApplicability.UNKNOWN,
        f"Partial minor branch intersection on {maj}.{min_v}: "
        f"affected patch interval is {merged_union}",
    )


def _calculate_provenance_independence(
    tech: TechnologyRecord,
    corroborating_obs: Sequence[ObservationRecord],
    evidence_records: Sequence[EvidenceArtifactRecord],
) -> int:
    """Calculate the count of truly independent evidence sources supporting a technology."""
    seen_sources: set[tuple[str, str]] = set()

    for obs in corroborating_obs:
        tool_or_source = (obs.source_tool_id or obs.source_type.value).casefold().strip()
        exec_ref = (obs.execution_ref or "").casefold().strip()
        seen_sources.add((tool_or_source, exec_ref))

    obs_evd_refs = {ref for obs in corroborating_obs for ref in obs.evidence_refs}
    evd_map = {e.evidence_id: e for e in evidence_records}

    for evd_id in tech.evidence_refs:
        if evd_id not in obs_evd_refs and evd_id in evd_map:
            evd = evd_map[evd_id]
            tool_or_source = (evd.source_tool_id or evd.artifact_type.value).casefold().strip()
            exec_ref = (evd.execution_ref or "").casefold().strip()
            seen_sources.add((tool_or_source, exec_ref))

    return max(1, len(seen_sources))


__all__ = [
    "_calculate_provenance_independence",
    "_parse_numeric_dot_tuple",
    "evaluate_version_applicability",
    "normalize_technology_fingerprint",
]

