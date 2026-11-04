"""Module 2 Injection-Focused CVE Matching and Candidate Extraction.

Implements deterministic technology normalization, product/CPE resolution,
tri-state version applicability evaluation, strict OWASP Top 10:2025 A05: Injection
scope policy enforcement, provenance independence verification, and CVECandidate
synthesis compatible with validate_module2_handoff().
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    CVECandidate,
    CveCandidateId,
    CveId,
    CweId,
    EvidenceId,
    Module2AnalysisRequest,
    ObservationId,
    TechnologyTargetRef,
)
from websecuritycheck.domain.enums import (
    ObservationType,
    TechnologyCategory,
)
from websecuritycheck.domain.models import (
    EvidenceArtifactRecord,
    ObservationRecord,
    TechnologyRecord,
)

# ---------------------------------------------------------------------------
# 1. Enums and Status Models
# ---------------------------------------------------------------------------


class InjectionSubtype(StrEnum):
    """Subtypes within OWASP Top 10:2025 A05: Injection."""

    SQL_INJECTION = "SQL_INJECTION"
    OS_COMMAND_INJECTION = "OS_COMMAND_INJECTION"
    NOSQL_INJECTION = "NOSQL_INJECTION"
    LDAP_INJECTION = "LDAP_INJECTION"
    XPATH_INJECTION = "XPATH_INJECTION"
    ORM_QUERY_INJECTION = "ORM_QUERY_INJECTION"
    SSTI = "SSTI"
    CODE_INJECTION = "CODE_INJECTION"


class InjectionScopeStatus(StrEnum):
    """Decision status returned by InjectionScopePolicy."""

    ALLOWED = "ALLOWED"
    EXCLUDED = "EXCLUDED"
    UNKNOWN = "UNKNOWN"


class ProductMatchKind(StrEnum):
    """Matching fidelity between observed technology and known product entry."""

    EXACT = "EXACT"
    ALIAS = "ALIAS"
    AMBIGUOUS = "AMBIGUOUS"
    UNMAPPED = "UNMAPPED"


class VersionScheme(StrEnum):
    """Supported version parsing and comparison scheme."""

    NUMERIC_DOT = "NUMERIC_DOT"


class VersionApplicability(StrEnum):
    """Tri-state version evaluation outcome."""

    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT_AFFECTED"
    UNKNOWN = "UNKNOWN"


class CVEProviderError(RuntimeError):
    """Raised when a vulnerability knowledge provider fails or contains invalid data."""


# ---------------------------------------------------------------------------
# 2. Advisory and Product Schemas
# ---------------------------------------------------------------------------


class CVEAdvisoryRecord(BaseModel):
    """Vulnerability advisory record returned by a knowledge provider.

    Deliberately omits any provider-asserted override flags to preserve the
    InjectionScopePolicy trust boundary.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: CveId
    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)
    cpe_prefix: str = Field(min_length=1)
    version_scheme: VersionScheme = VersionScheme.NUMERIC_DOT
    affected_range: str = Field(min_length=1)
    primary_cwe_id: CweId | None = None
    cwe_ids: tuple[CweId, ...] = Field(default_factory=tuple)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    injection_subtype: InjectionSubtype | None = None
    injection_rationale: str | None = None
    environmental_preconditions: tuple[str, ...] = Field(default_factory=tuple)
    summary: str = Field(min_length=5)
    advisory_source: str = Field(min_length=3)
    published_date: str = Field(min_length=4)
    advisory_url: str | None = None
    provider_name: str = Field(default="local_seed_catalog", min_length=1)
    catalog_version: str = Field(default="2026.03", min_length=1)


class CPEProductEntry(BaseModel):
    """Product resolution and mapping definition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    vendor: str = Field(min_length=1)
    product: str = Field(min_length=1)
    cpe_prefix: str = Field(min_length=1)
    version_scheme: VersionScheme = VersionScheme.NUMERIC_DOT
    exact_names: tuple[str, ...] = Field(default_factory=tuple)
    aliases: tuple[str, ...] = Field(default_factory=tuple)
    allowed_categories: tuple[TechnologyCategory, ...] = Field(default_factory=tuple)


class TrustedInjectionClassification(BaseModel):
    """Policy-owned curated classification for multi-CWE or context-dependent CVEs."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: CveId
    expected_cwe_ids: frozenset[CweId]
    canonical_subtype: InjectionSubtype
    policy_rationale: str = Field(min_length=10)


class InjectionScopeEvaluation(BaseModel):
    """Result of evaluating an advisory against InjectionScopePolicy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: InjectionScopeStatus
    subtype: InjectionSubtype | None = None
    matched_cwe_id: CweId | None = None
    used_trusted_allowlist: bool = False
    reason: str = Field(min_length=3)


# ---------------------------------------------------------------------------
# 3. CWE Tier Sets and InjectionScopePolicy
# ---------------------------------------------------------------------------

DIRECT_INJECTION_CWES: Mapping[str, InjectionSubtype] = {
    "CWE-89": InjectionSubtype.SQL_INJECTION,
    "CWE-564": InjectionSubtype.ORM_QUERY_INJECTION,
    "CWE-77": InjectionSubtype.OS_COMMAND_INJECTION,
    "CWE-78": InjectionSubtype.OS_COMMAND_INJECTION,
    "CWE-943": InjectionSubtype.NOSQL_INJECTION,
    "CWE-90": InjectionSubtype.LDAP_INJECTION,
    "CWE-91": InjectionSubtype.XPATH_INJECTION,
    "CWE-643": InjectionSubtype.XPATH_INJECTION,
    "CWE-1336": InjectionSubtype.SSTI,
    "CWE-94": InjectionSubtype.CODE_INJECTION,
    "CWE-95": InjectionSubtype.CODE_INJECTION,
    "CWE-917": InjectionSubtype.CODE_INJECTION,
}

CONTEXT_DEPENDENT_CWES: frozenset[str] = frozenset(
    {"CWE-74", "CWE-20", "CWE-116", "CWE-75", "CWE-96", "CWE-99"}
)

EXCLUDED_CWES: frozenset[str] = frozenset(
    {
        "CWE-22",
        "CWE-23",
        "CWE-79",
        "CWE-80",
        "CWE-918",
        "CWE-287",
        "CWE-862",
        "CWE-863",
        "CWE-400",
        "CWE-1333",
        "CWE-119",
        "CWE-125",
        "CWE-193",
        "CWE-787",
        "CWE-502",
        "CWE-200",
        "CWE-352",
    }
)

DEFAULT_TRUSTED_INJECTION_CLASSIFICATIONS: dict[str, TrustedInjectionClassification] = {
    "CVE-2022-22980": TrustedInjectionClassification(
        cve_id="CVE-2022-22980",  # type: ignore[arg-type]
        expected_cwe_ids=frozenset({"CWE-917", "CWE-943"}),  # type: ignore[arg-type]
        canonical_subtype=InjectionSubtype.NOSQL_INJECTION,
        policy_rationale=(
            "SpEL expression injection directly embedded in MongoDB repository "
            "@Query/@Aggregation constitutes NoSQL query injection."
        ),
    ),
    "CVE-2019-10906": TrustedInjectionClassification(
        cve_id="CVE-2019-10906",  # type: ignore[arg-type]
        expected_cwe_ids=frozenset({"CWE-94", "CWE-1336"}),  # type: ignore[arg-type]
        canonical_subtype=InjectionSubtype.SSTI,
        policy_rationale=(
            "Jinja2 SandboxedEnvironment bypass via str.format_map enables "
            "Server-Side Template Injection leading to arbitrary code execution."
        ),
    ),
}


class InjectionScopePolicy:
    """Enforces OWASP Top 10:2025 A05: Injection scope before CVECandidate creation."""

    def __init__(
        self,
        trusted_classifications: Mapping[CveId, TrustedInjectionClassification] | None = None,
    ) -> None:
        self._trusted: dict[str, TrustedInjectionClassification] = (
            dict(trusted_classifications)
            if trusted_classifications is not None
            else dict(DEFAULT_TRUSTED_INJECTION_CLASSIFICATIONS)
        )

    def trusted_classification(
        self, cve_id: CveId | str
    ) -> TrustedInjectionClassification | None:
        """Return the policy-owned trusted classification for a CVE if registered."""
        return self._trusted.get(str(cve_id))

    def evaluate(self, advisory: CVEAdvisoryRecord) -> InjectionScopeEvaluation:
        """Evaluate whether an advisory belongs to A05: Injection scope."""
        cve_id = advisory.cve_id
        all_cwes: set[str] = set(advisory.cwe_ids)
        if advisory.primary_cwe_id:
            all_cwes.add(advisory.primary_cwe_id)

        # 1. Trusted classification check (Policy-owned allowlist)
        if cve_id in self._trusted:
            trusted_entry = self._trusted[cve_id]
            if trusted_entry.expected_cwe_ids.issubset(all_cwes):
                return InjectionScopeEvaluation(
                    status=InjectionScopeStatus.ALLOWED,
                    subtype=trusted_entry.canonical_subtype,
                    matched_cwe_id=advisory.primary_cwe_id,
                    used_trusted_allowlist=True,
                    reason=trusted_entry.policy_rationale,
                )

        # 2. Hard block on excluded CWEs
        if not all_cwes:
            return InjectionScopeEvaluation(
                status=InjectionScopeStatus.UNKNOWN,
                reason="Advisory specifies no CWE identifier",
            )

        if advisory.primary_cwe_id in EXCLUDED_CWES or all_cwes.issubset(EXCLUDED_CWES):
            target_cwe = advisory.primary_cwe_id or sorted(all_cwes)
            return InjectionScopeEvaluation(
                status=InjectionScopeStatus.EXCLUDED,
                reason=f"CWE {target_cwe} is outside Injection scope",
            )

        if any(cwe in EXCLUDED_CWES for cwe in all_cwes):
            return InjectionScopeEvaluation(
                status=InjectionScopeStatus.UNKNOWN,
                reason=(
                    "Advisory contains an excluded CWE alongside other CWEs without "
                    "trusted classification"
                ),
            )

        # 3. Direct Injection CWE evaluation
        primary = advisory.primary_cwe_id
        if primary and primary in DIRECT_INJECTION_CWES:
            canonical_subtype = DIRECT_INJECTION_CWES[primary]

            # Verify no context-dependent or competing direct CWEs
            competing = {c for c in all_cwes if c != primary}
            for comp in competing:
                if comp in CONTEXT_DEPENDENT_CWES:
                    return InjectionScopeEvaluation(
                        status=InjectionScopeStatus.UNKNOWN,
                        reason=f"Primary CWE {primary} combined with context-dependent CWE {comp}",
                    )
                if (
                    comp in DIRECT_INJECTION_CWES
                    and DIRECT_INJECTION_CWES[comp] != canonical_subtype
                ):
                    return InjectionScopeEvaluation(
                        status=InjectionScopeStatus.UNKNOWN,
                        reason=f"Conflicting direct injection CWEs: {primary} vs {comp}",
                    )

            # Check advisory declared subtype consistency
            if (
                advisory.injection_subtype is not None
                and advisory.injection_subtype != canonical_subtype
            ):
                return InjectionScopeEvaluation(
                    status=InjectionScopeStatus.UNKNOWN,
                    reason=(
                        f"Advisory declared injection_subtype {advisory.injection_subtype} "
                        f"conflicts with CWE {primary} mapping {canonical_subtype}"
                    ),
                )

            return InjectionScopeEvaluation(
                status=InjectionScopeStatus.ALLOWED,
                subtype=canonical_subtype,
                matched_cwe_id=primary,
                used_trusted_allowlist=False,
                reason=f"Matched direct injection CWE {primary} ({canonical_subtype.value})",
            )

        # 4. Context-dependent CWE without trusted classification
        if primary in CONTEXT_DEPENDENT_CWES or any(c in CONTEXT_DEPENDENT_CWES for c in all_cwes):
            return InjectionScopeEvaluation(
                status=InjectionScopeStatus.UNKNOWN,
                reason=(
                    f"CWE {primary or sorted(all_cwes)} is context-dependent and requires "
                    "policy-owned trusted classification"
                ),
            )

        return InjectionScopeEvaluation(
            status=InjectionScopeStatus.UNKNOWN,
            reason=f"Unrecognized CWE combination: {sorted(all_cwes)}",
        )


# ---------------------------------------------------------------------------
# 4. Knowledge Provider Protocols & LocalSeedCVEProvider
# ---------------------------------------------------------------------------


class VulnerabilityKnowledgeProvider(Protocol):
    """Synchronous interface for querying vulnerability intelligence."""

    @property
    def is_complete_source(self) -> bool: ...

    def resolve_product(
        self, normalized_name: str, category: TechnologyCategory
    ) -> tuple[ProductMatchKind, CPEProductEntry | None]: ...

    def query_by_product(self, vendor: str, product: str) -> Sequence[CVEAdvisoryRecord]: ...


class AsyncVulnerabilityKnowledgePort(Protocol):
    """Asynchronous port for querying vulnerability intelligence."""

    @property
    def is_complete_source(self) -> bool: ...

    async def aresolve_product(
        self, normalized_name: str, category: TechnologyCategory
    ) -> tuple[ProductMatchKind, CPEProductEntry | None]: ...

    async def aquery_by_product(self, vendor: str, product: str) -> Sequence[CVEAdvisoryRecord]: ...


class LocalSeedCVEProvider:
    """Offline MVP seed catalog provider containing verified A05:2025 Injection CVEs only."""

    is_complete_source: bool = False

    def __init__(self, catalog_path: Path | None = None) -> None:
        if catalog_path is None:
            catalog_path = Path(__file__).parent / "data" / "cve_seed_catalog.json"
        self._path = catalog_path
        self._products: list[CPEProductEntry] = []
        self._advisories_by_product: dict[tuple[str, str], list[CVEAdvisoryRecord]] = {}
        self._load_catalog()

    def _load_catalog(self) -> None:
        if not self._path.exists() or not self._path.is_file():
            raise CVEProviderError(f"Seed catalog file does not exist: {self._path}")

        try:
            with open(self._path, encoding="utf-8") as f:
                raw_data = json.load(f)
        except Exception as exc:
            msg = f"Failed to read seed catalog JSON from {self._path}: {exc}"
            raise CVEProviderError(msg) from exc

        if not isinstance(raw_data, dict):
            raise CVEProviderError("Seed catalog JSON root must be an object")

        try:
            for p_dict in raw_data.get("products", []):
                entry = CPEProductEntry(
                    vendor=p_dict["vendor"],
                    product=p_dict["product"],
                    cpe_prefix=p_dict["cpe_prefix"],
                    version_scheme=p_dict.get("version_scheme", VersionScheme.NUMERIC_DOT),
                    exact_names=tuple(p_dict.get("exact_names", ())),
                    aliases=tuple(p_dict.get("aliases", ())),
                    allowed_categories=tuple(
                        TechnologyCategory(c) for c in p_dict.get("allowed_categories", ())
                    ),
                )
                self._products.append(entry)

            for a_dict in raw_data.get("advisories", []):
                adv = CVEAdvisoryRecord(
                    cve_id=a_dict["cve_id"],
                    vendor=a_dict["vendor"],
                    product=a_dict["product"],
                    cpe_prefix=a_dict["cpe_prefix"],
                    version_scheme=a_dict.get("version_scheme", VersionScheme.NUMERIC_DOT),
                    affected_range=a_dict["affected_range"],
                    primary_cwe_id=a_dict.get("primary_cwe_id"),
                    cwe_ids=tuple(a_dict.get("cwe_ids", ())),
                    cvss_score=a_dict.get("cvss_score"),
                    injection_subtype=a_dict.get("injection_subtype"),
                    injection_rationale=a_dict.get("injection_rationale"),
                    environmental_preconditions=tuple(
                        a_dict.get("environmental_preconditions", ())
                    ),
                    summary=a_dict["summary"],
                    advisory_source=a_dict["advisory_source"],
                    published_date=a_dict["published_date"],
                    advisory_url=a_dict.get("advisory_url"),
                    provider_name=a_dict.get("provider_name", "local_seed_catalog"),
                    catalog_version=a_dict.get("catalog_version", "2026.03"),
                )
                key = (adv.vendor.casefold(), adv.product.casefold())
                self._advisories_by_product.setdefault(key, []).append(adv)
        except Exception as exc:
            raise CVEProviderError(f"Malformed record in seed catalog: {exc}") from exc

    def resolve_product(
        self, normalized_name: str, category: TechnologyCategory
    ) -> tuple[ProductMatchKind, CPEProductEntry | None]:
        name_clean = normalized_name.casefold().strip()
        exact_matches: list[CPEProductEntry] = []
        alias_matches: list[CPEProductEntry] = []

        for p in self._products:
            # Check category compatibility
            cat_ok = category in p.allowed_categories or category == TechnologyCategory.OTHER
            if not cat_ok:
                continue

            # Exact match check
            is_exact = (
                name_clean == f"{p.vendor}:{p.product}".casefold()
                or name_clean == p.product.casefold()
                or any(name_clean == en.casefold() for en in p.exact_names)
            )
            if is_exact:
                exact_matches.append(p)
                continue

            # Alias match check
            if any(name_clean == al.casefold() for al in p.aliases):
                alias_matches.append(p)

        if len(exact_matches) == 1:
            return ProductMatchKind.EXACT, exact_matches[0]
        if len(exact_matches) > 1:
            return ProductMatchKind.AMBIGUOUS, None

        if len(alias_matches) == 1:
            return ProductMatchKind.ALIAS, alias_matches[0]
        if len(alias_matches) > 1:
            return ProductMatchKind.AMBIGUOUS, None

        return ProductMatchKind.UNMAPPED, None

    def query_by_product(self, vendor: str, product: str) -> Sequence[CVEAdvisoryRecord]:
        key = (vendor.casefold().strip(), product.casefold().strip())
        return tuple(self._advisories_by_product.get(key, ()))

    async def aresolve_product(
        self, normalized_name: str, category: TechnologyCategory
    ) -> tuple[ProductMatchKind, CPEProductEntry | None]:
        return self.resolve_product(normalized_name, category)

    async def aquery_by_product(self, vendor: str, product: str) -> Sequence[CVEAdvisoryRecord]:
        return self.query_by_product(vendor, product)


# ---------------------------------------------------------------------------
# 5. Technology & Version Normalization
# ---------------------------------------------------------------------------

NUMERIC_DOT_RE = re.compile(r"^[vV]?(\d+)\.(\d+)(?:\.(\d+))?$")


def normalize_technology_fingerprint(name: str, version: str | None) -> tuple[str, str | None]:
    """Deterministically clean up technology name and version.

    Conservative: never strips OS or distro suffixes from version to avoid false positives.
    """
    cleaned_name = name.casefold().strip()
    cleaned_version = version.strip() if version else None

    # If name embeds the version string (e.g. "Django/3.2.12" with version="3.2.12"),
    # safely decouple product name
    if cleaned_version and f"/{cleaned_version}".casefold() in cleaned_name:
        cleaned_name = cleaned_name.split(f"/{cleaned_version}".casefold())[0].strip()
    elif "/" in cleaned_name:
        parts = cleaned_name.split("/", 1)
        # If right side is a pure numeric version and version was None, extract
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


# ---------------------------------------------------------------------------
# 6. Tri-State Version Applicability Engine ([major.minor.0, major.(minor+1).0))
# ---------------------------------------------------------------------------

ComparisonOp = Literal["==", ">=", ">", "<=", "<"]


def _parse_condition(cond_str: str) -> tuple[ComparisonOp, tuple[int, int, int]]:
    cond = cond_str.strip()
    for op in (">=", "<=", "==", ">", "<"):
        if cond.startswith(op):
            target_str = cond[len(op) :].strip()
            parsed = _parse_numeric_dot_tuple(target_str)
            if parsed is None:
                raise CVEProviderError(f"Invalid version in affected_range condition: {cond_str}")
            # Ensure target has patch level; if 2-part, defaults to 0
            maj, min_v, patch = parsed
            return op, (maj, min_v, patch if patch is not None else 0)
    raise CVEProviderError(f"Invalid condition operator in affected_range: {cond_str}")


def _condition_to_patch_interval(
    op: ComparisonOp, target: tuple[int, int, int], branch_maj: int, branch_min: int
) -> tuple[int, int | None] | None:
    """Map condition to [p_low, p_high] interval on p in [0, +inf) for (branch_maj, branch_min).

    Returns None if the interval is empty (no p satisfies).
    p_high = None denotes +infinity.
    """
    target_maj, target_min, target_patch = target

    # Case 1: Target is on a different major.minor branch
    if (branch_maj, branch_min) != (target_maj, target_min):
        # Result of (branch_maj, branch_min, p) op target is identical for all p >= 0
        cmp_sample = (branch_maj, branch_min, 0)
        is_satisfied: bool
        if op == "==":
            is_satisfied = cmp_sample == target
        elif op == ">=":
            is_satisfied = cmp_sample >= target
        elif op == ">":
            is_satisfied = cmp_sample > target
        elif op == "<=":
            is_satisfied = cmp_sample <= target
        elif op == "<":
            is_satisfied = cmp_sample < target
        else:
            is_satisfied = False

        return (0, None) if is_satisfied else None

    # Case 2: Target is on the exact same branch (branch_maj, branch_min)
    # The condition reduces directly to p op target_patch on non-negative integers
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
    if i1 is None or i2 in (None,):
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
            # Previous interval already extends to +infinity
            continue

        if curr_low <= prev_high + 1:
            # Overlapping or adjacent on integers
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

    # Parse affected_range clauses
    or_groups: list[list[tuple[ComparisonOp, tuple[int, int, int]]]] = []
    try:
        raw_or_groups = [g.strip() for g in affected_range.split(";") if g.strip()]
        if not raw_or_groups:
            raise CVEProviderError("affected_range is empty")
        for g_str in raw_or_groups:
            and_conds = [c.strip() for c in g_str.split(",") if c.strip()]
            if not and_conds:
                raise CVEProviderError(f"Empty clause in affected_range: {g_str}")
            group_conditions = [_parse_condition(cond) for cond in and_conds]
            or_groups.append(group_conditions)
    except CVEProviderError:
        raise
    except Exception as exc:
        raise CVEProviderError(f"Failed to parse affected_range {affected_range!r}: {exc}") from exc

    # Case A: Full 3-part version (M.m.p) -> point evaluation
    if patch is not None:
        point = (maj, min_v, patch)
        for group in or_groups:
            group_matched = True
            for op, target in group:
                if op == "==" and point != target:
                    group_matched = False
                    break
                if op == ">=" and not (point >= target):
                    group_matched = False
                    break
                if op == ">" and not (point > target):
                    group_matched = False
                    break
                if op == "<=" and not (point <= target):
                    group_matched = False
                    break
                if op == "<" and not (point < target):
                    group_matched = False
                    break
            if group_matched:
                return (
                    VersionApplicability.AFFECTED,
                    f"Version {raw_version} satisfies range clause",
                )

        return (
            VersionApplicability.NOT_AFFECTED,
            f"Version {raw_version} outside affected range",
        )

    # Case B: 2-part version (M.m) -> interval evaluation on [M.m.0, M.(m+1).0)
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

    # If the merged union spans [0, +infinity), then every patch in the branch is affected
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


# ---------------------------------------------------------------------------
# 7. Evidence Grounding & Provenance Independence
# ---------------------------------------------------------------------------


def _calculate_provenance_independence(
    tech: TechnologyRecord,
    corroborating_obs: Sequence[ObservationRecord],
    evidence_records: Sequence[EvidenceArtifactRecord],
) -> int:
    """Calculate the count of truly independent evidence sources supporting a technology.

    Distinguishes observations/artifacts from the same tool/run from distinct sources.
    """
    seen_sources: set[tuple[str, str]] = set()

    for obs in corroborating_obs:
        tool_or_source = (obs.source_tool_id or obs.source_type.value).casefold().strip()
        exec_ref = (obs.execution_ref or "").casefold().strip()
        seen_sources.add((tool_or_source, exec_ref))

    # Inspect direct tech evidence records
    obs_evd_refs = {ref for obs in corroborating_obs for ref in obs.evidence_refs}
    evd_map = {e.evidence_id: e for e in evidence_records}

    for evd_id in tech.evidence_refs:
        if evd_id not in obs_evd_refs and evd_id in evd_map:
            evd = evd_map[evd_id]
            tool_or_source = (evd.source_tool_id or evd.artifact_type.value).casefold().strip()
            exec_ref = (evd.execution_ref or "").casefold().strip()
            seen_sources.add((tool_or_source, exec_ref))

    return max(1, len(seen_sources))


# ---------------------------------------------------------------------------
# 8. Diagnostics and Result Models
# ---------------------------------------------------------------------------


class CVEEvaluationDiagnostic(BaseModel):
    """Structured diagnostic record explaining an evaluation outcome."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    technology_name: str
    technology_version: str | None = None
    cve_id: CveId | None = None
    stage: Literal[
        "grounding",
        "product_matching",
        "version_parsing",
        "injection_scope",
        "version_applicability",
        "catalog_coverage",
    ]
    outcome: Literal["SKIPPED", "EXCLUDED", "UNKNOWN"]
    reason: str


class CVECorrelationMetadata(BaseModel):
    """Detailed advisory and environment metadata companion to CVECandidate."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_candidate_id: CveCandidateId
    cve_id: CveId
    matched_cpe: str
    product_match_kind: ProductMatchKind
    injection_subtype: InjectionSubtype
    environmental_preconditions: tuple[str, ...] = Field(default_factory=tuple)
    independent_source_count: int = Field(ge=1)
    provider_name: str
    catalog_version: str
    advisory_source: str
    published_date: str
    advisory_url: str | None = None


class CVEExtractionResult(BaseModel):
    """Complete Module 2 deterministic CVE candidate extraction output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_candidates: tuple[CVECandidate, ...] = Field(default_factory=tuple)
    correlation_metadata: tuple[CVECorrelationMetadata, ...] = Field(default_factory=tuple)
    diagnostics: tuple[CVEEvaluationDiagnostic, ...] = Field(default_factory=tuple)
    limitations: tuple[str, ...] = Field(default_factory=tuple)


# ---------------------------------------------------------------------------
# 9. Main Extraction Pipeline
# ---------------------------------------------------------------------------


def extract_cve_candidates(
    request: Module2AnalysisRequest,
    *,
    provider: VulnerabilityKnowledgeProvider | None = None,
    scope_policy: InjectionScopePolicy | None = None,
    caller_asserted_evidence_ids: frozenset[EvidenceId] | set[EvidenceId] | None = None,
    caller_asserted_observation_ids: frozenset[ObservationId] | set[ObservationId] | None = None,
) -> CVEExtractionResult:
    """Deterministically match versioned technologies against Injection CVEs."""
    if provider is None:
        provider = LocalSeedCVEProvider()
    if scope_policy is None:
        scope_policy = InjectionScopePolicy()

    verified_evd_ids = {e.evidence_id for e in request.evidence_records} | set(
        caller_asserted_evidence_ids or ()
    )
    verified_obs_ids = {o.observation_id for o in request.observations} | set(
        caller_asserted_observation_ids or ()
    )

    diagnostics: list[CVEEvaluationDiagnostic] = []
    limitations: list[str] = []

    if not provider.is_complete_source:
        limitations.append(
            "LocalSeedCVEProvider is an offline MVP seed catalog with limited product and "
            "CVE coverage; zero matched CVE candidates never implies the target technology "
            "is free of known vulnerabilities."
        )

    # Check for unpromoted NETWORK_SERVICE observations (CR-M1-02)
    tech_keys = {
        (t.category.value.upper(), t.name.casefold().strip(), (t.version or "").casefold().strip())
        for t in request.target_model.technologies
    }
    for obs in request.observations:
        if obs.observation_type == ObservationType.NETWORK_SERVICE:
            payload = obs.payload
            product = getattr(payload, "product", None)
            version = getattr(payload, "version", None)
            if product and version:
                norm_p = product.casefold().strip()
                norm_v = version.casefold().strip()
                matched_in_model = any(k[1] == norm_p and k[2] == norm_v for k in tech_keys)
                if not matched_in_model:
                    limitations.append(
                        f"Observation {obs.observation_id} detected network service "
                        f"{product} {version} which is not promoted into "
                        "TargetModel.technologies (CR-M1-02); skipping CVE extraction "
                        "to prevent handoff reference validation failure."
                    )

    intermediate_candidates: list[
        tuple[
            TechnologyRecord,
            CVEAdvisoryRecord,
            CPEProductEntry,
            ProductMatchKind,
            InjectionSubtype,
            list[EvidenceId],
            list[ObservationId],
            int,
            bool,
        ]
    ] = []

    for tech in request.target_model.technologies:
        # Step 1: Version requirement check
        if not tech.version or not tech.version.strip():
            diagnostics.append(
                CVEEvaluationDiagnostic(
                    technology_name=tech.name,
                    technology_version=None,
                    stage="version_parsing",
                    outcome="SKIPPED",
                    reason="TechnologyRecord has no version specified",
                )
            )
            continue

        # Step 2: Strict evidence grounding check against canonical request
        tech_verified_evd = [ref for ref in tech.evidence_refs if ref in verified_evd_ids]
        tech_verified_obs = [ref for ref in tech.observation_refs if ref in verified_obs_ids]
        tech_verified_refs = set(tech_verified_evd) | set(tech_verified_obs)

        if not tech_verified_refs:
            diagnostics.append(
                CVEEvaluationDiagnostic(
                    technology_name=tech.name,
                    technology_version=tech.version,
                    stage="grounding",
                    outcome="SKIPPED",
                    reason="TechnologyRecord has no verified evidence or observation references",
                )
            )
            continue

        # Step 3: Normalization & Product Resolution
        norm_name, norm_version = normalize_technology_fingerprint(tech.name, tech.version)
        match_kind, product_entry = provider.resolve_product(norm_name, tech.category)

        if (
            match_kind in (ProductMatchKind.UNMAPPED, ProductMatchKind.AMBIGUOUS)
            or product_entry is None
        ):
            diagnostics.append(
                CVEEvaluationDiagnostic(
                    technology_name=tech.name,
                    technology_version=tech.version,
                    stage="product_matching",
                    outcome="SKIPPED",
                    reason=f"Product resolution result was {match_kind.value}",
                )
            )
            continue

        # Step 4: Query knowledge provider
        advisories = provider.query_by_product(product_entry.vendor, product_entry.product)
        if not advisories:
            diagnostics.append(
                CVEEvaluationDiagnostic(
                    technology_name=tech.name,
                    technology_version=tech.version,
                    stage="catalog_coverage",
                    outcome="SKIPPED",
                    reason=(
                        f"No advisories found for {product_entry.vendor}:{product_entry.product}"
                    ),
                )
            )
            continue

        # Gather corroborating observations
        corroborating_obs: list[ObservationRecord] = []
        for obs in request.observations:
            if obs.observation_id not in verified_obs_ids:
                continue
            if obs.observation_type == ObservationType.TECHNOLOGY:
                p_name = getattr(obs.payload, "name", "")
                p_ver = getattr(obs.payload, "version", "")
                if (
                    p_name.casefold().strip() == tech.name.casefold().strip()
                    and (p_ver or "").casefold().strip() == tech.version.casefold().strip()
                ):
                    corroborating_obs.append(obs)
            elif obs.observation_type == ObservationType.NETWORK_SERVICE:
                p_prod = getattr(obs.payload, "product", "")
                p_ver = getattr(obs.payload, "version", "")
                if p_prod and p_ver:
                    clean_p, clean_v = normalize_technology_fingerprint(p_prod, p_ver)
                    if clean_p == norm_name and clean_v == norm_version:
                        corroborating_obs.append(obs)

        corrob_evd_refs: list[EvidenceId] = list(tech_verified_evd)
        corrob_obs_refs: list[ObservationId] = list(tech_verified_obs)
        for obs in corroborating_obs:
            if obs.observation_id not in corrob_obs_refs:
                corrob_obs_refs.append(obs.observation_id)
            for evd_ref in obs.evidence_refs:
                if evd_ref in verified_evd_ids and evd_ref not in corrob_evd_refs:
                    corrob_evd_refs.append(evd_ref)

        independent_source_count = _calculate_provenance_independence(
            tech, corroborating_obs, request.evidence_records
        )

        # Step 5: Evaluate each advisory
        for adv in advisories:
            # 5a: Injection Scope Policy
            scope_eval = scope_policy.evaluate(adv)
            if scope_eval.status == InjectionScopeStatus.EXCLUDED:
                diagnostics.append(
                    CVEEvaluationDiagnostic(
                        technology_name=tech.name,
                        technology_version=tech.version,
                        cve_id=adv.cve_id,
                        stage="injection_scope",
                        outcome="EXCLUDED",
                        reason=scope_eval.reason,
                    )
                )
                continue
            if scope_eval.status == InjectionScopeStatus.UNKNOWN:
                diagnostics.append(
                    CVEEvaluationDiagnostic(
                        technology_name=tech.name,
                        technology_version=tech.version,
                        cve_id=adv.cve_id,
                        stage="injection_scope",
                        outcome="UNKNOWN",
                        reason=scope_eval.reason,
                    )
                )
                continue

            # 5b: Version Applicability
            app_status, app_reason = evaluate_version_applicability(
                norm_version, adv.affected_range, scheme=product_entry.version_scheme
            )
            if app_status == VersionApplicability.NOT_AFFECTED:
                continue
            if app_status == VersionApplicability.UNKNOWN:
                diagnostics.append(
                    CVEEvaluationDiagnostic(
                        technology_name=tech.name,
                        technology_version=tech.version,
                        cve_id=adv.cve_id,
                        stage="version_applicability",
                        outcome="UNKNOWN",
                        reason=app_reason,
                    )
                )
                continue

            assert scope_eval.subtype is not None
            intermediate_candidates.append(
                (
                    tech,
                    adv,
                    product_entry,
                    match_kind,
                    scope_eval.subtype,
                    corrob_evd_refs,
                    corrob_obs_refs,
                    independent_source_count,
                    scope_eval.used_trusted_allowlist,
                )
            )

    # Step 6: Deduplication & Candidate Construction
    # Group by (tech.canonical_key, cve_id)
    grouped: dict[
        tuple[tuple[str, str, str], str],
        list[
            tuple[
                TechnologyRecord,
                CVEAdvisoryRecord,
                CPEProductEntry,
                ProductMatchKind,
                InjectionSubtype,
                list[EvidenceId],
                list[ObservationId],
                int,
                bool,
            ]
        ],
    ] = {}

    for item in intermediate_candidates:
        tech, adv = item[0], item[1]
        t_ref = TechnologyTargetRef.from_record(tech)
        key = (t_ref.canonical_key, adv.cve_id)
        grouped.setdefault(key, []).append(item)

    cve_candidates: list[CVECandidate] = []
    correlation_metadata: list[CVECorrelationMetadata] = []

    # Sort grouped keys for deterministic ID assignment
    sorted_group_keys = sorted(grouped.keys(), key=lambda k: (k[0], k[1]))

    for idx, g_key in enumerate(sorted_group_keys, start=1):
        items = grouped[g_key]
        primary_item = items[0]
        (
            tech,
            adv,
            product_entry,
            match_kind,
            injection_subtype,
            _,
            _,
            _,
            used_trusted_allowlist,
        ) = primary_item

        # Merge references
        merged_evd_refs: set[EvidenceId] = set()
        merged_obs_refs: set[ObservationId] = set()
        max_sources = 1
        for it in items:
            merged_evd_refs.update(it[5])
            merged_obs_refs.update(it[6])
            if it[7] > max_sources:
                max_sources = it[7]

        # Invariant check: must intersect tech's original ground references
        tech_orig_refs = set(tech.evidence_refs) | set(tech.observation_refs)
        assert (merged_evd_refs | merged_obs_refs) & tech_orig_refs

        # Determine confidence
        parsed_v = _parse_numeric_dot_tuple(tech.version or "")
        is_full_patch_version = parsed_v is not None and parsed_v[2] is not None

        if (
            match_kind == ProductMatchKind.EXACT
            and is_full_patch_version
            and not used_trusted_allowlist
            and max_sources >= 2
            and tech.category != TechnologyCategory.OTHER
        ):
            confidence = ConfidenceLevel.HIGH
        elif (
            (
                match_kind == ProductMatchKind.EXACT
                and is_full_patch_version
                and not used_trusted_allowlist
            )
            or (match_kind == ProductMatchKind.ALIAS and is_full_patch_version and max_sources >= 2)
        ) and tech.category != TechnologyCategory.OTHER:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW

        cand_id = f"CVC-{idx:03d}"
        target_ref = TechnologyTargetRef.from_record(tech)

        precond_note = (
            f" Preconditions: {'; '.join(adv.environmental_preconditions)}"
            if adv.environmental_preconditions
            else ""
        )
        rationale = (
            f"Matched {tech.name} {tech.version} against {adv.cve_id} ({injection_subtype.value}) "
            f"in range '{adv.affected_range}' via {adv.provider_name}.{precond_note}"
        )

        candidate = CVECandidate(
            cve_candidate_id=cand_id,  # type: ignore[arg-type]
            cve_id=adv.cve_id,
            target_technology=target_ref,
            affected_range=adv.affected_range,
            cwe_id=adv.primary_cwe_id,
            cvss_score=adv.cvss_score,
            confidence=confidence,
            match_rationale=rationale,
            evidence_refs=sorted(merged_evd_refs),
            observation_refs=sorted(merged_obs_refs),
            is_confirmed=False,
        )
        cve_candidates.append(candidate)

        meta = CVECorrelationMetadata(
            cve_candidate_id=cand_id,  # type: ignore[arg-type]
            cve_id=adv.cve_id,
            matched_cpe=adv.cpe_prefix,
            product_match_kind=match_kind,
            injection_subtype=injection_subtype,
            environmental_preconditions=adv.environmental_preconditions,
            independent_source_count=max_sources,
            provider_name=adv.provider_name,
            catalog_version=adv.catalog_version,
            advisory_source=adv.advisory_source,
            published_date=adv.published_date,
            advisory_url=adv.advisory_url,
        )
        correlation_metadata.append(meta)

    return CVEExtractionResult(
        cve_candidates=tuple(cve_candidates),
        correlation_metadata=tuple(correlation_metadata),
        diagnostics=tuple(diagnostics),
        limitations=tuple(limitations),
    )


async def aextract_cve_candidates(
    request: Module2AnalysisRequest,
    *,
    provider: AsyncVulnerabilityKnowledgePort | VulnerabilityKnowledgeProvider | None = None,
    scope_policy: InjectionScopePolicy | None = None,
    caller_asserted_evidence_ids: frozenset[EvidenceId] | set[EvidenceId] | None = None,
    caller_asserted_observation_ids: frozenset[ObservationId] | set[ObservationId] | None = None,
) -> CVEExtractionResult:
    """Asynchronous wrapper for CVE candidate extraction."""
    # LocalSeedCVEProvider supports both sync and async protocols seamlessly
    return extract_cve_candidates(
        request,
        provider=provider,  # type: ignore[arg-type]
        scope_policy=scope_policy,
        caller_asserted_evidence_ids=caller_asserted_evidence_ids,
        caller_asserted_observation_ids=caller_asserted_observation_ids,
    )
