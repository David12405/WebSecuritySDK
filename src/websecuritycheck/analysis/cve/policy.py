"""OWASP Top 10:2025 A05: Injection scope policy and CWE classification tables."""

from __future__ import annotations

from collections.abc import Mapping

from websecuritycheck.domain.analysis_models import CveId

from .models import (
    CVEAdvisoryRecord,
    InjectionScopeEvaluation,
    InjectionScopeStatus,
    InjectionSubtype,
    TrustedInjectionClassification,
)

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

    def trusted_classification(self, cve_id: CveId | str) -> TrustedInjectionClassification | None:
        """Return the policy-owned trusted classification for a CVE if registered."""
        return self._trusted.get(str(cve_id))

    def evaluate(self, advisory: CVEAdvisoryRecord) -> InjectionScopeEvaluation:
        """Evaluate whether an advisory belongs to A05: Injection scope."""
        cve_id = advisory.cve_id
        all_cwes: set[str] = set(advisory.cwe_ids)
        if advisory.primary_cwe_id:
            all_cwes.add(advisory.primary_cwe_id)

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

        primary = advisory.primary_cwe_id
        if primary and primary in DIRECT_INJECTION_CWES:
            canonical_subtype = DIRECT_INJECTION_CWES[primary]

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


__all__ = [
    "CONTEXT_DEPENDENT_CWES",
    "DEFAULT_TRUSTED_INJECTION_CLASSIFICATIONS",
    "DIRECT_INJECTION_CWES",
    "EXCLUDED_CWES",
    "InjectionScopePolicy",
]

