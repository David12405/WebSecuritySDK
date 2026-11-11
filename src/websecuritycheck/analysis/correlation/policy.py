"""Control-plane trust policies, taxonomy mappings, and enums for M2-T05 correlation."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from websecuritycheck.domain.analysis_models import (
    CveId,
    CweId,
    SinkKind,
    VulnerabilityCategory,
)

from ..ast_taint.models import TrustedTaintProducer
from ..cve import InjectionSubtype
from ..route_binding.models import TrustedRouteProducer

CorrelationId = Annotated[str, StringConstraints(pattern=r"^COR-[0-9a-f]{16}$")]


class CorrelationInputError(ValueError):
    """Raised when correlation input data or references fail closed."""


class CorrelationTrustPolicyError(ValueError):
    """Raised when CorrelationTrustPolicy entries fail invariant checks."""


class CorrelationKind(StrEnum):
    """Classification of the security relation established by correlation."""

    INPUT_SINK = "INPUT_SINK"
    ENDPOINT_SINK = "ENDPOINT_SINK"
    CVE_TECHNOLOGY = "CVE_TECHNOLOGY"
    SINK_CVE = "SINK_CVE"
    INPUT_SINK_CVE_CHAIN = "INPUT_SINK_CVE_CHAIN"


class CorrelationStatus(StrEnum):
    """Certainty status of the correlated relationship."""

    VERIFIED = "VERIFIED"
    PARTIAL = "PARTIAL"
    UNRESOLVED = "UNRESOLVED"


class AccessorResolution(StrEnum):
    """Outcome of parsing a static taint source snippet for input accessors."""

    RESOLVED = "RESOLVED"
    DYNAMIC_KEY = "DYNAMIC_KEY"
    REDACTED = "REDACTED"
    TRUNCATED = "TRUNCATED"
    UNSUPPORTED = "UNSUPPORTED"


class RuleMode(StrEnum):
    """Opengrep analysis mode declared by an approved rule."""

    TAINT = "TAINT"
    SEARCH = "SEARCH"


class RuleProvenanceStatus(StrEnum):
    """Validation status of the Opengrep rule and ruleset provenance."""

    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    CONFLICT = "CONFLICT"


class FlowTrust(StrEnum):
    """Trust tier of the static dataflow / taint trace."""

    TRUSTED_TAINT = "TRUSTED_TAINT"
    UNTRUSTED_TAINT = "UNTRUSTED_TAINT"
    PATTERN_ONLY = "PATTERN_ONLY"
    CONFLICT = "CONFLICT"


class IndependenceStatus(StrEnum):
    """Provenance independence evaluation across supporting relation evidence."""

    INDEPENDENT = "INDEPENDENT"
    SHARED = "SHARED"
    UNKNOWN = "UNKNOWN"


SUBTYPE_TO_CATEGORY: dict[InjectionSubtype, VulnerabilityCategory | None] = {
    InjectionSubtype.SQL_INJECTION: VulnerabilityCategory.SQL_INJECTION,
    InjectionSubtype.OS_COMMAND_INJECTION: VulnerabilityCategory.OS_COMMAND_INJECTION,
    InjectionSubtype.NOSQL_INJECTION: VulnerabilityCategory.NOSQL_INJECTION,
    InjectionSubtype.LDAP_INJECTION: VulnerabilityCategory.LDAP_XPATH_ORM_INJECTION,
    InjectionSubtype.XPATH_INJECTION: VulnerabilityCategory.LDAP_XPATH_ORM_INJECTION,
    InjectionSubtype.ORM_QUERY_INJECTION: VulnerabilityCategory.LDAP_XPATH_ORM_INJECTION,
    InjectionSubtype.SSTI: VulnerabilityCategory.SSTI,
    InjectionSubtype.CODE_INJECTION: None,
}

SINK_KIND_INJECTION_CWES: dict[SinkKind, frozenset[str]] = {
    SinkKind.SQL_QUERY: frozenset({"CWE-89"}),
    SinkKind.ORM_QUERY: frozenset({"CWE-564", "CWE-89"}),
    SinkKind.OS_COMMAND: frozenset({"CWE-77", "CWE-78"}),
    SinkKind.NOSQL_QUERY: frozenset({"CWE-943"}),
    SinkKind.LDAP_OR_XPATH: frozenset({"CWE-90", "CWE-91", "CWE-643"}),
    SinkKind.TEMPLATE_RENDER: frozenset({"CWE-1336"}),
    SinkKind.CODE_EVAL: frozenset({"CWE-94", "CWE-95", "CWE-917"}),
    SinkKind.HTML_OUTPUT: frozenset(),
    SinkKind.PATH_ACCESS: frozenset(),
}


class ApprovedRuleSpec(BaseModel):
    """Specification of an approved Opengrep rule within an approved ruleset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    rule_id: str = Field(min_length=1)
    mode: RuleMode = RuleMode.TAINT
    sink_kind: SinkKind
    subtype: InjectionSubtype
    cwe_ids: frozenset[CweId]


class ApprovedRulesetEntry(BaseModel):
    """Approved local ruleset registered by policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ruleset_id: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    review_ref: str = Field(min_length=1)
    rules: tuple[ApprovedRuleSpec, ...] = ()


PINNED_CLOUDFLARE_RULESET_SHA256 = (
    "11923c354378d4977056f74072d780cc3b5639cfb85b00f404dd10a144166f2e"
)

REVIEWED_CLOUDFLARE_RULESET_ENTRY = ApprovedRulesetEntry(
    ruleset_id="rules/cloudflare",
    sha256=PINNED_CLOUDFLARE_RULESET_SHA256,
    review_ref="SECURITY-REVIEW-2026-M2-T03C",
    rules=(
        ApprovedRuleSpec(
            rule_id="cloudflare-workers.tainted-code-injection",
            mode=RuleMode.TAINT,
            sink_kind=SinkKind.CODE_EVAL,
            subtype=InjectionSubtype.CODE_INJECTION,
            cwe_ids=frozenset({CweId("CWE-94"), CweId("CWE-95")}),
        ),
        ApprovedRuleSpec(
            rule_id="cloudflare-workers.tainted-command-injection",
            mode=RuleMode.TAINT,
            sink_kind=SinkKind.OS_COMMAND,
            subtype=InjectionSubtype.OS_COMMAND_INJECTION,
            cwe_ids=frozenset({CweId("CWE-78")}),
        ),
        ApprovedRuleSpec(
            rule_id="cloudflare-workers.tainted-d1-sql-injection",
            mode=RuleMode.TAINT,
            sink_kind=SinkKind.SQL_QUERY,
            subtype=InjectionSubtype.SQL_INJECTION,
            cwe_ids=frozenset({CweId("CWE-89")}),
        ),
    ),
)


class ApprovedVulnerableApiEntry(BaseModel):
    """Curated mapping linking an approved Opengrep rule to a specific CVE."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cve_id: CveId
    technology_name: str = Field(min_length=1)
    ruleset_sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$")
    rule_ids: frozenset[str]
    review_ref: str = Field(min_length=1)
    advisory_ref: str = Field(min_length=1)
    rationale: str = Field(min_length=5)


def _compute_policy_fingerprint(
    rulesets: tuple[ApprovedRulesetEntry, ...],
    producers: tuple[TrustedRouteProducer, ...],
    vulnerable_apis: tuple[ApprovedVulnerableApiEntry, ...],
    taint_producers: tuple[TrustedTaintProducer, ...] = (),
) -> str:
    """Compute deterministic SHA-256 fingerprint of the trust policy configuration."""
    canonical_dict: dict[str, Any] = {
        "rulesets": [
            {
                "id": r.ruleset_id,
                "sha256": r.sha256.lower(),
                "review_ref": r.review_ref,
                "rules": sorted(
                    [
                        {
                            "rule_id": rule.rule_id,
                            "mode": rule.mode.value,
                            "sink_kind": rule.sink_kind.value,
                            "subtype": rule.subtype.value,
                            "cwe_ids": sorted(str(c) for c in rule.cwe_ids),
                        }
                        for rule in r.rules
                    ],
                    key=lambda x: x["rule_id"],
                ),
            }
            for r in sorted(rulesets, key=lambda x: x.ruleset_id)
        ],
        "producers": [
            {
                "id": p.producer_id,
                "methods": sorted(p.approved_methods),
                "digests": sorted(p.approved_method_digests),
                "review_ref": p.review_ref,
            }
            for p in sorted(producers, key=lambda x: x.producer_id)
        ],
        "vulnerable_apis": [
            {
                "cve_id": v.cve_id,
                "tech": v.technology_name.casefold().strip(),
                "ruleset_sha256": v.ruleset_sha256.lower(),
                "rule_ids": sorted(v.rule_ids),
                "review_ref": v.review_ref,
                "advisory_ref": v.advisory_ref,
            }
            for v in sorted(vulnerable_apis, key=lambda x: (x.cve_id, x.technology_name))
        ],
    }
    if taint_producers:
        canonical_dict["taint_producers"] = [
            {
                "id": tp.producer_id,
                "methods": sorted(tp.approved_methods),
                "digests": sorted(tp.approved_method_digests),
                "review_ref": tp.review_ref,
            }
            for tp in sorted(taint_producers, key=lambda x: x.producer_id)
        ]
    dumped = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(dumped.encode("utf-8")).hexdigest()


class CorrelationTrustPolicy(BaseModel):
    """Control-plane policy defining approved registries and trusted producers.

    All registries are strictly empty by default for fail-closed verification.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    approved_rulesets: tuple[ApprovedRulesetEntry, ...] = ()
    trusted_route_producers: tuple[TrustedRouteProducer, ...] = ()
    trusted_taint_producers: tuple[TrustedTaintProducer, ...] = ()
    approved_vulnerable_apis: tuple[ApprovedVulnerableApiEntry, ...] = ()
    fingerprint: str = ""

    @model_validator(mode="before")
    @classmethod
    def enforce_invariants_and_fingerprint(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        rulesets = tuple(data.get("approved_rulesets") or ())
        producers = tuple(data.get("trusted_route_producers") or ())
        taint_producers = tuple(data.get("trusted_taint_producers") or ())
        apis = tuple(data.get("approved_vulnerable_apis") or ())

        known_rules: dict[str, set[str]] = {}
        for rs in rulesets:
            rs_obj = rs if isinstance(rs, ApprovedRulesetEntry) else ApprovedRulesetEntry(**rs)
            digest = rs_obj.sha256.lower()
            rule_set = known_rules.setdefault(digest, set())
            for rule in rs_obj.rules:
                rule_set.add(rule.rule_id)

        for api in apis:
            api_obj = (
                api
                if isinstance(api, ApprovedVulnerableApiEntry)
                else ApprovedVulnerableApiEntry(**api)
            )
            r_digest = api_obj.ruleset_sha256.lower()
            if r_digest not in known_rules:
                raise CorrelationTrustPolicyError(
                    f"VulnerableApiEntry {api_obj.cve_id} references unapproved "
                    f"ruleset digest {r_digest}"
                )
            missing = set(api_obj.rule_ids) - known_rules[r_digest]
            if missing:
                raise CorrelationTrustPolicyError(
                    f"VulnerableApiEntry {api_obj.cve_id} references rule(s) {sorted(missing)} "
                    f"not in ruleset {r_digest}"
                )

        computed_fp = _compute_policy_fingerprint(
            tuple(
                r if isinstance(r, ApprovedRulesetEntry) else ApprovedRulesetEntry(**r)
                for r in rulesets
            ),
            tuple(
                p if isinstance(p, TrustedRouteProducer) else TrustedRouteProducer(**p)
                for p in producers
            ),
            tuple(
                a if isinstance(a, ApprovedVulnerableApiEntry) else ApprovedVulnerableApiEntry(**a)
                for a in apis
            ),
            tuple(
                tp if isinstance(tp, TrustedTaintProducer) else TrustedTaintProducer(**tp)
                for tp in taint_producers
            ),
        )
        data_copy = dict(data)
        data_copy["fingerprint"] = computed_fp
        return data_copy


DEFAULT_CORRELATION_TRUST_POLICY = CorrelationTrustPolicy()

__all__ = [
    "DEFAULT_CORRELATION_TRUST_POLICY",
    "PINNED_CLOUDFLARE_RULESET_SHA256",
    "REVIEWED_CLOUDFLARE_RULESET_ENTRY",
    "SINK_KIND_INJECTION_CWES",
    "SUBTYPE_TO_CATEGORY",
    "AccessorResolution",
    "ApprovedRuleSpec",
    "ApprovedRulesetEntry",
    "ApprovedVulnerableApiEntry",
    "CorrelationId",
    "CorrelationInputError",
    "CorrelationKind",
    "CorrelationStatus",
    "CorrelationTrustPolicy",
    "CorrelationTrustPolicyError",
    "FlowTrust",
    "IndependenceStatus",
    "RuleMode",
    "RuleProvenanceStatus",
    "TrustedRouteProducer",
    "TrustedTaintProducer",
    "_compute_policy_fingerprint",
]

