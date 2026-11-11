"""Vulnerability knowledge provider protocols and LocalSeedCVEProvider."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from websecuritycheck.domain.enums import TechnologyCategory

from .models import (
    CPEProductEntry,
    CVEAdvisoryRecord,
    CVEProviderError,
    ProductMatchKind,
    VersionScheme,
)


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
            catalog_path = Path(__file__).resolve().parent.parent / "data" / "cve_seed_catalog.json"
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
            cat_ok = category in p.allowed_categories or category == TechnologyCategory.OTHER
            if not cat_ok:
                continue

            is_exact = (
                name_clean == f"{p.vendor}:{p.product}".casefold()
                or name_clean == p.product.casefold()
                or any(name_clean == en.casefold() for en in p.exact_names)
            )
            if is_exact:
                exact_matches.append(p)
                continue

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


__all__ = [
    "AsyncVulnerabilityKnowledgePort",
    "LocalSeedCVEProvider",
    "VulnerabilityKnowledgeProvider",
]

