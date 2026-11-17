"""Validation tests for the Generic Guided Tactic Schema, Capability Catalog, and Tactics."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
import yaml

from websecuritycheck.domain.analysis_models import VulnerabilityCategory
from websecuritycheck.domain.enums import InputLocation

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TACTICS_ROOT = PROJECT_ROOT / "tactics"
SCHEMA_PATH = TACTICS_ROOT / "schemas" / "tactic.schema.json"
CATALOG_PATH = TACTICS_ROOT / "schemas" / "capabilities_catalog.json"
SQLI_TACTIC_PATH = TACTICS_ROOT / "sqli" / "sqli_testing.yaml"
CONTRACTS_PATH = PROJECT_ROOT / "docs" / "CAPABILITY_CONTRACTS.md"
HANDOFF_PATH = PROJECT_ROOT / "docs" / "M3_TACTIC_AND_MCP_HANDOFF.md"

EXPECTED_OUTCOMES = frozenset(
    {
        "CONFIRMED",
        "NOT_CONFIRMED",
        "INCONCLUSIVE",
        "ERROR",
        "UNSUPPORTED",
        "POLICY_BLOCKED",
    }
)


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def _tactic_yaml_paths() -> list[Path]:
    return sorted(TACTICS_ROOT.rglob("*.yaml"))


def _load_yaml(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _markdown_slugs(path: Path) -> set[str]:
    slugs: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            heading = line.lstrip("#").strip()
            slug = re.sub(r"[^a-z0-9 _-]", "", heading.lower().replace("`", "")).strip()
            slug = re.sub(r"\s+", "-", slug)
            slugs.add(slug)
    return slugs


def test_capabilities_catalog_matches_contracts_and_domain_enums():
    catalog = _load_catalog()
    caps = catalog["capabilities"]
    cap_ids = [item["id"] for item in caps]
    assert len(cap_ids) == len(set(cap_ids))
    assert set(cap_ids) == {
        "HTTP_REQUEST",
        "SQLI_DETECTION",
        "XSS_DETECTION",
        "BROWSER_INTERACTION",
        "CVE_SAFE_CHECK",
    }

    valid_vulns = {item.value for item in VulnerabilityCategory}
    valid_locations = {item.value for item in InputLocation}
    contract_slugs = _markdown_slugs(CONTRACTS_PATH)

    for cap in caps:
        assert set(cap["vulnerability_categories"]) <= valid_vulns
        assert set(cap["supported_input_locations"]) <= valid_locations
        assert cap["allowed_inputs"]
        assert cap["output_fields"]
        file_part, _, anchor = cap["contract_ref"].partition("#")
        assert (PROJECT_ROOT / file_part).is_file()
        assert anchor in contract_slugs

    assert HANDOFF_PATH.is_file()


@pytest.mark.parametrize("tactic_path", _tactic_yaml_paths(), ids=lambda p: p.name)
def test_all_tactics_validate_against_json_schema(tactic_path: Path):
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    tactic = _load_yaml(tactic_path)
    jsonschema.Draft202012Validator(schema).validate(tactic)


@pytest.mark.parametrize("tactic_path", _tactic_yaml_paths(), ids=lambda p: p.name)
def test_all_tactics_semantics_domain_alignment_and_catalog_consistency(tactic_path: Path):
    tactic = _load_yaml(tactic_path)
    catalog_by_id = {item["id"]: item for item in _load_catalog()["capabilities"]}
    contract_slugs = _markdown_slugs(CONTRACTS_PATH)

    assert tactic["scope"]["vulnerability"] in {item.value for item in VulnerabilityCategory}
    valid_locations = {item.value for item in InputLocation}
    assert set(tactic["scope"]["supported_input_locations"]) <= valid_locations
    assert set(tactic["outcomes"]) == EXPECTED_OUTCOMES

    declared_caps = {cap["id"]: cap for cap in tactic["capabilities"]}
    for cap_id, cap_entry in declared_caps.items():
        assert cap_id in catalog_by_id
        assert cap_entry["contract_ref"] == catalog_by_id[cap_id]["contract_ref"]
        file_part, _, anchor = cap_entry["contract_ref"].partition("#")
        assert (PROJECT_ROOT / file_part).is_file()
        assert anchor in contract_slugs

    steps = tactic["steps"]
    step_ids = [step["id"] for step in steps]
    assert len(step_ids) == len(set(step_ids))
    valid_actions = set(step_ids) | set(tactic["outcomes"])

    reaches_terminal = False
    for step in steps:
        rec_cap = step["recommended_capability"]
        if rec_cap is not None:
            assert rec_cap in declared_caps
            suggested = step.get("suggested_inputs") or {}
            allowed = set(catalog_by_id[rec_cap]["allowed_inputs"])
            assert set(suggested) <= allowed
        for option in step["next_options"]:
            assert option["action"] in valid_actions
            if option["action"] in EXPECTED_OUTCOMES:
                reaches_terminal = True
    assert reaches_terminal

    for ref in tactic["references"]:
        if ref.endswith(".md"):
            assert (PROJECT_ROOT / ref).is_file()

    joined_rules = " ".join(tactic["confirmation_rules"]).lower()
    assert "confirmed" in joined_rules
    assert "evidence" in joined_rules


def test_tactic_schema_rejects_unknown_fields_and_invalid_modes():
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(_load_schema())

    invalid_extra = _load_yaml(SQLI_TACTIC_PATH)
    invalid_extra["unexpected_field"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid_extra)

    invalid_mode = copy.deepcopy(_load_yaml(SQLI_TACTIC_PATH))
    invalid_mode["mode"] = "WORKFLOW_ENGINE"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid_mode)
