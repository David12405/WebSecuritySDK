"""Validation tests for the Generic Guided Tactic Schema and SQLi Tactic YAML."""

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
SCHEMA_PATH = PROJECT_ROOT / "tactics" / "schemas" / "tactic.schema.json"
SQLI_TACTIC_PATH = PROJECT_ROOT / "tactics" / "sqli" / "sqli_testing.yaml"
CONTRACTS_PATH = PROJECT_ROOT / "docs" / "CAPABILITY_CONTRACTS.md"
GUIDE_PATH = PROJECT_ROOT / "docs" / "SQLI_TACTIC_GUIDE.md"

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
CAPABILITY_INPUT_KEYS = {
    "HTTP_REQUEST": frozenset(
        {
            "request_artifact_ref",
            "target_url",
            "method",
            "headers_ref",
            "body_ref",
            "auth_ref",
            "sample_count",
            "timeout_seconds",
        }
    ),
    "SQLI_DETECTION": frozenset(
        {
            "request_artifact_ref",
            "target_url",
            "method",
            "parameter_name",
            "parameter_location",
            "auth_ref",
            "baseline_artifact_refs",
            "techniques",
            "dbms_hint",
            "max_requests",
            "timeout_seconds",
            "risk_profile",
        }
    ),
}


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _load_sqli_tactic() -> dict:
    data = yaml.safe_load(SQLI_TACTIC_PATH.read_text(encoding="utf-8"))
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


def test_sqli_tactic_validates_against_json_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = _load_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    tactic = _load_sqli_tactic()
    jsonschema.Draft202012Validator(schema).validate(tactic)


def test_sqli_tactic_semantics_domain_alignment_and_contracts():
    tactic = _load_sqli_tactic()

    # Domain enum alignment
    assert tactic["scope"]["vulnerability"] in {item.value for item in VulnerabilityCategory}
    valid_locations = {item.value for item in InputLocation}
    assert set(tactic["scope"]["supported_input_locations"]) <= valid_locations
    assert set(tactic["outcomes"]) == EXPECTED_OUTCOMES

    # Unique step IDs, valid capabilities, valid transition targets
    declared_caps = {cap["id"]: cap for cap in tactic["capabilities"]}
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
            if rec_cap in CAPABILITY_INPUT_KEYS:
                assert set(suggested) <= CAPABILITY_INPUT_KEYS[rec_cap]
        for option in step["next_options"]:
            assert option["action"] in valid_actions
            if option["action"] in EXPECTED_OUTCOMES:
                reaches_terminal = True
    assert reaches_terminal

    # Contract & reference resolution
    for ref in tactic["references"]:
        if ref.endswith(".md"):
            assert (PROJECT_ROOT / ref).is_file()
    assert GUIDE_PATH.is_file()
    assert CONTRACTS_PATH.is_file()

    contract_slugs = _markdown_slugs(CONTRACTS_PATH)
    for cap in tactic["capabilities"]:
        file_part, _, anchor = cap["contract_ref"].partition("#")
        assert (PROJECT_ROOT / file_part).is_file()
        assert anchor in contract_slugs

    # Required M1/M2 context accuracy & evidence rules
    ctx_sources = {item["name"]: item["source"] for item in tactic["required_context"]}
    assert ctx_sources["parameter_name"] == "M2.InputCandidate"
    assert ctx_sources["expected_signals"] == "M2.ValidationCapabilityRequirement"

    joined_rules = " ".join(tactic["confirmation_rules"]).lower()
    assert "confirmed" in joined_rules
    assert "evidence" in joined_rules


def test_tactic_schema_rejects_unknown_fields_and_invalid_modes():
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(_load_schema())

    invalid_extra = _load_sqli_tactic()
    invalid_extra["unexpected_field"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid_extra)

    invalid_mode = copy.deepcopy(_load_sqli_tactic())
    invalid_mode["mode"] = "WORKFLOW_ENGINE"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(invalid_mode)


def test_generic_schema_supports_reflected_xss_tactic_shape():
    jsonschema = pytest.importorskip("jsonschema")
    validator = jsonschema.Draft202012Validator(_load_schema())

    xss_tactic_example = {
        "schema_version": "0.1.0",
        "tactic_id": "TACTIC-XSS-001",
        "name": "reflected_xss_testing",
        "mode": "GUIDED_AGENT",
        "scope": {
            "vulnerability": VulnerabilityCategory.XSS.value,
            "supported_input_locations": ["QUERY", "FORM", "HEADER", "DOM"],
            "limitations": ["Reflected XSS detection and verification only"],
        },
        "references": ["WSTG-INPV-01", "docs/TACTIC_SCHEMA_SPEC.md"],
        "required_context": [
            {"name": "target_url", "source": "M1.EndpointDefinition", "required": True},
            {"name": "parameter_name", "source": "M2.InputCandidate", "required": True},
            {"name": "execution_policy", "source": "M1.ExecutionPolicy", "required": True},
        ],
        "capabilities": [
            {
                "id": "HTTP_REQUEST",
                "contract_ref": "docs/CAPABILITY_CONTRACTS.md#2-http_request",
                "role": "required",
            },
            {
                "id": "XSS_DETECTION",
                "contract_ref": "docs/CAPABILITY_CONTRACTS.md#xss",
                "role": "required",
            },
            {
                "id": "BROWSER_INTERACTION",
                "contract_ref": "docs/CAPABILITY_CONTRACTS.md#browser",
                "role": "optional",
            },
        ],
        "safety_rules": ["Never execute unauthorized active payloads outside scope"],
        "steps": [
            {
                "id": "preflight",
                "goal": "Verify scope and policy",
                "recommended_capability": None,
                "guidance": "Check policy and input location",
                "next_options": [
                    {"when": "policy_denied", "action": "POLICY_BLOCKED", "reason": "Denied"},
                    {"when": "ready", "action": "reflection_probe", "reason": "Probe reflection"},
                ],
            },
            {
                "id": "reflection_probe",
                "goal": "Check benign canary reflection",
                "recommended_capability": "HTTP_REQUEST",
                "guidance": "Stop early as NOT_CONFIRMED if benign canary is not reflected",
                "next_options": [
                    {
                        "when": "not_reflected",
                        "action": "NOT_CONFIRMED",
                        "reason": "No reflection observed",
                    },
                    {"when": "reflected", "action": "finalize", "reason": "Evaluate proof"},
                ],
            },
            {
                "id": "finalize",
                "goal": "Verify evidence and conclude",
                "recommended_capability": None,
                "guidance": "Confirm only with unencoded executable context proof",
                "next_options": [
                    {"when": "verified", "action": "CONFIRMED", "reason": "Verified"},
                    {"when": "insufficient", "action": "INCONCLUSIVE", "reason": "Uncertain"},
                ],
            },
        ],
        "outcomes": sorted(EXPECTED_OUTCOMES),
        "confirmation_rules": [
            "Requires unencoded reflection in executable context with redacted evidence"
        ],
    }
    validator.validate(xss_tactic_example)
