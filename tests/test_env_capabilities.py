# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for tri-state environment capability fields.

Whether a target offers time64 entry points, and whether its C library honours
``_TIME_BITS``, are facts about a library build that no ABI establishes. These
tests hold the third state open: a config that never found out must not read,
validate, serialize or prompt like one that found the feature absent.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from config_detector.validator import ConfigValidator as DetectorValidator
from envui.cli.derive_fields import FieldDeriver
from envui.cli.validate_env import EnvironmentValidator
from tacs.batch_scan_repos import VALID_CONFIG_IDS, _config_id_to_env_json
from tacs.core.env_capabilities import (
    UNKNOWN_SETTING,
    capability,
    capability_of,
    describe_capability,
    setting,
    setting_of,
    time64_suffix,
)
from tacs.core.llm_client import LLMClient

CAPABILITY_FIELDS = ("time64_functions_available", "d_time_bits_supported")


def _config(**overrides) -> dict:
    config = {
        "hardware_model": "ILP32",
        "time_t_size_bits": 32,
        "time_t_signed": "signed",
        "time64_functions_available": None,
        "d_time_bits_supported": None,
        "d_time_bits_setting": UNKNOWN_SETTING,
        "c_library": "other",
        "c_library_other_text": "unspecified",
        "scenario_hint": "ILP32-32bit-signed-time64_unknown",
        "mitigation_path": "upgrade_env",
    }
    config.update(overrides)
    return config


def _environment_context(config: dict) -> str:
    return LLMClient("none", "none", config)._build_environment_context()


# --- 1. reading a capability -------------------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        (True, True),
        (False, False),
        (None, None),
        ("true", True),
        ("false", False),
        ("unknown", None),
        ("", None),
        ("nonsense", None),
    ],
)
def test_capability_reads_three_states(value, expected) -> None:
    assert capability(value) is expected


def test_absent_capability_field_is_unknown_not_false() -> None:
    """Omission is the same claim as null: nobody established the answer."""
    assert capability_of({}, "d_time_bits_supported") is None
    assert capability_of(None, "d_time_bits_supported") is None
    assert setting_of({}) == UNKNOWN_SETTING


@pytest.mark.parametrize(
    "value, expected",
    [
        ("64", "64"),
        ("not_set", "not_set"),
        ("not_available", "not_available"),
        ("unknown", UNKNOWN_SETTING),
        ("", UNKNOWN_SETTING),
        (None, UNKNOWN_SETTING),
    ],
)
def test_setting_keeps_a_known_absence_apart_from_an_unknown(value, expected) -> None:
    assert setting(value) == expected


def test_describe_capability_has_no_path_from_unknown_to_no() -> None:
    phrased = [
        describe_capability(v, yes="yes", no="no", unknown="unknown")
        for v in (True, False, None, "unknown", "", {}, 3)
    ]
    assert phrased == ["yes", "no", "unknown", "unknown", "unknown", "unknown", "unknown"]


def test_time64_suffix_has_three_forms() -> None:
    assert (time64_suffix(True), time64_suffix(False), time64_suffix(None)) == (
        "yes",
        "no",
        "unknown",
    )


# --- 2. generated configs ----------------------------------------------------


@pytest.mark.parametrize("config_id", sorted(VALID_CONFIG_IDS))
def test_generated_configs_claim_no_capability_the_id_does_not_prove(config_id: str) -> None:
    """A config id names an ABI, and an ABI ships no C library entry points."""
    config = _config_id_to_env_json(config_id)

    assert config["time64_functions_available"] is None
    assert config["d_time_bits_supported"] is None
    assert config["d_time_bits_setting"] == UNKNOWN_SETTING
    assert "not_available" not in json.dumps(config)


@pytest.mark.parametrize("config_id", sorted(VALID_CONFIG_IDS))
def test_generated_hints_report_time64_as_unknown(config_id: str) -> None:
    hint = _config_id_to_env_json(config_id)["scenario_hint"]

    assert hint.endswith("-time64_unknown")
    assert "time64_yes" not in hint and "time64_no" not in hint


def test_generated_configs_stay_distinct_per_config_id() -> None:
    hints = {cid: _config_id_to_env_json(cid)["scenario_hint"] for cid in VALID_CONFIG_IDS}

    assert len(set(hints.values())) == len(VALID_CONFIG_IDS), hints


def test_32bit_generated_configs_still_require_a_mitigation_path() -> None:
    """Unknown time64 availability does not rule the Y2038 risk out."""
    for config_id in ("ilp32_signed_32bit", "lp64_signed_32bit"):
        assert _config_id_to_env_json(config_id)["mitigation_path"] == "upgrade_env"


# --- 3. schema and validation ------------------------------------------------


@pytest.fixture(scope="module")
def envui_validator() -> EnvironmentValidator:
    return EnvironmentValidator()


@pytest.fixture(scope="module")
def detector_validator() -> DetectorValidator:
    return DetectorValidator()


def test_schema_permits_null_capabilities(envui_validator) -> None:
    is_valid, errors = envui_validator.validate(_config())

    assert is_valid, errors


def test_schema_still_permits_explicit_true_and_false(envui_validator) -> None:
    known_available = _config(
        hardware_model="LP64",
        time_t_size_bits=64,
        time_t_signed="signed",
        time64_functions_available=True,
        d_time_bits_supported=True,
        d_time_bits_setting="64",
        c_library="glibc",
        c_library_other_text="",
        scenario_hint="LP64-64bit-N/A",
        mitigation_path=None,
    )
    known_absent = _config(
        time64_functions_available=False,
        d_time_bits_supported=False,
        d_time_bits_setting="not_available",
        scenario_hint="ILP32-32bit-signed-time64_no",
    )

    for config in (known_available, known_absent):
        is_valid, errors = envui_validator.validate(config)
        assert is_valid, errors


@pytest.mark.parametrize(
    "supported, setting_value, valid",
    [
        (False, "not_available", True),
        (False, "64", False),
        (False, UNKNOWN_SETTING, False),
        (True, "64", True),
        (True, UNKNOWN_SETTING, True),
        (True, "not_available", False),
        (None, UNKNOWN_SETTING, True),
        (None, "64", True),
        (None, "not_available", False),
    ],
)
def test_time_bits_rules_read_support_as_a_tri_state(
    envui_validator, detector_validator, supported, setting_value, valid
) -> None:
    """Unknown support contradicts only a claim that the feature is absent."""
    config = _config(d_time_bits_supported=supported, d_time_bits_setting=setting_value)

    for validator in (envui_validator, detector_validator):
        is_valid, errors = validator.validate(config)
        assert is_valid is valid, errors


def test_unknown_support_error_names_the_replacement(envui_validator) -> None:
    _, errors = envui_validator.validate(
        _config(d_time_bits_supported=None, d_time_bits_setting="not_available")
    )

    assert any("unknown" in error and "not_available" in error for error in errors)


def test_detector_normalizer_keeps_unknown_out_of_false() -> None:
    """Reading these as plain booleans turned "unknown" into a claimed absence."""
    normalized = DetectorValidator().normalize(
        {
            "time64_functions_available": "unknown",
            "d_time_bits_supported": "true",
            "d_time_bits_setting": "",
        }
    )

    assert normalized["time64_functions_available"] is None
    assert normalized["d_time_bits_supported"] is True
    assert normalized["d_time_bits_setting"] == UNKNOWN_SETTING


def test_unknown_survives_a_round_trip_through_json(tmp_path: Path, envui_validator) -> None:
    path = tmp_path / "env.json"
    path.write_text(json.dumps(_config()), encoding="utf-8")

    reloaded = json.loads(path.read_text(encoding="utf-8"))

    assert reloaded["time64_functions_available"] is None
    assert reloaded["d_time_bits_supported"] is None
    assert reloaded["d_time_bits_setting"] == UNKNOWN_SETTING
    assert envui_validator.validate(reloaded)[0]


@pytest.mark.parametrize("config_id", sorted(VALID_CONFIG_IDS))
def test_generated_configs_pass_the_capability_business_rules(
    envui_validator, detector_validator, config_id: str
) -> None:
    config = _config_id_to_env_json(config_id)

    for validator in (envui_validator, detector_validator):
        errors = validator._validate_business_rules(config)
        assert errors == []


def test_shipped_example_configs_still_validate(envui_validator) -> None:
    """Explicit true/false configs written before tri-state keep working."""
    repo_root = Path(__file__).resolve().parent.parent
    sample = json.loads(
        (repo_root / "src/envui/examples/env_config.sample.json").read_text(encoding="utf-8")
    )

    assert envui_validator._validate_business_rules(sample) == []
    assert sample["d_time_bits_supported"] is True


# --- 4. derived fields -------------------------------------------------------


@pytest.mark.parametrize(
    "time64, expected_hint, expected_mitigation",
    [
        (True, "ILP32-32bit-signed-time64_yes", None),
        (False, "ILP32-32bit-signed-time64_no", "upgrade_env"),
        (None, "ILP32-32bit-signed-time64_unknown", "upgrade_env"),
    ],
)
def test_derived_hint_carries_the_three_states(
    time64, expected_hint, expected_mitigation
) -> None:
    derived = FieldDeriver().derive_fields(
        {
            "hardware_model": "ILP32",
            "time_t_size_bits": 32,
            "time_t_signed": "signed",
            "time64_functions_available": time64,
        }
    )

    assert derived["scenario_hint"] == expected_hint
    assert derived["mitigation_path"] == expected_mitigation


def test_derived_hints_are_schema_values(envui_validator) -> None:
    allowed = re.compile(envui_validator.schema["properties"]["scenario_hint"]["pattern"])

    for time64 in (True, False, None):
        for signedness in ("signed", "unsigned"):
            hint = FieldDeriver()._derive_scenario_hint(
                {
                    "hardware_model": "ILP32",
                    "time_t_size_bits": 32,
                    "time_t_signed": signedness,
                    "time64_functions_available": time64,
                }
            )
            assert allowed.match(hint), hint


def test_scenario_summary_does_not_report_unknown_as_unsupported() -> None:
    summary = FieldDeriver().get_scenario_summary(_config())

    assert "time64=unknown" in summary
    assert "not_supported" not in summary
    assert "_TIME_BITS=support_unknown:unknown" in summary


# --- 5. prompt generation ----------------------------------------------------


def test_prompt_reports_available_capabilities() -> None:
    context = _environment_context(
        _config(
            time64_functions_available=True,
            d_time_bits_supported=True,
            d_time_bits_setting="64",
        )
    )

    assert "- time64 functions: available" in context
    assert "- _TIME_BITS: supported (setting: 64)" in context


def test_prompt_reports_absent_capabilities() -> None:
    context = _environment_context(
        _config(
            time64_functions_available=False,
            d_time_bits_supported=False,
            d_time_bits_setting="not_available",
        )
    )

    assert "- time64 functions: not available" in context
    assert "- _TIME_BITS: not supported (setting: not_available)" in context


def test_prompt_never_calls_an_unknown_capability_absent() -> None:
    context = _environment_context(_config())

    assert "- time64 functions: unknown (not established" in context
    assert "- _TIME_BITS: support unknown (not established" in context
    assert "not available" not in context.split("CRITICAL")[0]
    assert "not supported" not in context.split("CRITICAL")[0]


def test_prompt_tells_the_model_what_unknown_means() -> None:
    context = _environment_context(_config())

    assert "Treat it as undetermined, not as absent" in context


@pytest.mark.parametrize("config_id", sorted(VALID_CONFIG_IDS))
def test_generated_configs_prompt_as_unknown(config_id: str) -> None:
    context = _environment_context(_config_id_to_env_json(config_id))

    assert "unknown (not established" in context
    assert "support unknown (not established" in context


# --- 6. example selection ----------------------------------------------------


@pytest.mark.parametrize(
    "config_id, expected",
    [
        ("ilp32_signed_32bit", "_get_ilp32_risky_examples"),
        ("ilp32_unsigned_32bit", "_get_ilp32_unsigned_examples"),
        ("ilp32_signed_64bit", "_get_generic_examples"),
        ("ilp32_unsigned_64bit", "_get_generic_examples"),
        ("lp64_signed_32bit", "_get_generic_examples"),
        ("lp64_unsigned_32bit", "_get_generic_examples"),
        ("lp64_signed_64bit", "_get_lp64_examples"),
        ("lp64_unsigned_64bit", "_get_lp64_examples"),
    ],
)
def test_example_selection_survives_an_unknown_capability(config_id: str, expected: str) -> None:
    """Selection reads the ABI fields, so it does not move when time64 goes unknown."""
    client = LLMClient("none", "none", _config_id_to_env_json(config_id))

    assert client._get_scenario_examples() == getattr(client, expected)()


def test_known_time64_still_moves_ilp32_signed_off_the_risky_examples() -> None:
    client = LLMClient(
        "none", "none", _config(time64_functions_available=True, d_time_bits_setting="not_set")
    )

    assert client._get_scenario_examples() == client._get_generic_examples()
