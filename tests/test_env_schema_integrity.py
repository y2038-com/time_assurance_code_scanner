# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Integrity tests for environment.schema.json and its Python counterparts.

Three layers decide whether an environment config is acceptable: the JSON
schema, ``envui``'s business rules and ``config_detector``'s. They can drift
apart without anything failing, which is how a schema kept four conditionals as
duplicate object keys, silently retained only the last pair, and enforced three
rules less than it appeared to.

These tests hold the layers together: the schema must parse strictly and be a
valid schema, every hint TACS composes must satisfy it, and a matrix of configs
must get the same verdict from every layer.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from config_detector.validator import ConfigValidator as DetectorValidator
from envui.cli.derive_fields import FieldDeriver, requires_mitigation_path
from envui.cli.validate_env import EnvironmentValidator
from tacs.batch_scan_repos import VALID_CONFIG_IDS, _config_id_to_env_json

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "src/envui/schemas/environment.schema.json"


def load_json_strict(text: str) -> Any:
    """Parse JSON, refusing duplicate object keys instead of keeping the last.

    ``json.loads`` resolves ``{"if": ..., "if": ...}`` to the final value without
    complaint, so a schema can carry rules that never run.
    """

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                raise ValueError(f"duplicate JSON object key: {key!r}")
            seen.add(key)
        return dict(pairs)

    return json.loads(text, object_pairs_hook=reject_duplicates)


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return load_json_strict(SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def envui_validator() -> EnvironmentValidator:
    return EnvironmentValidator()


@pytest.fixture(scope="module")
def detector_validator() -> DetectorValidator:
    return DetectorValidator()


def _valid_config(**overrides: Any) -> dict[str, Any]:
    config = {
        "hardware_model": "ILP32",
        "time_t_size_bits": 32,
        "time_t_signed": "signed",
        "time64_functions_available": None,
        "d_time_bits_supported": None,
        "d_time_bits_setting": "unknown",
        "c_library": "glibc",
        "scenario_hint": "ILP32-32bit-signed-time64_unknown",
        "mitigation_path": "upgrade_env",
    }
    config.update(overrides)
    return config


def _schema_accepts(schema: dict[str, Any], config: dict[str, Any]) -> bool:
    return jsonschema.Draft7Validator(schema).is_valid(config)


# --- A. duplicate object keys ------------------------------------------------


def test_schema_file_has_no_duplicate_keys() -> None:
    """The defect that hid three conditionals must fail the build, not the reader."""
    load_json_strict(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_strict_loader_catches_the_shape_of_the_original_defect() -> None:
    duplicated = """
    {
      "if": {"properties": {"a": {"const": false}}},
      "then": {"properties": {"b": {"const": "x"}}},
      "if": {"properties": {"a": {"const": true}}},
      "then": {"properties": {"b": {"const": "y"}}}
    }
    """

    assert json.loads(duplicated)["if"]["properties"]["a"]["const"] is True
    with pytest.raises(ValueError, match="duplicate JSON object key: 'if'"):
        load_json_strict(duplicated)


def test_every_conditional_in_the_schema_is_reachable(schema: dict[str, Any]) -> None:
    """Conditionals live under allOf, where siblings cannot overwrite each other."""
    assert "if" not in schema and "then" not in schema
    assert len(schema["allOf"]) == 5
    for clause in schema["allOf"]:
        assert set(clause) == {"if", "then"}
        assert clause["if"].get("required"), "an if without required fires on absent fields"


# --- B. the schema is a schema -----------------------------------------------


def test_schema_is_a_valid_draft7_schema(schema: dict[str, Any]) -> None:
    jsonschema.Draft7Validator.check_schema(schema)


def test_schema_declares_the_draft_it_is_checked_against(schema: dict[str, Any]) -> None:
    assert schema["$schema"] == jsonschema.Draft7Validator.META_SCHEMA["$id"]


def test_validators_load_the_same_schema_file(envui_validator, detector_validator) -> None:
    on_disk = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert envui_validator.schema == on_disk
    assert detector_validator.schema == on_disk


# --- C. generated configs validate -------------------------------------------


@pytest.mark.parametrize("config_id", sorted(VALID_CONFIG_IDS))
def test_generated_configs_validate_against_the_schema(
    schema: dict[str, Any], envui_validator, detector_validator, config_id: str
) -> None:
    config = _config_id_to_env_json(config_id)

    jsonschema.Draft7Validator(schema).validate(config)
    assert envui_validator.validate(config) == (True, [])
    assert detector_validator.validate(config) == (True, [])


@pytest.mark.parametrize("time64", [True, False, None])
@pytest.mark.parametrize("model, bits", [("ILP32", 32), ("ILP32", 64), ("LP64", 64)])
@pytest.mark.parametrize("signedness", ["signed", "unsigned"])
def test_derived_hints_validate_against_the_schema(
    schema: dict[str, Any], time64, model: str, bits: int, signedness: str
) -> None:
    hint = FieldDeriver()._derive_scenario_hint(
        {
            "hardware_model": model,
            "time_t_size_bits": bits,
            "time_t_signed": signedness,
            "time64_functions_available": time64,
        }
    )

    assert _schema_accepts(schema, _valid_config(scenario_hint=hint, mitigation_path="upgrade_env"))


@pytest.mark.parametrize(
    "hint",
    [
        "ILP32-32bit-signed-time64_no",
        "ILP32-32bit-signed-time64_unknown",
        "ILP32-32bit-unsigned-time64_yes",
        "ILP32-64bit-N/A",
        "LP64-64bit-N/A",
        "LP64-64bit-signed-time64_unknown",
        # Hints user-authored fixtures already carry, composed with a _TIME_BITS tail.
        "ILP32-32bit-signed-time64_no-N/A",
        "ILP32-64bit-signed-time64_yes-_TIME_BITS_64",
        "LP64-64bit-unsigned-time64_yes-_TIME_BITS_64",
    ],
)
def test_hints_tacs_and_its_fixtures_compose_are_valid(schema: dict[str, Any], hint: str) -> None:
    assert _schema_accepts(schema, _valid_config(scenario_hint=hint, mitigation_path="upgrade_env"))


@pytest.mark.parametrize(
    "hint",
    [
        "",
        "unknown",
        "N/A",
        "ILP32",
        "ILP32-33bit-signed-time64_no",
        "MIPS32-32bit-signed-time64_no",
        "ILP32-32bit-maybe-time64_no",
        "ILP32-32bit-signed-time64_maybe",
        "ILP32-32bit-signed-time64_no-_TIME_BITS_16",
        "ILP32-32bit-signed-time64_no-extra-N/A",
        "32-bit embedded system with unsigned time_t",
        " ILP32-32bit-signed-time64_no",
        "ILP32-32bit-signed-time64_no ",
    ],
)
def test_malformed_hints_are_rejected(schema: dict[str, Any], hint: str) -> None:
    assert not _schema_accepts(schema, _valid_config(scenario_hint=hint))


def test_generated_hints_are_deterministic() -> None:
    for config_id in sorted(VALID_CONFIG_IDS):
        hints = {_config_id_to_env_json(config_id)["scenario_hint"] for _ in range(3)}
        assert len(hints) == 1


def test_the_pattern_fixture_generator_also_composes_valid_configs(schema: dict[str, Any]) -> None:
    """The third hint generator, used to build tests/patterns/env_configs."""
    sys.path.insert(0, str(REPO_ROOT / "tests/patterns"))
    from test_config_fixtures import get_all_test_configs

    configs = get_all_test_configs()
    assert len(configs) == 8

    for name, config in configs.items():
        errors = [error.message for error in jsonschema.Draft7Validator(schema).iter_errors(config)]
        assert not errors, f"{name}: {errors}"


def test_shipped_configs_and_fixtures_validate(
    schema: dict[str, Any], envui_validator, detector_validator
) -> None:
    shipped = [
        *(REPO_ROOT / "configs").glob("*.env_config.json"),
        REPO_ROOT / "configs/embedded_32bit_unsigned_time_t.json",
        REPO_ROOT / "src/envui/examples/env_config.sample.json",
        *(REPO_ROOT / "tests/patterns/env_configs").glob("*.json"),
    ]
    assert len(shipped) >= 7

    for path in shipped:
        config = load_json_strict(path.read_text(encoding="utf-8"))
        errors = jsonschema.Draft7Validator(schema).iter_errors(config)
        assert not list(errors), f"{path.name} fails the schema"
        assert envui_validator.validate(config)[0], path.name
        assert detector_validator.validate(config)[0], path.name


# --- D. schema / Python validator parity -------------------------------------

#: (name, config, expected_valid). Each case must get the same verdict from the
#: schema and from both Python validators.
PARITY_CASES: list[tuple[str, dict[str, Any], bool]] = [
    # Tri-state capabilities
    ("capabilities unknown", _valid_config(), True),
    (
        "capabilities known available",
        _valid_config(
            time64_functions_available=True,
            d_time_bits_supported=True,
            d_time_bits_setting="64",
        ),
        True,
    ),
    (
        "capabilities known absent",
        _valid_config(
            time64_functions_available=False,
            d_time_bits_supported=False,
            d_time_bits_setting="not_available",
            scenario_hint="ILP32-32bit-signed-time64_no",
        ),
        True,
    ),
    (
        "time64 unknown with _TIME_BITS known",
        _valid_config(
            time64_functions_available=None,
            d_time_bits_supported=True,
            d_time_bits_setting="not_set",
        ),
        True,
    ),
    ("capability field omitted", _omitted := _valid_config(), False),
    # _TIME_BITS support vs setting
    (
        "support false with a setting",
        _valid_config(d_time_bits_supported=False, d_time_bits_setting="64"),
        False,
    ),
    (
        "support false with unknown setting",
        _valid_config(d_time_bits_supported=False, d_time_bits_setting="unknown"),
        False,
    ),
    (
        "support true but setting not_available",
        _valid_config(d_time_bits_supported=True, d_time_bits_setting="not_available"),
        False,
    ),
    (
        "support true with unknown setting",
        _valid_config(d_time_bits_supported=True, d_time_bits_setting="unknown"),
        True,
    ),
    (
        "support unknown but setting not_available",
        _valid_config(d_time_bits_supported=None, d_time_bits_setting="not_available"),
        False,
    ),
    (
        "setting outside the enum",
        _valid_config(d_time_bits_supported=True, d_time_bits_setting="not set"),
        False,
    ),
    # c_library
    (
        "c_library other with text",
        _valid_config(c_library="other", c_library_other_text="vendor libc"),
        True,
    ),
    ("c_library other with empty text", _valid_config(c_library="other", c_library_other_text=""), False),
    ("c_library other without text", _valid_config(c_library="other"), False),
    ("c_library outside the enum", _valid_config(c_library="embedded C library"), False),
    # scenario_hint and mitigation_path
    (
        "risky hint with mitigation",
        _valid_config(scenario_hint="ILP32-32bit-signed-time64_no", mitigation_path="stay_and_patch"),
        True,
    ),
    (
        "risky hint with null mitigation",
        _valid_config(scenario_hint="ILP32-32bit-signed-time64_no", mitigation_path=None),
        False,
    ),
    (
        "risky hint without a mitigation key",
        {k: v for k, v in _valid_config().items() if k != "mitigation_path"},
        False,
    ),
    (
        "risky unknown-time64 hint with null mitigation",
        _valid_config(scenario_hint="ILP32-32bit-signed-time64_unknown", mitigation_path=None),
        False,
    ),
    (
        "risky hint with a trailing segment and null mitigation",
        _valid_config(scenario_hint="ILP32-32bit-signed-time64_no-N/A", mitigation_path=None),
        False,
    ),
    (
        "safe hint with null mitigation",
        _valid_config(
            hardware_model="LP64",
            time_t_size_bits=64,
            scenario_hint="LP64-64bit-N/A",
            mitigation_path=None,
        ),
        True,
    ),
    ("malformed hint", _valid_config(scenario_hint="ILP32-32bit-signed-time64_maybe"), False),
    ("mitigation outside the enum", _valid_config(mitigation_path="rewrite_in_rust"), False),
    # Core ABI fields
    ("hardware_model outside the enum", _valid_config(hardware_model="ilp32"), False),
    ("time_t width outside the enum", _valid_config(time_t_size_bits=16), False),
    ("signedness outside the enum", _valid_config(time_t_signed="maybe"), False),
    # toolchain_flags
    ("toolchain flags well formed", _valid_config(toolchain_flags=["-D_TIME_BITS=64"]), True),
    ("toolchain flags malformed", _valid_config(toolchain_flags=["_TIME_BITS=64"]), False),
    ("toolchain flags not a list", _valid_config(toolchain_flags="-D_TIME_BITS=64"), False),
]

# The omitted-capability case is built by deletion, which _valid_config cannot express.
_omitted.pop("time64_functions_available")


@pytest.mark.parametrize("name, config, expected", PARITY_CASES, ids=[c[0] for c in PARITY_CASES])
def test_schema_and_python_validators_agree(
    schema: dict[str, Any], envui_validator, detector_validator, name, config, expected
) -> None:
    schema_ok = _schema_accepts(schema, config)
    envui_ok, envui_errors = envui_validator.validate(config)
    detector_ok, detector_errors = detector_validator.validate(config)

    assert schema_ok is expected, f"{name}: schema disagrees"
    assert envui_ok is expected, f"{name}: envui says {envui_errors}"
    assert detector_ok is expected, f"{name}: config_detector says {detector_errors}"


@pytest.mark.parametrize(
    "flags",
    [
        [64],
        [None],
        [1.5],
        [True],
        [["-D_TIME_BITS=64"]],
        [{"flag": "-D_TIME_BITS=64"}],
        ["-D_TIME_BITS=64", 64],
    ],
    ids=["int", "null", "float", "bool", "list", "dict", "mixed with a valid flag"],
)
def test_non_string_toolchain_flags_are_reported_not_raised(
    schema: dict[str, Any], envui_validator, detector_validator, flags
) -> None:
    """A validator answers whether the config is valid; crashing answers nothing."""
    config = _valid_config(toolchain_flags=flags)

    envui_ok, envui_errors = envui_validator.validate(config)
    detector_ok, _ = detector_validator.validate(config)

    assert envui_ok is False
    assert detector_ok is False
    assert not _schema_accepts(schema, config)
    assert any("must be a string" in error for error in envui_errors), envui_errors


def test_a_non_list_toolchain_flags_value_is_reported_not_raised(
    envui_validator, detector_validator
) -> None:
    config = _valid_config(toolchain_flags=64)

    envui_ok, envui_errors = envui_validator.validate(config)

    assert envui_ok is False
    assert detector_validator.validate(config)[0] is False
    assert any("must be a list" in error for error in envui_errors), envui_errors


def test_valid_toolchain_flags_are_untouched(envui_validator) -> None:
    config = _valid_config(toolchain_flags=["-D_TIME_BITS=64", "-D_FILE_OFFSET_BITS=64", "-m32"])

    assert envui_validator.validate(config) == (True, [])


def test_a_malformed_string_flag_keeps_its_original_error(envui_validator) -> None:
    _, errors = envui_validator.validate(_valid_config(toolchain_flags=["_TIME_BITS=64"]))

    assert any("Invalid toolchain flag format: '_TIME_BITS=64'" in error for error in errors)


@pytest.mark.parametrize(
    "hint, required",
    [
        ("ILP32-32bit-signed-time64_no", True),
        ("ILP32-32bit-signed-time64_unknown", True),
        ("ILP32-32bit-signed-time64_no-N/A", True),
        ("ILP32-32bit-signed-time64_unknown-_TIME_BITS_unknown", True),
        ("ILP32-32bit-signed-time64_yes", False),
        ("ILP32-32bit-unsigned-time64_no", False),
        ("LP64-64bit-N/A", False),
    ],
)
def test_mitigation_rule_reads_hints_the_way_the_schema_does(
    schema: dict[str, Any], hint: str, required: bool
) -> None:
    """One question, asked as a prefix in Python and as a pattern in the schema."""
    assert requires_mitigation_path(hint) is required

    without_mitigation = _valid_config(scenario_hint=hint, mitigation_path=None)
    assert _schema_accepts(schema, without_mitigation) is not required


def test_a_missing_hint_asks_for_no_mitigation() -> None:
    assert requires_mitigation_path("") is False
    assert requires_mitigation_path(None) is False
