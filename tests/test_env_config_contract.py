# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the --env-config contract.

Target ``time_t`` width and signedness decide whether an expression overflows at
all, so a scan that was asked for a specific environment must not quietly run
without it. An unreadable, malformed, or unrecognized config used to produce a
warning and then scan with no environment at all, reporting findings for a
different target than the one requested. Supplying no config remains valid.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from tacs.cli import app
from tacs.core.config_validator import ConfigValidator
from tacs.core.pipeline import EnvironmentConfigError, ScanningPipeline

SCANNER = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tacs"
    / "python"
    / "y2038scan_fast_json_group.py"
)

VALID_CONFIG = {
    "hardware_model": "ILP32",
    "time_t_size_bits": 32,
    "time_t_signed": "signed",
}


def _pipeline(env_config_path: str | None) -> ScanningPipeline:
    return ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        environment_config_path=env_config_path,
    )


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# --- an explicitly supplied config must be usable ---------------------------


def test_missing_config_file_fails_the_scan(tmp_path: Path) -> None:
    with pytest.raises(EnvironmentConfigError, match="Cannot read environment config"):
        _pipeline(str(tmp_path / "typo.json"))


def test_malformed_json_fails_the_scan(tmp_path: Path) -> None:
    path = _write(tmp_path, "bad.json", '{"hardware_model": ILP32,,,}')

    with pytest.raises(EnvironmentConfigError, match="not valid JSON"):
        _pipeline(str(path))


def test_non_object_json_fails_the_scan(tmp_path: Path) -> None:
    path = _write(tmp_path, "list.json", json.dumps([VALID_CONFIG]))

    with pytest.raises(EnvironmentConfigError, match="must hold a JSON object"):
        _pipeline(str(path))


def test_unrecognized_target_fails_the_scan(tmp_path: Path) -> None:
    """A syntactically fine config describing no known target is still an error."""
    path = _write(
        tmp_path,
        "wrong.json",
        json.dumps({**VALID_CONFIG, "time_t_size_bits": 48}),
    )

    with pytest.raises(EnvironmentConfigError, match="is invalid"):
        _pipeline(str(path))


def test_missing_required_fields_fails_the_scan(tmp_path: Path) -> None:
    path = _write(tmp_path, "partial.json", json.dumps({"hardware_model": "ILP32"}))

    with pytest.raises(EnvironmentConfigError, match="Missing required fields"):
        _pipeline(str(path))


def test_error_names_the_offending_path(tmp_path: Path) -> None:
    path = _write(tmp_path, "bad.json", "{oops")

    with pytest.raises(EnvironmentConfigError) as excinfo:
        _pipeline(str(path))
    assert str(path) in str(excinfo.value)


# --- valid and absent configs are unaffected --------------------------------


def test_valid_config_loads_and_is_identified(tmp_path: Path) -> None:
    path = _write(tmp_path, "env.json", json.dumps(VALID_CONFIG))

    pipeline = _pipeline(str(path))

    assert pipeline.environment_config["config_id"] == "ilp32_signed_32bit"
    assert pipeline.environment_config["time_t_size_bits"] == 32


def test_no_config_is_still_allowed() -> None:
    """Scanning without a declared environment stays valid."""
    pipeline = _pipeline(None)

    assert pipeline.environment_config is None


@pytest.mark.parametrize("config_id", sorted(ConfigValidator.VALID_CONFIGS))
def test_every_supported_config_satisfies_the_contract(
    config_id: str, tmp_path: Path
) -> None:
    """The configs tacs repos generates must all pass the stricter check."""
    from tacs.batch_scan_repos import _config_id_to_env_json

    path = _write(tmp_path, "env.json", json.dumps(_config_id_to_env_json(config_id)))

    pipeline = _pipeline(str(path))

    assert pipeline.environment_config["config_id"] == config_id


# --- the CLI reports it clearly and produces nothing ------------------------


@pytest.mark.parametrize(
    ("name", "text", "expected"),
    [
        ("typo.json", None, "Cannot read environment config"),
        ("bad.json", "{oops", "not valid JSON"),
        ("wrong.json", '{"hardware_model":"ILP32","time_t_size_bits":48,'
                       '"time_t_signed":"signed"}', "is invalid"),
    ],
)
def test_scan_cli_fails_clearly_without_writing_findings(
    name: str, text: str | None, expected: str, tmp_path: Path
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.c").write_text(
        "#include <time.h>\nint f(void){ time_t t=time(NULL); return (int)t; }\n",
        encoding="utf-8",
    )
    rules = _write(
        tmp_path,
        "rules.json",
        json.dumps(
            [{"symbol": "time", "risk": "high", "category": "function",
              "description": "time"}]
        ),
    )
    env_config = tmp_path / name
    if text is not None:
        env_config.write_text(text, encoding="utf-8")
    out = tmp_path / "out.json"

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--root",
            str(root),
            "--rules",
            str(rules),
            "--llm",
            "none",
            "--out",
            str(out),
            "--env-config",
            str(env_config),
            "--log-level",
            "ERROR",
        ],
    )

    assert result.exit_code == 1
    combined = result.output + (result.stderr or "")
    assert "Scan failed" in combined
    assert expected in combined
    assert "Traceback" not in combined
    assert not out.exists(), "a failed scan must not leave findings behind"
