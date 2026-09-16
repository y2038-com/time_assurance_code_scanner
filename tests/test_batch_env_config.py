# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for batch environment-config wiring and config-id mapping."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import tacs.batch_scan_repos as bsr
from tacs.batch_scan_repos import (
    VALID_CONFIG_IDS,
    _build_pipeline,
    _config_id_to_env_json,
)
from tacs.core.config_validator import ConfigValidator


def _write_env_config(tmp_path: Path, config_id: str) -> Path:
    path = tmp_path / f"{config_id}.json"
    path.write_text(json.dumps(_config_id_to_env_json(config_id)), encoding="utf-8")
    return path


def _batch_pipeline(env_config_path: Path, *, enable_llm: bool = False):
    return _build_pipeline(
        include_no_findings=False,
        enable_llm=enable_llm,
        llm_type="ollama",
        model="none",
        disable_stage1=True,
        detect_y2106=True,
        confidence_floor=0.85,
        timeout_sec=60,
        environment_config_path=str(env_config_path),
    )


# --- 1. environment config must reach the pipeline's consumers ---------------


@pytest.mark.parametrize(
    "config_id,expected_bits,expected_signed",
    [
        ("ilp32_signed_32bit", 32, "signed"),
        ("ilp32_signed_64bit", 64, "signed"),
    ],
)
def test_build_pipeline_loads_env_config_into_consumers(
    tmp_path: Path, config_id: str, expected_bits: int, expected_signed: str
) -> None:
    """The config must be loaded at construction, not assigned afterwards."""
    pipeline = _batch_pipeline(_write_env_config(tmp_path, config_id))

    assert pipeline.environment_config is not None
    assert pipeline.environment_config["config_id"] == config_id
    assert pipeline.environment_config["time_t_size_bits"] == expected_bits

    # I/O boundary analyzer scores candidates against these values.
    assert pipeline.io_analyzer is not None
    assert pipeline.io_analyzer.environment_config["config_id"] == config_id
    assert pipeline.io_analyzer.time_t_size == expected_bits
    assert pipeline.io_analyzer.time_t_signed == expected_signed

    # LLM clients embed these values in prompts.
    assert pipeline.function_llm_client.environment_config["config_id"] == config_id
    assert pipeline.function_llm_client.base_client.environment_config["config_id"] == config_id


def test_build_pipeline_config_changes_consumer_behavior(tmp_path: Path) -> None:
    """Materially different configs must produce materially different analysis state."""
    narrow = _batch_pipeline(_write_env_config(tmp_path, "ilp32_signed_32bit"))
    wide = _batch_pipeline(_write_env_config(tmp_path, "ilp32_signed_64bit"))

    assert narrow.io_analyzer.time_t_size == 32
    assert wide.io_analyzer.time_t_size == 64
    assert (
        narrow.function_llm_client.environment_config
        != wide.function_llm_client.environment_config
    )

    narrow_context = narrow.function_llm_client.base_client._build_environment_context()
    wide_context = wide.function_llm_client.base_client._build_environment_context()
    assert "32-bit signed" in narrow_context
    assert "64-bit signed" in wide_context
    assert "No environment configuration provided" not in narrow_context


def test_build_pipeline_requires_environment_config_path() -> None:
    """The batch path must not be able to build a pipeline with no config."""
    with pytest.raises(TypeError):
        _build_pipeline(
            include_no_findings=False,
            enable_llm=False,
            llm_type="ollama",
            model="none",
            disable_stage1=True,
            detect_y2106=True,
            confidence_floor=0.85,
            timeout_sec=60,
        )


def test_build_pipeline_rejects_missing_environment_config(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        _batch_pipeline(tmp_path / "absent.json")


def _write_sample_repo(tmp_path: Path) -> Path:
    sample = tmp_path / "sample_src"
    sample.mkdir()
    (sample / "t.c").write_text(
        "#include <time.h>\n"
        "int main(void) {\n"
        "    time_t t = time(NULL);\n"
        "    return (int)t;\n"
        "}\n",
        encoding="utf-8",
    )
    return sample


def test_batch_run_records_env_config_in_findings_meta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A batch run's findings metadata must match the per-repo effective config."""
    sample = _write_sample_repo(tmp_path)

    def fake_prepare(identity, repo_url: str) -> None:
        identity.cache_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(sample, identity.cache_path, dirs_exist_ok=True)

    monkeypatch.setattr(bsr, "_prepare_repo", fake_prepare)
    monkeypatch.setattr(bsr, "_resolve_ref", lambda repo, ref: ("master", "a" * 40, "master"))
    monkeypatch.setattr(bsr, "_checkout_clean", lambda repo, ref, sha: None)

    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps(
            {
                "repo_url": "https://example.com/local/sample.git",
                "scan_overrides": {"config_override": "ilp32_signed_32bit"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "batch_out"

    code = bsr.main(
        [
            "--repos-file",
            str(repos_file),
            "--out-dir",
            str(out_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--log-level",
            "error",
        ]
    )
    assert code == 0

    meta_files = list(out_dir.glob("*/repos/*/meta.json"))
    assert meta_files, "expected per-repo meta.json"
    meta = json.loads(meta_files[0].read_text(encoding="utf-8"))
    assert meta["effective_config_id"] == "ilp32_signed_32bit"

    findings_files = list(out_dir.glob("*/repos/*/scan/findings.json"))
    assert findings_files, "expected per-repo findings.json"
    scan_meta = json.loads(findings_files[0].read_text(encoding="utf-8"))["meta"]
    env_config = scan_meta["environment_config"]
    assert env_config is not None, "scan metadata must record the environment config it used"
    assert env_config["config_id"] == meta["effective_config_id"]
    assert env_config["time_t_size_bits"] == 32
    assert env_config["time_t_signed"] == "signed"


def test_batch_repo_failure_reports_error_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repo failing before options are resolved must still write a status record."""

    def failing_prepare(identity, repo_url: str) -> None:
        raise RuntimeError("git clone failed: boom")

    monkeypatch.setattr(bsr, "_prepare_repo", failing_prepare)

    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps({"repo_url": "https://example.com/local/sample.git"}) + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "batch_out"

    code = bsr.main(
        [
            "--repos-file",
            str(repos_file),
            "--out-dir",
            str(out_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--log-level",
            "error",
        ]
    )
    assert code == 1

    status_files = list(out_dir.glob("*/repos/*/status.json"))
    assert status_files, "expected per-repo status.json on failure"
    status = json.loads(status_files[0].read_text(encoding="utf-8"))
    assert status["status"] == "failed"
    assert status["error_code"] == "CLONE_FAILED"
    assert "boom" in status["error_message"]
    assert status["llm_type"] == "none"


# --- 3. config id -> environment config mapping ------------------------------


@pytest.mark.parametrize("config_id", sorted(VALID_CONFIG_IDS))
def test_config_id_to_env_json_is_internally_consistent(config_id: str) -> None:
    model, signedness, bits_part = config_id.split("_")
    expected_bits = int(bits_part.removesuffix("bit"))
    config = _config_id_to_env_json(config_id)

    assert config["config_id"] == config_id
    assert config["hardware_model"] == model.upper()
    assert config["time_t_size_bits"] == expected_bits
    assert config["time_t_signed"] == signedness

    hint = config["scenario_hint"]
    assert hint.startswith(f"{model.upper()}-{expected_bits}bit-{signedness}")
    if model == "ilp32":
        assert "LP64" not in hint, f"{config_id} mislabeled as LP64"
    if signedness == "unsigned":
        assert "-signed" not in hint, f"{config_id} mislabeled as signed"
    assert f"{expected_bits}bit" in hint

    # The pipeline re-derives the config id from these fields; they must agree.
    is_valid, derived_id, error = ConfigValidator.validate_config(config)
    assert is_valid, error
    assert derived_id == config_id

    assert config["mitigation_path"] == ("upgrade_env" if expected_bits == 32 else None)
    assert config["time64_functions_available"] is (expected_bits == 64)
    assert f"{expected_bits}-bit" in config["notes"] or model.upper() in config["notes"]

    # Facts the config id does not establish stay unspecified.
    assert config["os_or_rtos"] == "unspecified"
    assert config["c_library"] == "other"
    assert config["c_library_other_text"]


def test_all_config_ids_produce_distinct_env_configs() -> None:
    hints = {cid: _config_id_to_env_json(cid)["scenario_hint"] for cid in VALID_CONFIG_IDS}
    assert len(set(hints.values())) == len(VALID_CONFIG_IDS), hints


def test_32bit_time_t_never_gets_64bit_scenario_hint() -> None:
    """LP64 with 32-bit time_t must not claim a 64-bit (safe) scenario."""
    for config_id in ("lp64_signed_32bit", "lp64_unsigned_32bit"):
        hint = _config_id_to_env_json(config_id)["scenario_hint"]
        assert "64bit" not in hint, f"{config_id} advertised as 64-bit time_t"


def test_config_id_to_env_json_rejects_invalid_ids() -> None:
    for bad in ("", "ilp32_signed", "ilp32_signed_16bit", "x86_signed_32bit", "ilp32_maybe_32bit"):
        with pytest.raises(ValueError):
            _config_id_to_env_json(bad)
