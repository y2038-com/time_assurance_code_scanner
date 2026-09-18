# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests keeping tacs scan and tacs repos on the same analysis defaults.

Both commands drive one scanning engine, so the same source, config, and model
should produce the same analysis whichever command ran it. They drifted apart
once: batch enabled Y2106 detection (a different LLM system prompt, plus
retention of Y2038=NO findings that are Y2106=YES) and batch disabled the Stage
S1 pre-filter, while standalone did the opposite on both counts. That silently
made batch results non-comparable with standalone ones.

The agreed defaults are Y2106 detection off and Stage S1 off, in both commands
and in the engine itself.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from tacs.batch_scan_repos import _build_parser
from tacs.core.pipeline import ScanningPipeline
from tacs.scan_command import main as scan_command

SCANNER = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tacs"
    / "python"
    / "y2038scan_fast_json_group.py"
)

# Options that change what the analysis reports, as opposed to where output goes
# or how chatty it is. Divergence here means two commands answering differently.
ANALYSIS_OPTIONS = (
    "detect_y2106",
    "disable_stage1",
    "confidence_floor",
    "include_no_findings",
)


def _scan_defaults() -> dict[str, object]:
    return {p.name: p.default for p in scan_command.params}


def _repos_defaults() -> dict[str, object]:
    return {a.dest: a.default for a in _build_parser()._actions}


@pytest.mark.parametrize("option", ANALYSIS_OPTIONS)
def test_both_commands_declare_the_same_analysis_default(option: str) -> None:
    scan = _scan_defaults()
    repos = _repos_defaults()

    assert option in scan, f"tacs scan no longer exposes {option}"
    assert option in repos, f"tacs repos no longer exposes {option}"
    assert scan[option] == repos[option], (
        f"tacs scan and tacs repos disagree on {option}: "
        f"{scan[option]!r} vs {repos[option]!r}. Both drive one engine, so a "
        f"divergent default makes batch results non-comparable with standalone ones."
    )


def test_agreed_defaults_are_y2106_off_and_stage1_off() -> None:
    """Pin the chosen values, not just that the two commands happen to match."""
    for defaults in (_scan_defaults(), _repos_defaults()):
        assert defaults["detect_y2106"] is False
        assert defaults["disable_stage1"] is True


def test_engine_default_matches_the_commands() -> None:
    """A library caller building a pipeline directly gets the same analysis."""
    params = inspect.signature(ScanningPipeline.__init__).parameters

    assert params["detect_y2106"].default is False
    assert params["enable_pass1"].default is False


# --- both flags stay reachable in both commands -----------------------------


def test_stage1_is_reachable_from_both_commands() -> None:
    """A default of 'disabled' must not make the pre-filter impossible to request."""
    scan_flags = {
        opt for p in scan_command.params for opt in p.opts + p.secondary_opts
    }
    repos_flags = {
        opt for a in _build_parser()._actions for opt in a.option_strings
    }

    assert "--no-disable-stage1" in scan_flags
    assert "--no-disable-stage1" in repos_flags


def test_both_commands_expose_llm_provider_flag() -> None:
    scan_flags = {
        opt for p in scan_command.params for opt in p.opts + p.secondary_opts
    }
    repos_flags = {
        opt for a in _build_parser()._actions for opt in a.option_strings
    }

    assert "--llm" in scan_flags
    assert "--llm" in repos_flags
    assert "--model" in scan_flags
    assert "--model" in repos_flags
    assert "--enable-llm" not in repos_flags
    assert "--llm-type" not in repos_flags
    assert "--no-llm" not in repos_flags


def test_y2106_is_reachable_from_both_commands() -> None:
    scan_flags = {
        opt for p in scan_command.params for opt in p.opts + p.secondary_opts
    }
    repos_flags = {
        opt for a in _build_parser()._actions for opt in a.option_strings
    }

    assert "--detect-y2106" in scan_flags
    assert "--detect-y2106" in repos_flags


# --- the defaults reach the engine the same way -----------------------------


def _batch_pipeline(tmp_path: Path, **overrides: object) -> ScanningPipeline:
    """Build a pipeline the way tacs repos does, with batch CLI defaults."""
    from tacs.batch_scan_repos import _build_pipeline

    repos_defaults = _repos_defaults()
    env_config = tmp_path / "env.json"
    env_config.write_text(
        '{"hardware_model":"ILP32","time_t_size_bits":32,"time_t_signed":"signed"}',
        encoding="utf-8",
    )
    kwargs: dict[str, object] = {
        "include_no_findings": repos_defaults["include_no_findings"],
        "llm": "ollama",
        "model": "stub-model",
        "disable_stage1": repos_defaults["disable_stage1"],
        "detect_y2106": repos_defaults["detect_y2106"],
        "confidence_floor": repos_defaults["confidence_floor"],
        "timeout_sec": 60,
        "environment_config_path": str(env_config),
    }
    kwargs.update(overrides)
    return _build_pipeline(**kwargs)  # type: ignore[arg-type]


def test_batch_pipeline_analysis_settings_match_the_engine_defaults(
    tmp_path: Path,
) -> None:
    pipeline = _batch_pipeline(tmp_path)

    assert pipeline.enable_pass1 is False
    assert pipeline.detect_y2106 is False
    assert pipeline.confidence_floor == 0.85


def test_batch_no_disable_stage1_actually_enables_stage1(tmp_path: Path) -> None:
    """The flag used to be ANDed with LLM opt-in, so it could not turn Stage S1 on.

    Stage S1 needs an LLM, but the pipeline already skips it when llm is
    "none", so the extra coupling only made the flag mean something different in
    batch than in standalone.
    """
    pipeline = _batch_pipeline(tmp_path, disable_stage1=False)

    assert pipeline.enable_pass1 is True


def test_batch_stage1_flag_is_not_silently_tied_to_llm_opt_in(
    tmp_path: Path,
) -> None:
    """--no-disable-stage1 reads the same with the LLM off as tacs scan does."""
    pipeline = _batch_pipeline(tmp_path, disable_stage1=False, llm="none")

    assert pipeline.enable_pass1 is True
    # The LLM stages are still off, so Stage S1 cannot run; that guard lives in
    # the pipeline rather than in the flag's meaning.
    assert pipeline.llm_type == "none"


def test_batch_detect_y2106_flag_reaches_the_llm_client(tmp_path: Path) -> None:
    """Y2106 changes the system prompt, so it has to reach the prompt builder."""
    pipeline = _batch_pipeline(tmp_path, detect_y2106=True)

    assert pipeline.detect_y2106 is True
    assert pipeline.function_llm_client.detect_y2106 is True


def test_detect_y2106_reaches_the_llm_client_from_a_direct_pipeline() -> None:
    """The pipeline once built the client with positional args only.

    detect_y2106 is the client's eighth parameter and defaults to False, so it
    kept that default: the Y2106 system prompt and the y2106_summary parsing were
    both fully implemented but unreachable, leaving the flag to affect only
    finding retention and the summary counters.
    """
    pipeline = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="ollama",
        model="stub-model",
        detect_y2106=True,
    )

    assert pipeline.function_llm_client.detect_y2106 is True
