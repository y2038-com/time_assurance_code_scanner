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
    "confidence_floor",
    "include_no_findings",
    "min_risk",
)


def _scan_defaults() -> dict[str, object]:
    return {p.name: p.default for p in scan_command.params}


def _repos_defaults() -> dict[str, object]:
    return {a.dest: a.default for a in _build_parser()._actions}


def _resolved_repos_defaults() -> dict[str, object]:
    """Defaults after ``main()`` fills dynamic None sentinels (llm/model/include)."""
    from tacs.batch_scan_repos import (
        DEFAULT_EXCLUDE_PATTERNS,
        DEFAULT_INCLUDE_PATTERNS,
        _cli_default_llm,
    )
    from tacs.llm.env import default_model_id

    args = _build_parser().parse_args(["--repos-file", "x"])
    # Mirror main()'s post-parse resolution without running a batch.
    if args.llm is None:
        args.llm = _cli_default_llm()
    if args.model is None:
        args.model = default_model_id()
    if args.include is None:
        args.include = list(DEFAULT_INCLUDE_PATTERNS)
    if args.exclude is None:
        args.exclude = list(DEFAULT_EXCLUDE_PATTERNS)
    return vars(args)


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


def test_request_timeout_defaults_match() -> None:
    scan = _scan_defaults()
    repos = _repos_defaults()
    assert scan["request_timeout_sec"] == 300
    assert repos["request_timeout_sec"] == 300
    assert scan["request_timeout_sec"] == repos["request_timeout_sec"]


def test_include_exclude_defaults_match_scan() -> None:
    from tacs.batch_scan_repos import DEFAULT_EXCLUDE_PATTERNS, DEFAULT_INCLUDE_PATTERNS

    scan = _scan_defaults()
    assert list(scan["include"]) == list(DEFAULT_INCLUDE_PATTERNS)
    assert list(scan["exclude"]) == list(DEFAULT_EXCLUDE_PATTERNS)
    resolved = _resolved_repos_defaults()
    assert resolved["include"] == list(DEFAULT_INCLUDE_PATTERNS)
    assert resolved["exclude"] == list(DEFAULT_EXCLUDE_PATTERNS)


def test_agreed_defaults_are_y2106_off() -> None:
    """Pin the chosen values, not just that the two commands happen to match."""
    for defaults in (_scan_defaults(), _repos_defaults()):
        assert defaults["detect_y2106"] is False


def test_engine_default_matches_the_commands() -> None:
    """A library caller building a pipeline directly gets the same analysis."""
    params = inspect.signature(ScanningPipeline.__init__).parameters

    assert params["detect_y2106"].default is False
    assert params["enable_pass1"].default is False
    assert params["function_first"].default is True


def test_stage1_is_scan_legacy_only() -> None:
    """Stage S1 is a tacs scan legacy-path control; repos is function-first only."""
    scan_flags = {
        opt for p in scan_command.params for opt in p.opts + p.secondary_opts
    }
    repos_flags = {
        opt for a in _build_parser()._actions for opt in a.option_strings
    }

    assert "--no-disable-stage1" in scan_flags
    assert "--disable-stage1" in scan_flags
    assert "--no-disable-stage1" not in repos_flags
    assert "--disable-stage1" not in repos_flags


def test_function_first_never_builds_legacy_llm_client_for_stage1() -> None:
    """Stage S1 gates on ``llm_client``; function-first only builds FunctionLLMClient."""
    pipeline = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="ollama",
        model="stub-model",
        function_first=True,
        enable_pass1=True,
    )

    assert pipeline.enable_pass1 is True
    assert hasattr(pipeline, "function_llm_client")
    assert not hasattr(pipeline, "llm_client")


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

    assert pipeline.function_first is True
    assert pipeline.enable_pass1 is False
    assert pipeline.detect_y2106 is False
    assert pipeline.confidence_floor == 0.85
    assert not hasattr(pipeline, "llm_client")


def test_batch_pipeline_cannot_enable_stage1(tmp_path: Path) -> None:
    """tacs repos is function-first only; Stage S1 is not exposed or constructible."""
    pipeline = _batch_pipeline(tmp_path, llm="ollama")

    assert pipeline.enable_pass1 is False
    assert not hasattr(pipeline, "llm_client")


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
