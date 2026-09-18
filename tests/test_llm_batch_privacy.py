# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for function-batch artifact privacy (raw bodies and prompts)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from tacs.cli import app
from tacs.core.function_schemas import FunctionBatch, FunctionBody
from tacs.core.scan_session import ScanSession

SECRET_BODY_LINE = "    time_t proprietary_deadline = internal_secret_clock() + 86400;"
BODY = (
    "int check_deadline(void) {\n"
    f"{SECRET_BODY_LINE}\n"
    "    return (int)proprietary_deadline;\n"
    "}"
)


def _make_session(tmp_path: Path, **flags) -> ScanSession:
    root = tmp_path / "src_root"
    root.mkdir(exist_ok=True)
    (root / "deadline.c").write_text(BODY, encoding="utf-8")
    return ScanSession(root_path=str(root), output_base=str(tmp_path), **flags)


def _make_batch(tmp_path: Path) -> FunctionBatch:
    function = FunctionBody(
        function_id="deadline.c@check_deadline:1-4",
        file_path=str(tmp_path / "src_root" / "deadline.c"),
        symbol="check_deadline",
        start_line=1,
        end_line=4,
        body=BODY,
        candidate_lines=[2],
    )
    return FunctionBatch(batch_id="s2_p1_batch_0001", functions=[function], iteration=1)


def _prompt() -> str:
    return (
        "Analyze the following functions for Y2038 risk.\n"
        "Target Environment (ilp32_signed_32bit):\n"
        "Function deadline.c@check_deadline:1-4:\n"
        "```c\n"
        f"{BODY}\n"
        "```\n"
        "Respond with JSON.\n"
    )


def _save_batch(session: ScanSession, tmp_path: Path) -> dict:
    session.save_function_batch(
        pass_name="stage_8_pass_2a",
        batch_num=1,
        function_batch=_make_batch(tmp_path),
        prompt=_prompt(),
        response=[{"function_id": "deadline.c@check_deadline:1-4", "y2038_summary": "yes"}],
    )
    batch_file = session.llm_dir / "stage_8_pass_2a" / "batches" / "0001_input.json"
    assert batch_file.is_file(), "batch manifest should always be written"
    return {
        "payload": json.loads(batch_file.read_text(encoding="utf-8")),
        "raw_text": batch_file.read_text(encoding="utf-8"),
        "path": batch_file,
    }


def _assert_manifest_fields(payload: dict) -> None:
    assert payload["batch_id"] == "stage_8_pass_2a_batch_0001"
    assert payload["pass"] == "stage_8_pass_2a"
    assert payload["function_count"] == 1
    entry = payload["functions"][0]
    assert entry["function_id"] == "deadline.c@check_deadline:1-4"
    assert entry["file_path"] == "deadline.c"
    assert entry["symbol"] == "check_deadline"
    assert entry["start_line"] == 1
    assert entry["end_line"] == 4
    assert entry["candidate_lines"] == [2]
    assert entry["candidate_count"] == 1
    assert entry["body_lines"] == 4
    assert payload["prompt_sha256"]
    assert payload["prompt_chars"] > 0


def test_llm_enabled_default_persists_manifest_without_source(tmp_path: Path) -> None:
    """Default LLM operation keeps audit metadata but no prompt or body text."""
    session = _make_session(
        tmp_path,
        enable_llm_logging=False,
        redact_prompts=True,
        allow_raw_code_logging=False,
    )
    saved = _save_batch(session, tmp_path)

    _assert_manifest_fields(saved["payload"])
    assert "full_prompt" not in saved["payload"]
    assert "prompt_redacted" not in saved["payload"]
    assert "body" not in saved["payload"]["functions"][0]
    assert SECRET_BODY_LINE.strip() not in saved["raw_text"]
    assert "internal_secret_clock" not in saved["raw_text"]
    assert saved["payload"]["privacy"]["prompt_persisted"] == "none"
    assert saved["payload"]["privacy"]["raw_function_bodies_persisted"] is False


def test_llm_logging_persists_redacted_prompt_only(tmp_path: Path) -> None:
    """--log-llm with normal privacy defaults writes a redacted prompt, not source."""
    session = _make_session(
        tmp_path,
        enable_llm_logging=True,
        redact_prompts=True,
        allow_raw_code_logging=False,
    )
    saved = _save_batch(session, tmp_path)

    _assert_manifest_fields(saved["payload"])
    assert "full_prompt" not in saved["payload"]
    assert "body" not in saved["payload"]["functions"][0]

    redacted = saved["payload"]["prompt_redacted"]
    assert "Analyze the following functions" in redacted, "non-sensitive prompt structure kept"
    assert "REDACTED" in redacted
    assert SECRET_BODY_LINE.strip() not in redacted
    assert "internal_secret_clock" not in saved["raw_text"]
    assert saved["payload"]["privacy"]["prompt_persisted"] == "redacted"


def test_redaction_covers_line_numbered_source_embedding(tmp_path: Path) -> None:
    """Source embedded with line-number prefixes must still be redacted."""
    session = _make_session(
        tmp_path,
        enable_llm_logging=True,
        redact_prompts=True,
        allow_raw_code_logging=False,
    )
    numbered = "\n".join(
        f"  {num} | {line}" for num, line in enumerate(BODY.splitlines(), start=1)
    )
    session.save_function_batch(
        pass_name="stage_9_pass_1",
        batch_num=2,
        function_batch=_make_batch(tmp_path),
        prompt=f"Analyze these lines:\n{numbered}\nRespond with JSON.\n",
    )
    batch_file = session.llm_dir / "stage_9_pass_1" / "batches" / "0002_input.json"
    text = batch_file.read_text(encoding="utf-8")
    assert "internal_secret_clock" not in text
    assert "REDACTED SOURCE LINE" in text


def test_redact_prompts_false_still_requires_raw_permission(tmp_path: Path) -> None:
    """allow_raw_code_logging is authoritative; redact_prompts=False alone grants nothing."""
    session = _make_session(
        tmp_path,
        enable_llm_logging=True,
        redact_prompts=False,
        allow_raw_code_logging=False,
    )
    saved = _save_batch(session, tmp_path)

    assert "full_prompt" not in saved["payload"]
    assert "internal_secret_clock" not in saved["raw_text"]
    assert saved["payload"]["privacy"]["prompt_persisted"] == "redacted"


def test_allow_raw_code_logging_persists_verbatim_content(tmp_path: Path) -> None:
    """Explicit raw-code logging permits verbatim prompt and body retention."""
    session = _make_session(
        tmp_path,
        enable_llm_logging=True,
        redact_prompts=True,
        allow_raw_code_logging=True,
    )
    saved = _save_batch(session, tmp_path)

    _assert_manifest_fields(saved["payload"])
    assert saved["payload"]["full_prompt"] == _prompt()
    assert saved["payload"]["functions"][0]["body"] == BODY
    assert saved["payload"]["privacy"]["prompt_persisted"] == "verbatim"
    assert saved["payload"]["privacy"]["raw_function_bodies_persisted"] is True


def test_raw_code_logging_requires_llm_logging(tmp_path: Path) -> None:
    """allow_raw_code_logging without enable_llm_logging must not persist source."""
    session = _make_session(
        tmp_path,
        enable_llm_logging=False,
        redact_prompts=True,
        allow_raw_code_logging=True,
    )
    saved = _save_batch(session, tmp_path)

    assert "full_prompt" not in saved["payload"]
    assert "body" not in saved["payload"]["functions"][0]
    assert "internal_secret_clock" not in saved["raw_text"]


def test_batch_output_artifact_holds_result_metadata(tmp_path: Path) -> None:
    """Classification results stay available for audit and contain no source."""
    session = _make_session(
        tmp_path,
        enable_llm_logging=False,
        redact_prompts=True,
        allow_raw_code_logging=False,
    )
    _save_batch(session, tmp_path)

    output_file = session.llm_dir / "stage_8_pass_2a" / "batches" / "0001_output.json"
    assert output_file.is_file()
    text = output_file.read_text(encoding="utf-8")
    payload = json.loads(text)
    assert payload["response"][0]["y2038_summary"] == "yes"
    assert "internal_secret_clock" not in text


def test_batch_pipeline_privacy_flags_match_standalone_defaults(tmp_path: Path) -> None:
    """tacs repos --llm must get the same privacy posture as tacs scan."""
    from tacs.batch_scan_repos import _build_pipeline, _config_id_to_env_json

    env_config = tmp_path / "env_config.json"
    env_config.write_text(
        json.dumps(_config_id_to_env_json("ilp32_signed_32bit")), encoding="utf-8"
    )
    pipeline = _build_pipeline(
        include_no_findings=False,
        llm="ollama",
        model="none",
        disable_stage1=False,
        detect_y2106=False,
        confidence_floor=0.85,
        timeout_sec=60,
        environment_config_path=str(env_config),
    )
    assert pipeline.enable_llm_logging is False
    assert pipeline.redact_prompts is True
    assert pipeline.allow_raw_code_logging is False

    session = _make_session(
        tmp_path,
        enable_llm_logging=pipeline.enable_llm_logging,
        redact_prompts=pipeline.redact_prompts,
        allow_raw_code_logging=pipeline.allow_raw_code_logging,
    )
    saved = _save_batch(session, tmp_path)
    assert "full_prompt" not in saved["payload"]
    assert "body" not in saved["payload"]["functions"][0]
    assert "internal_secret_clock" not in saved["raw_text"]


def test_llm_none_scan_writes_no_function_batch_artifacts(
    tmp_path: Path, monkeypatch
) -> None:
    """--llm none must not produce an LLM batch artifact tree at all."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "t.c").write_text(
        "#include <time.h>\nint main(void) { time_t t = time(NULL); return (int)t; }\n",
        encoding="utf-8",
    )
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "id": "time_call",
                    "pattern": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "time",
                }
            ]
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--root",
            str(tmp_path),
            "--rules",
            str(rules),
            "--include",
            "*.c",
            "--llm",
            "none",
            "--out",
            str(tmp_path / "out.json"),
            "--log-level",
            "ERROR",
        ],
    )
    assert result.exit_code == 0, result.stderr or result.output
    scans_root = tmp_path / "results" / "scans"
    assert scans_root.is_dir()
    assert not list(scans_root.glob("*/llm/**/batches/*_input.json"))
    assert not list(scans_root.glob("*/llm/**/batches/*_output.json"))
