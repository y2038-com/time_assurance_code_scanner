# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""CLI adapter tests for argparse-backed subcommands."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from tacs.batch_scan_repos import main as batch_main
from tacs.cli import app


def test_batch_scan_repos_main_accepts_argv_help() -> None:
    """batch_scan_repos.main must accept argv like the report renderer."""
    try:
        batch_main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("expected SystemExit(0) from --help")


def test_tacs_repos_forwards_argv_to_batch_main(tmp_path: Path) -> None:
    """tacs repos must forward Click extra args into batch_scan_repos.main(argv)."""
    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text("", encoding="utf-8")
    out_dir = tmp_path / "batch_out"

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "repos",
            "--repos-file",
            str(repos_file),
            "--out-dir",
            str(out_dir),
            "--dry-run",
            "--limit",
            "0",
        ],
    )
    assert result.exception is None, result.exception
    assert result.exit_code == 0, result.output
    summaries = list(out_dir.glob("*/summary.json"))
    assert summaries, "expected batch summary under --out-dir"
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    assert summary["args"]["enable_llm"] is False, (
        "batch LLM must be opt-in by default (privacy-safe)"
    )


def test_batch_pipeline_uses_packaged_tacs_scanner() -> None:
    """Batch scans must resolve y2038scan from src/tacs/python/, not pre-split src/scanner/."""
    from tacs.batch_scan_repos import _build_pipeline

    pipeline = _build_pipeline(
        include_no_findings=False,
        enable_llm=False,
        llm_type="ollama",
        model="none",
        disable_stage1=True,
        detect_y2106=True,
        confidence_floor=0.85,
        timeout_sec=60,
    )
    path = Path(pipeline.scanner_path)
    assert path.is_file(), path
    assert path.name == "y2038scan_fast_json_group.py"
    assert path.parent.name == "python"
    assert path.parent.parent.name == "tacs"
    assert "scanner" not in path.parts


def test_tacs_repos_missing_repos_file_clear_error(tmp_path: Path) -> None:
    """Missing --repos-file should fail with a clear message, not a traceback."""
    missing = tmp_path / "does_not_exist.jsonl"
    out_dir = tmp_path / "batch_out"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "repos",
            "--repos-file",
            str(missing),
            "--out-dir",
            str(out_dir),
            "--dry-run",
        ],
    )
    assert result.exit_code != 0
    combined = (result.output or "") + (result.stderr or "") + str(result.exception or "")
    assert "--repos-file not found" in combined
    assert str(missing.resolve()) in combined or str(missing) in combined
    assert "Traceback" not in combined
    assert not out_dir.exists() or not any(out_dir.iterdir())


def test_batch_main_missing_repos_file_system_exit(tmp_path: Path) -> None:
    missing = tmp_path / "missing.jsonl"
    try:
        batch_main(
            [
                "--repos-file",
                str(missing),
                "--out-dir",
                str(tmp_path / "out"),
                "--dry-run",
            ]
        )
    except SystemExit as exc:
        assert exc.code != 0
        assert isinstance(exc.code, str)
        assert "--repos-file not found" in exc.code
        assert "Traceback" not in exc.code
    else:
        raise AssertionError("expected SystemExit for missing repos file")


def test_tacs_repos_help_shows_argparse_options() -> None:
    """tacs repos --help must surface argparse flags, not thin Click wrapper help."""
    runner = CliRunner()
    result = runner.invoke(app, ["repos", "--help"])
    assert result.exit_code == 0, result.output
    assert "--repos-file" in result.output
    assert "--enable-llm" in result.output
    assert "Usage: app repos" not in result.output


def test_tacs_render_help_shows_argparse_options() -> None:
    """tacs render --help must surface argparse flags, not thin Click wrapper help."""
    runner = CliRunner()
    result = runner.invoke(app, ["render", "--help"])
    assert result.exit_code == 0, result.output
    assert "--batch-run-dir" in result.output
    assert "--format" in result.output
    assert "Usage: app render" not in result.output
