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


def test_batch_pipeline_uses_packaged_tacs_scanner(tmp_path: Path) -> None:
    """Batch scans must resolve y2038scan from src/tacs/python/, not pre-split src/scanner/."""
    from tacs.batch_scan_repos import _build_pipeline, _config_id_to_env_json

    env_config = tmp_path / "env_config.json"
    env_config.write_text(
        json.dumps(_config_id_to_env_json("ilp32_signed_32bit")), encoding="utf-8"
    )

    pipeline = _build_pipeline(
        include_no_findings=False,
        enable_llm=False,
        llm_type="ollama",
        model="none",
        disable_stage1=True,
        detect_y2106=True,
        confidence_floor=0.85,
        timeout_sec=60,
        environment_config_path=str(env_config),
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


def test_repo_cache_dir_is_gitignored() -> None:
    """tacs repos retains clones in .repo_cache; it must never be committable."""
    repo_root = Path(__file__).resolve().parents[1]
    ignore_lines = {
        line.strip()
        for line in (repo_root / ".gitignore").read_text(encoding="utf-8").splitlines()
    }
    assert ".repo_cache/" in ignore_lines or ".repo_cache" in ignore_lines


def test_cache_dir_help_discloses_retention() -> None:
    """--cache-dir help must state that clones are kept, not treated as ephemeral."""
    runner = CliRunner()
    result = runner.invoke(app, ["repos", "--help"])
    assert result.exit_code == 0, result.output
    help_text = " ".join(result.output.split())
    assert "--cache-dir" in help_text
    assert "retained" in help_text
    assert ".repo_cache" in help_text


def test_batch_default_out_dir_is_results_batch_runs(tmp_path: Path, monkeypatch) -> None:
    """Omitting --out-dir must write under results/batch_runs, not top-level batch_runs/."""
    monkeypatch.chdir(tmp_path)
    repos = tmp_path / "repos.jsonl"
    repos.write_text("", encoding="utf-8")
    code = batch_main(
        [
            "--repos-file",
            str(repos),
            "--dry-run",
            "--limit",
            "0",
        ]
    )
    assert code == 0
    batch_root = tmp_path / "results" / "batch_runs"
    assert batch_root.is_dir()
    summaries = list(batch_root.glob("*/summary.json"))
    assert summaries, "expected summary under results/batch_runs/<run_id>/"
    assert not (tmp_path / "batch_runs").exists()


def test_batch_explicit_out_dir_not_forced_under_results(tmp_path: Path) -> None:
    repos = tmp_path / "repos.jsonl"
    repos.write_text("", encoding="utf-8")
    custom = tmp_path / "custom_batch"
    code = batch_main(
        [
            "--repos-file",
            str(repos),
            "--out-dir",
            str(custom),
            "--dry-run",
            "--limit",
            "0",
        ]
    )
    assert code == 0
    assert list(custom.glob("*/summary.json")), "explicit --out-dir must be used as-is"
    assert not (tmp_path / "results" / "batch_runs").exists()


def test_tacs_repos_help_shows_argparse_options() -> None:
    """tacs repos --help must surface argparse flags, not thin Click wrapper help."""
    runner = CliRunner()
    result = runner.invoke(app, ["repos", "--help"])
    assert result.exit_code == 0, result.output
    assert "--repos-file" in result.output
    assert "--enable-llm" in result.output
    assert "results/batch_runs" in result.output
    assert "Usage: app repos" not in result.output


def test_tacs_render_help_shows_argparse_options() -> None:
    """tacs render --help must surface argparse flags, not thin Click wrapper help."""
    runner = CliRunner()
    result = runner.invoke(app, ["render", "--help"])
    assert result.exit_code == 0, result.output
    assert "findings JSON" in result.output.lower() or "Findings JSON" in result.output
    assert "--format" in result.output
    assert "--batch-run-dir" in result.output
    assert "Usage: app render" not in result.output
