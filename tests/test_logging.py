# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for CLI log-level behavior."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from tacs.batch_scan_repos import main as batch_main
from tacs.cli import app
from tacs.core.logging_config import configure_logging, get_logger, resolve_log_level
from tacs.core.status_logger import StatusLogger


def test_resolve_log_level_verbose_and_precedence() -> None:
    assert resolve_log_level() == "INFO"
    assert resolve_log_level(verbose=True) == "DEBUG"
    assert resolve_log_level(log_level="warning", verbose=True) == "WARNING"
    assert resolve_log_level(log_level="error") == "ERROR"


def test_configure_logging_no_duplicate_handlers() -> None:
    configure_logging("INFO")
    configure_logging("DEBUG")
    configure_logging("WARNING")
    logger = get_logger("tacs")
    ours = [h for h in logger.handlers if getattr(h, "_tacs_console_handler", False)]
    assert len(ours) == 1


def test_status_logger_respects_warning_level(capsys) -> None:
    configure_logging("WARNING")
    StatusLogger.timestamped_print("info-should-hide")
    StatusLogger.timestamped_warning("warn-should-show")
    StatusLogger.timestamped_error("error-should-show")
    err = capsys.readouterr().err
    assert "info-should-hide" not in err
    assert "warn-should-show" in err
    assert "error-should-show" in err
    assert "WARNING" in err
    assert "ERROR" in err


def test_status_logger_debug_visible_only_at_debug(capsys) -> None:
    configure_logging("INFO")
    StatusLogger.timestamped_debug("debug-hidden")
    assert "debug-hidden" not in capsys.readouterr().err
    configure_logging("DEBUG")
    StatusLogger.timestamped_debug("debug-visible")
    assert "debug-visible" in capsys.readouterr().err


def test_scan_log_level_warning_suppresses_info(tmp_path: Path) -> None:
    src = tmp_path / "t.c"
    src.write_text("#include <time.h>\nint main(){ time_t t=time(NULL); return 0; }\n")
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "symbol": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "time",
                }
            ]
        )
    )
    out = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(
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
            str(out),
            "--log-level",
            "WARNING",
        ],
    )
    assert result.exit_code == 0, result.output + (result.stderr or "")
    # Stage banners are INFO and should be absent on stderr at WARNING
    assert "Stage 1:" not in (result.stderr or "")
    assert "Stage 3:" not in (result.stderr or "")
    assert out.exists()


def test_scan_default_info_shows_stages(tmp_path: Path) -> None:
    src = tmp_path / "t.c"
    src.write_text("#include <time.h>\nint main(){ time_t t=time(NULL); return 0; }\n")
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "symbol": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "time",
                }
            ]
        )
    )
    out = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(
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
            str(out),
            "--log-level",
            "INFO",
        ],
    )
    assert result.exit_code == 0, result.stderr
    err = result.stderr or ""
    assert "Stage 1:" in err
    assert "confirmed Y2038 issues" in err
    assert "remain unclassified (LLM disabled)" in err or "Scan complete" in err


def test_scan_debug_shows_debug_lines(tmp_path: Path) -> None:
    src = tmp_path / "t.c"
    src.write_text("#include <time.h>\nint main(){ time_t t=time(NULL); return 0; }\n")
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "symbol": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "time",
                }
            ]
        )
    )
    out = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(
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
            str(out),
            "--log-level",
            "DEBUG",
        ],
    )
    assert result.exit_code == 0, result.stderr
    assert "DEBUG" in (result.stderr or "")


def test_detect_json_stdout_clean_with_diagnostics(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["detect", str(tmp_path), "--format", "json", "--log-level", "INFO"],
    )
    assert result.exit_code == 0, result.stderr or result.output
    payload = json.loads(result.stdout)
    assert isinstance(payload, dict)
    err = result.stderr or ""
    assert "WARNING" in err or "experimental" in err.lower()
    assert "WARNING" not in result.stdout
    assert not result.stdout.lstrip().startswith("20")


def test_detect_error_level_suppresses_experimental_warning(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["detect", str(tmp_path), "--format", "json", "--log-level", "ERROR"],
    )
    err = result.stderr or ""
    assert "experimental" not in err.lower()


def test_repos_verbose_enables_debug_in_summary(tmp_path: Path) -> None:
    repos = tmp_path / "repos.jsonl"
    repos.write_text("", encoding="utf-8")
    out = tmp_path / "out"
    code = batch_main(
        [
            "--repos-file",
            str(repos),
            "--out-dir",
            str(out),
            "--dry-run",
            "--limit",
            "0",
            "--verbose",
        ]
    )
    assert code == 0
    summary = json.loads(next(out.glob("*/summary.json")).read_text())
    assert summary["args"]["log_level"] == "DEBUG"


def test_repos_log_level_overrides_verbose(tmp_path: Path) -> None:
    repos = tmp_path / "repos.jsonl"
    repos.write_text("", encoding="utf-8")
    out = tmp_path / "out"
    code = batch_main(
        [
            "--repos-file",
            str(repos),
            "--out-dir",
            str(out),
            "--dry-run",
            "--limit",
            "0",
            "--verbose",
            "--log-level",
            "WARNING",
        ]
    )
    assert code == 0
    summary = json.loads(next(out.glob("*/summary.json")).read_text())
    assert summary["args"]["log_level"] == "WARNING"


def test_config_override_skips_autodetect() -> None:
    """Valid config_override must not call detect_fn or emit the experimental warning."""
    from tacs.batch_scan_repos import _resolve_effective_config

    called = {"n": 0}

    def _fake_detect(*_a, **_k):
        called["n"] += 1
        return {"experimental": True, "overall_confidence": 0.99}

    configure_logging("INFO")
    log = logging.getLogger("tacs.batch_scan_repos")
    with patch.object(log, "warning") as warn:
        effective, source, reason, payload = _resolve_effective_config(
            explicit_config_id="ilp32_signed_32bit",
            repo_dir=Path("."),
            fallback_config_id="ilp32_signed_32bit",
            config_min_confidence=0.7,
            detect_fn=_fake_detect,
        )
    assert called["n"] == 0
    warn.assert_not_called()
    assert source == "explicit"
    assert effective == "ilp32_signed_32bit"
    assert payload.get("skipped") is True
    assert "override" in reason

    with patch.object(log, "warning") as warn:
        _resolve_effective_config(
            explicit_config_id=None,
            repo_dir=Path("."),
            fallback_config_id="ilp32_signed_32bit",
            config_min_confidence=0.7,
            detect_fn=_fake_detect,
        )
    assert called["n"] == 1
    warn.assert_called()
