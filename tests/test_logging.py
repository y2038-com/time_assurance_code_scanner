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
    # Captured/non-TTY stderr must not contain ANSI color codes
    assert "\033[" not in err


def test_severity_color_formatter_colors_only_levelname() -> None:
    from tacs.core.logging_config import SeverityColorFormatter

    fmt = SeverityColorFormatter(
        fmt="%(levelname)s %(message)s",
        use_color=True,
    )
    warn = logging.LogRecord("tacs", logging.WARNING, __file__, 1, "cfg fallback", (), None)
    err = logging.LogRecord("tacs", logging.ERROR, __file__, 1, "scan failed", (), None)
    info = logging.LogRecord("tacs", logging.INFO, __file__, 1, "ok", (), None)
    warn_out = fmt.format(warn)
    err_out = fmt.format(err)
    info_out = fmt.format(info)
    assert "WARNING" in warn_out
    assert "ERROR" in err_out
    assert warn_out.startswith("\033[33mWARNING\033[0m ")
    assert err_out.startswith("\033[91mERROR\033[0m ")
    assert info_out == "INFO ok"
    assert "\033[" not in info_out


def test_stream_supports_color_respects_no_color(monkeypatch) -> None:
    from tacs.core.logging_config import stream_supports_color

    class _Tty:
        def isatty(self) -> bool:
            return True

    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    assert stream_supports_color(_Tty()) is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert stream_supports_color(_Tty()) is False


def test_status_logger_debug_visible_only_at_debug(capsys) -> None:
    configure_logging("INFO")
    StatusLogger.timestamped_debug("debug-hidden")
    assert "debug-hidden" not in capsys.readouterr().err
    configure_logging("DEBUG")
    StatusLogger.timestamped_debug("debug-visible")
    assert "debug-visible" in capsys.readouterr().err


def _write_time_sample(tmp_path: Path, *, with_time_call: bool = True) -> tuple[Path, Path]:
    """Write a small C sample and rules file; return (rules_path, out_path)."""
    src = tmp_path / "t.c"
    if with_time_call:
        src.write_text(
            "#include <time.h>\n"
            "int main(void) {\n"
            "    time_t t = time(NULL);\n"
            "    return (int)t;\n"
            "}\n"
        )
    else:
        src.write_text("int main(void) { return 0; }\n")
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
    return rules, tmp_path / "out.json"


def test_scan_log_level_warning_suppresses_info(tmp_path: Path) -> None:
    rules, out = _write_time_sample(tmp_path)
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
    rules, out = _write_time_sample(tmp_path)
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
    # Operational INFO lines
    assert "Stage 1: Found" in err
    assert "Stage 3: IR candidate discovery" in err
    assert "Found" in err and "candidates" in err
    assert "Stage 4: After filtering:" in err
    assert "Extracted" in err and "functions containing candidates" in err
    assert "Scan complete:" in err
    assert "confirmed Y2038 issues" in err
    assert "remain unclassified (LLM disabled)" in err
    # Singular candidate wording for count==1
    assert "Found 1 candidate" in err
    assert "After filtering: 1 candidate" in err
    assert "Found 1 candidates" not in err
    assert "After filtering: 1 candidates" not in err
    assert "Total issues:" not in err
    # Demoted sub-stage / skip chatter must not appear at INFO
    assert "Updating rules with discoveries" not in err
    assert "Added 0 new rules" not in err
    assert "discovered rules to scan session" not in err
    assert "Stage 6: Skipped" not in err
    assert "Stage 7: Skipped" not in err
    assert "Stage 8, Pass 2a: Skipped" not in err
    assert "Stage 8, Pass 2b: Skipped" not in err
    assert "Stage 9: Skipped" not in err
    assert "files with I/O function calls" not in err
    assert "I/O-boundary candidates" not in err
    assert "Functionization - extracting" not in err
    assert "Running function-first analysis" not in err


def test_scan_debug_shows_demoted_skip_details(tmp_path: Path) -> None:
    rules, out = _write_time_sample(tmp_path)
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
    err = result.stderr or ""
    assert "DEBUG" in err
    assert "Stage 6: Skipped (migration mode disabled)" in err
    assert "Stage 7: Skipped (LLM disabled)" in err
    assert "Stage 8, Pass 2a: Skipped (LLM disabled)" in err
    assert "Updating rules with discoveries" in err


def test_scan_zero_candidates_uses_clean_wording(tmp_path: Path) -> None:
    rules, out = _write_time_sample(tmp_path, with_time_call=False)
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
    assert "No Y2038 candidate findings detected" in err
    assert "remain unclassified (LLM disabled)" not in err


def test_scan_y2106_breakdown_is_debug_only(tmp_path: Path) -> None:
    rules, out = _write_time_sample(tmp_path)
    runner = CliRunner()
    info = runner.invoke(
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
            "--detect-y2106",
            "--out",
            str(out),
            "--log-level",
            "INFO",
        ],
    )
    assert info.exit_code == 0, info.stderr
    info_err = info.stderr or ""
    assert "Scan complete:" in info_err
    assert "  Y2038:" not in info_err
    assert "  Y2106:" not in info_err
    assert "Total issues:" not in info_err
    assert "\033[" not in info_err

    debug = runner.invoke(
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
            "--detect-y2106",
            "--out",
            str(tmp_path / "out2.json"),
            "--log-level",
            "DEBUG",
        ],
    )
    assert debug.exit_code == 0, debug.stderr
    debug_err = debug.stderr or ""
    assert "  Y2038:" in debug_err
    assert "  Y2106:" in debug_err
    assert "Total issues:" in debug_err


def test_format_no_llm_repo_summary_wording() -> None:
    from tacs.batch_scan_repos import _format_no_llm_repo_summary

    assert (
        _format_no_llm_repo_summary("repo_a", {"total_findings": 0, "yes_findings": 0, "abstain_findings": 0})
        == "repo_a: No Y2038 candidate findings detected"
    )
    assert (
        _format_no_llm_repo_summary(
            "repo_b",
            {"total_findings": 44, "yes_findings": 0, "abstain_findings": 44},
        )
        == "repo_b: 0 confirmed Y2038 issues; 44 candidate findings remain unclassified (LLM disabled)"
    )


def test_scan_debug_shows_debug_lines(tmp_path: Path) -> None:
    rules, out = _write_time_sample(tmp_path)
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
    assert "\033[" not in result.stdout
    assert "\033[" not in err


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


def test_status_logger_always_ignores_log_level(capsys) -> None:
    configure_logging("ERROR")
    StatusLogger.always("[1/2] owner/repo @ master — https://example.com/owner/repo")
    err = capsys.readouterr().err
    assert "[1/2] owner/repo @ master" in err
    assert "https://example.com/owner/repo" in err
    # Timestamped, but not a leveled log record
    assert err.lstrip()[:4].isdigit()
    assert " ERROR " not in err
    assert " INFO " not in err


def test_discovery_prints_respect_warning_threshold(capsys) -> None:
    """Define/arithmetic/alias discovery chatter must not bypass --log-level WARNING."""
    from tacs.core.arithmetic_scanner import ArithmeticMatch, ArithmeticScanner
    from tacs.core.define_scanner import DefineMatch, DefineScanner

    configure_logging("WARNING")
    DefineScanner().print_discovered_defines(
        [
            DefineMatch(
                macro_name="CHEAT_DAYS",
                macro_value="(1199145600 / 24 / 60 / 60)",
                file_path="x.c",
                line_number=1,
                full_line="#define CHEAT_DAYS ...",
                subcheck_type="time_constant",
                confidence=0.9,
                needs_followup_scan=False,
            )
        ]
    )
    ArithmeticScanner().print_discovered_arithmetic(
        [
            ArithmeticMatch(
                operation="+",
                file_path="x.c",
                line_number=1,
                full_line="t + 1",
                time_t_var="t",
                operand="1",
                confidence=0.8,
                risk_level="medium",
            )
        ]
    )
    err = capsys.readouterr().err
    assert "time_constant" not in err
    assert "CHEAT_DAYS" not in err
    assert "Discovered" not in err
    assert "Medium risk" not in err
    assert "arithmetic" not in err.lower()


def test_discovery_prints_visible_and_timestamped_at_debug(capsys) -> None:
    from tacs.core.arithmetic_scanner import ArithmeticMatch, ArithmeticScanner
    from tacs.core.define_scanner import DefineMatch, DefineScanner

    configure_logging("DEBUG")
    DefineScanner().print_discovered_defines(
        [
            DefineMatch(
                macro_name="MAX_EPOLL_TIMEOUT_MSEC",
                macro_value="(35*60*1000)",
                file_path="x.c",
                line_number=1,
                full_line="#define MAX_EPOLL_TIMEOUT_MSEC ...",
                subcheck_type="time_constant",
                confidence=0.9,
                needs_followup_scan=False,
            )
        ]
    )
    ArithmeticScanner().print_discovered_arithmetic(
        [
            ArithmeticMatch(
                operation="+",
                file_path="x.c",
                line_number=1,
                full_line="t + 1",
                time_t_var="t",
                operand="1",
                confidence=0.8,
                risk_level="medium",
            )
        ]
    )
    err = capsys.readouterr().err
    assert "time_constant" in err
    assert "MAX_EPOLL_TIMEOUT_MSEC" in err
    assert "Discovered" in err
    assert "Medium risk" in err
    for line in err.strip().splitlines():
        if "time_constant" in line or "Discovered" in line or "Medium risk" in line:
            assert line.lstrip()[:4].isdigit(), f"untimestamped: {line!r}"
            assert " DEBUG " in line


def test_repos_headers_visible_at_warning_and_error(tmp_path: Path, capsys) -> None:
    repos = tmp_path / "repos.jsonl"
    repos.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "repo_url": "https://github.com/evalEmpire/y2038",
                        "ref": "master",
                        "name": "y2038",
                    }
                ),
                json.dumps(
                    {
                        "repo_url": "https://github.com/example/other",
                        "ref": "main",
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    for level in ("WARNING", "ERROR"):
        code = batch_main(
            [
                "--repos-file",
                str(repos),
                "--out-dir",
                str(out / level.lower()),
                "--dry-run",
                "--log-level",
                level,
            ]
        )
        assert code == 0
        err = capsys.readouterr().err
        assert "[1/2] evalEmpire/y2038 @ master" in err
        assert "https://github.com/evalEmpire/y2038" in err
        assert "[2/2] example/other @ main" in err
        # Headers are timestamped
        header_lines = [ln for ln in err.splitlines() if "[1/2]" in ln or "[2/2]" in ln]
        assert len(header_lines) == 2
        for ln in header_lines:
            assert ln.lstrip()[:4].isdigit()
        # Ordinary batch INFO chatter suppressed
        assert "starting batch run" not in err


def test_repos_warning_suppresses_info_chatter(tmp_path: Path, capsys) -> None:
    repos = tmp_path / "repos.jsonl"
    repos.write_text(
        json.dumps({"repo_url": "https://github.com/acme/demo", "ref": "v1"}) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    code = batch_main(
        [
            "--repos-file",
            str(repos),
            "--out-dir",
            str(out),
            "--dry-run",
            "--log-level",
            "WARNING",
        ]
    )
    assert code == 0
    err = capsys.readouterr().err
    assert "[1/1] acme/demo @ v1" in err
    assert "starting batch run" not in err
    assert " INFO " not in err
    assert " DEBUG " not in err


def test_repos_header_omits_default_when_ref_unspecified(tmp_path: Path, capsys) -> None:
    """Unspecified ref must not render as '@ default' in the always-visible header."""
    repos = tmp_path / "repos.jsonl"
    repos.write_text(
        json.dumps({"repo_url": "https://github.com/evalEmpire/y2038.git"}) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    code = batch_main(
        [
            "--repos-file",
            str(repos),
            "--out-dir",
            str(out),
            "--dry-run",
            "--log-level",
            "WARNING",
        ]
    )
    assert code == 0
    err = capsys.readouterr().err
    assert "[1/1] evalEmpire/y2038 — https://github.com/evalEmpire/y2038.git" in err
    assert "@ default" not in err
    assert " @ " not in err.split("[1/1]", 1)[1].split("—", 1)[0]


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
