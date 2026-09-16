# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Tests for unified tacs render (single findings + batch run dirs)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from tacs.batch_render_reports import detect_render_mode, main as render_main
from tacs.cli import app


def _minimal_findings() -> dict:
    return {
        "findings": [
            {
                "file": "a.c",
                "region": {"start_line": 10, "end_line": 10},
                "lines": [10],
                "symbol": "time",
                "y2038_issue": "yes",
                "severity": "high",
                "confidence": 0.9,
                "reason": "test finding",
                "source_snippet": "time_t t = time(NULL);",
                "rule": "TIME_T_TRUNCATION",
            }
        ]
    }


def test_detect_render_mode_file_and_batch(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps(_minimal_findings()), encoding="utf-8")
    mode, target = detect_render_mode(findings)
    assert mode == "single"
    assert target == findings.resolve() or target == findings

    batch = tmp_path / "run"
    (batch / "repos" / "r1").mkdir(parents=True)
    mode, target = detect_render_mode(batch)
    assert mode == "batch"
    assert target == batch.resolve() or target == batch


def test_detect_render_mode_session_dir(tmp_path: Path) -> None:
    session = tmp_path / "scan-session"
    nested = session / "findings" / "findings.json"
    nested.parent.mkdir(parents=True)
    nested.write_text(json.dumps(_minimal_findings()), encoding="utf-8")
    mode, target = detect_render_mode(session)
    assert mode == "single"
    assert target == nested.resolve() or target == nested


def test_tacs_render_single_text_stdout(tmp_path: Path) -> None:
    findings = tmp_path / "out.json"
    findings.write_text(json.dumps(_minimal_findings()), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(app, ["render", str(findings), "--format", "text"])
    assert result.exit_code == 0, result.output + (result.stderr or "")
    assert "Finding" in result.stdout or "a.c" in result.stdout
    assert "\033[" not in result.stdout


def test_tacs_render_single_html_writes_default(tmp_path: Path) -> None:
    findings = tmp_path / "eval_findings.json"
    findings.write_text(json.dumps(_minimal_findings()), encoding="utf-8")
    code = render_main([str(findings), "--format", "html", "--log-level", "WARNING"])
    assert code == 0
    html = tmp_path / "eval_findings_report.html"
    assert html.is_file()
    assert "Finding" in html.read_text(encoding="utf-8")


def test_tacs_render_batch_compat_alias(tmp_path: Path) -> None:
    batch = tmp_path / "20260101T000000Z_aaaaaa"
    repo = batch / "repos" / "github__acme__demo__main"
    repo.mkdir(parents=True)
    (repo / "findings.json").write_text(json.dumps(_minimal_findings()), encoding="utf-8")
    out_dir = tmp_path / "reports"
    code = render_main(
        [
            "--batch-run-dir",
            str(batch),
            "--format",
            "text",
            "--out-dir",
            str(out_dir),
            "--log-level",
            "WARNING",
        ]
    )
    assert code == 0
    assert (out_dir / "index.json").is_file()
    assert (out_dir / "github__acme__demo__main.txt").is_file()


def test_tacs_render_batch_progress_headers_always_visible(tmp_path: Path, capsys) -> None:
    """Per-repo render headers must appear even at ERROR log level."""
    batch = tmp_path / "run"
    for name in ("repo_a", "repo_b"):
        repo = batch / "repos" / name
        repo.mkdir(parents=True)
        (repo / "findings.json").write_text(
            json.dumps(_minimal_findings()), encoding="utf-8"
        )
    code = render_main(
        [str(batch), "--format", "text", "--log-level", "ERROR"]
    )
    assert code == 0
    err = capsys.readouterr().err
    assert "[1/2] repo_a" in err
    assert "[2/2] repo_b" in err
    assert "Rendering" not in err  # INFO summary suppressed at ERROR
    header_lines = [ln for ln in err.splitlines() if "[1/2]" in ln or "[2/2]" in ln]
    assert len(header_lines) == 2
    for ln in header_lines:
        assert ln.lstrip()[:4].isdigit()
    batch = tmp_path / "runid"
    repo = batch / "repos" / "r1"
    repo.mkdir(parents=True)
    (repo / "findings.json").write_text(
        json.dumps(_minimal_findings()), encoding="utf-8"
    )
    code = render_main([str(batch), "--format", "text", "--log-level", "ERROR"])
    assert code == 0
    reports = batch / "reports" / "text"
    assert (reports / "index.json").is_file()


def test_tacs_render_batch_reads_pre_flattening_layout(tmp_path: Path) -> None:
    """Batch runs recorded before the per-repo flattening still render."""
    batch = tmp_path / "legacy_run"
    scan = batch / "repos" / "r1" / "scan"
    scan.mkdir(parents=True)
    (scan / "findings.json").write_text(
        json.dumps(_minimal_findings()), encoding="utf-8"
    )
    code = render_main([str(batch), "--format", "text", "--log-level", "ERROR"])
    assert code == 0
    reports = batch / "reports" / "text"
    assert (reports / "r1.txt").is_file()


def test_tacs_render_rejects_out_dir_on_single(tmp_path: Path) -> None:
    findings = tmp_path / "f.json"
    findings.write_text(json.dumps(_minimal_findings()), encoding="utf-8")
    try:
        render_main([str(findings), "--format", "text", "--out-dir", str(tmp_path / "x")])
    except SystemExit as exc:
        assert "--out-dir" in str(exc.code)
    else:
        raise AssertionError("expected SystemExit")


def test_tacs_render_rejects_finding_on_batch(tmp_path: Path) -> None:
    batch = tmp_path / "run"
    (batch / "repos" / "r1").mkdir(parents=True)
    (batch / "repos" / "r1" / "findings.json").write_text(
        json.dumps(_minimal_findings()), encoding="utf-8"
    )
    try:
        render_main([str(batch), "--format", "text", "--finding", "1"])
    except SystemExit as exc:
        assert "--finding" in str(exc.code)
    else:
        raise AssertionError("expected SystemExit")


def test_tacs_render_missing_path_clear_error(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"
    try:
        render_main([str(missing), "--format", "text"])
    except SystemExit as exc:
        assert "not found" in str(exc.code).lower()
        assert "Traceback" not in str(exc.code)
    else:
        raise AssertionError("expected SystemExit")
