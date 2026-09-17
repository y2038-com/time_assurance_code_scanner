# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for repository-relative path normalization.

``tacs repos`` scans a clone under ``--cache-dir``, so persisted identifiers used
to carry either the host path or a ``../..`` escape back toward the TACS project.
Everything TACS persists or prints about a scanned file should instead name it the
way the repository does.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

import tacs.batch_scan_repos as bsr
from tacs.cli import app
from tacs.core.function_analyzer import FunctionAnalyzer
from tacs.core.function_schemas import FunctionBatch
from tacs.core.logging_config import configure_logging
from tacs.core.path_utils import (
    display_local_path,
    display_rules_path,
    display_scan_root,
    repo_relative_path,
)
from tacs.core.scan_session import ScanSession
from tacs.core.schema import Candidate

SOURCE = """#include <time.h>

int measure_window(void) {
    time_t now = time(NULL);
    long later = now + 86400;
    return (int)later;
}
"""

RULES = [
    {
        "symbol": "time",
        "risk": "high",
        "category": "function",
        "description": "time",
    }
]


def _write_repo(tmp_path: Path) -> Path:
    """Create a repository whose sources sit in a subdirectory."""
    repo = tmp_path / "repo"
    (repo / "benchmark").mkdir(parents=True)
    (repo / "benchmark" / "timezone_gmt_time.c").write_text(SOURCE, encoding="utf-8")
    return repo


def _write_rules(tmp_path: Path) -> Path:
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps(RULES), encoding="utf-8")
    return rules


# --- normalization rule -----------------------------------------------------


def test_repo_relative_path_names_file_as_repository_does(tmp_path: Path) -> None:
    root = _write_repo(tmp_path)
    source = root / "benchmark" / "timezone_gmt_time.c"

    assert repo_relative_path(str(source), str(root)) == "benchmark/timezone_gmt_time.c"


def test_repo_relative_path_leaves_external_path_alone(tmp_path: Path) -> None:
    """An unrelated file must not be reached with ``..`` or claimed by the repo."""
    root = _write_repo(tmp_path)
    outside = tmp_path / "elsewhere" / "vendor.c"
    outside.parent.mkdir()
    outside.write_text(SOURCE, encoding="utf-8")

    result = repo_relative_path(str(outside), str(root))

    assert result == str(outside)
    assert ".." not in result


def test_repo_relative_path_leaves_relative_path_alone(tmp_path: Path) -> None:
    """Already-normalized paths pass through, so normalizing twice is harmless."""
    root = _write_repo(tmp_path)

    assert repo_relative_path("benchmark/timezone_gmt_time.c", str(root)) == (
        "benchmark/timezone_gmt_time.c"
    )


def test_repo_relative_path_without_root_returns_input(tmp_path: Path) -> None:
    source = _write_repo(tmp_path) / "benchmark" / "timezone_gmt_time.c"

    assert repo_relative_path(str(source), None) == str(source)
    assert repo_relative_path(str(source), "") == str(source)
    assert repo_relative_path(None, str(tmp_path)) == ""


# --- function identifiers ---------------------------------------------------


def _extract(root: Path, *files: Path) -> list:
    analyzer = FunctionAnalyzer(root_path=str(root))
    candidates = [
        Candidate(
            file=str(path),
            line=4,
            symbol="time",
            one_line_snippet="    time_t now = time(NULL);",
            risk="high",
        )
        for path in files
    ]
    return analyzer.extract_functions_with_candidates(candidates)


def test_function_ids_are_repo_relative(tmp_path: Path) -> None:
    root = _write_repo(tmp_path)
    source = root / "benchmark" / "timezone_gmt_time.c"

    functions = _extract(root, source)

    assert functions, "expected the sample function to be extracted"
    for func in functions:
        assert func.function_id.startswith("benchmark/timezone_gmt_time.c@")
        assert ".." not in func.function_id
        assert str(tmp_path) not in func.function_id
        # File access still needs the real location.
        assert Path(func.file_path).is_absolute()


def test_function_id_keeps_external_file_absolute(tmp_path: Path) -> None:
    """A candidate outside the scan root must not look like a repository file."""
    root = _write_repo(tmp_path)
    outside = tmp_path / "elsewhere" / "vendor.c"
    outside.parent.mkdir()
    outside.write_text(SOURCE, encoding="utf-8")

    functions = _extract(root, outside)

    assert functions
    for func in functions:
        assert func.function_id.startswith(str(outside) + "@")


def test_split_function_parts_are_repo_relative(tmp_path: Path) -> None:
    root = _write_repo(tmp_path)
    source = root / "benchmark" / "timezone_gmt_time.c"
    analyzer = FunctionAnalyzer(max_function_lines=2, root_path=str(root))
    candidates = [
        Candidate(
            file=str(source),
            line=4,
            symbol="time",
            one_line_snippet="    time_t now = time(NULL);",
            risk="high",
        )
    ]

    parts = analyzer.extract_functions_with_candidates(candidates)

    assert len(parts) > 1, "expected the function to be split into parts"
    for part in parts:
        assert part.function_id.startswith("benchmark/timezone_gmt_time.c@")
        assert ".." not in part.function_id


# --- persisted scan artifacts -----------------------------------------------


def _run_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, level: str = "INFO"):
    """Scan a repo from a working directory that is not one of its ancestors."""
    root = _write_repo(tmp_path)
    rules = _write_rules(tmp_path)
    workdir = tmp_path / "work"
    workdir.mkdir()
    monkeypatch.chdir(workdir)
    out = workdir / "findings.json"

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--root",
            str(root),
            "--rules",
            str(rules),
            "--include",
            "**/*.c",
            "--llm",
            "none",
            "--out",
            str(out),
            "--log-level",
            level,
        ],
    )
    assert result.exit_code == 0, result.stderr or result.output
    return root, workdir, out, result


def test_scan_findings_paths_are_repo_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _workdir, out, _result = _run_scan(tmp_path, monkeypatch)

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["findings"], "expected at least one finding"
    for finding in payload["findings"]:
        assert finding["file"] == "benchmark/timezone_gmt_time.c"
        assert ".." not in finding["file"]
        assert str(root) not in finding["file"]


def test_scan_candidate_artifacts_are_repo_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, workdir, _out, _result = _run_scan(tmp_path, monkeypatch)

    candidate_files = list(workdir.glob("results/scans/*/ir/candidates.jsonl"))
    assert candidate_files, "expected session candidate artifacts"
    entries = [
        json.loads(line)
        for line in candidate_files[0].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert entries
    for entry in entries:
        assert entry["file"] == "benchmark/timezone_gmt_time.c"
        # The candidate id embeds the path, so it needs normalizing too.
        assert entry["id"].startswith("benchmark/timezone_gmt_time.c:")
        assert str(root) not in entry["id"]


def test_scan_info_output_has_no_host_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A normal INFO scan must not print the scan root or escape paths."""
    root, _workdir, _out, result = _run_scan(tmp_path, monkeypatch)
    err = result.stderr or ""

    assert "Stage 1:" in err, "expected normal INFO progress"
    assert str(root) not in err
    assert "../" not in err


def test_rendered_report_uses_repo_relative_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reports and their --file-glob filter work on repository-relative paths."""
    from tacs.batch_render_reports import main as render_main

    root, _workdir, out, _result = _run_scan(tmp_path, monkeypatch)
    report = tmp_path / "report.txt"

    assert (
        render_main(
            [
                str(out),
                "--format",
                "text",
                "--file-glob",
                "benchmark/*.c",
                "--out",
                str(report),
            ]
        )
        == 0
    )

    text = report.read_text(encoding="utf-8")
    assert "File: benchmark/timezone_gmt_time.c" in text
    assert str(root) not in text


# --- LLM batch manifests ----------------------------------------------------


def test_llm_batch_manifest_paths_are_repo_relative(tmp_path: Path) -> None:
    root = _write_repo(tmp_path)
    source = root / "benchmark" / "timezone_gmt_time.c"
    functions = _extract(root, source)
    session = ScanSession(root_path=str(root), output_base=str(tmp_path / "out"))

    session.save_function_batch(
        pass_name="stage_8_pass_2a",
        batch_num=1,
        function_batch=FunctionBatch(batch_id="b1", functions=functions, iteration=1),
        prompt="prompt text",
    )

    manifests = list(
        (tmp_path / "out").glob("results/scans/*/llm/stage_8_pass_2a/batches/0001_input.json")
    )
    assert manifests, "expected a batch manifest"
    payload = json.loads(manifests[0].read_text(encoding="utf-8"))
    assert payload["functions"]
    for entry in payload["functions"]:
        assert entry["file_path"] == "benchmark/timezone_gmt_time.c"
        assert entry["function_id"].startswith("benchmark/timezone_gmt_time.c@")
        assert ".." not in entry["function_id"]
        assert str(root) not in json.dumps(entry)


# --- Stage 8 / Stage 9 diagnostics ------------------------------------------


def _pass_pipeline(root: Path):
    from tacs.core.pipeline import ScanningPipeline

    scanner_path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "tacs"
        / "python"
        / "y2038scan_fast_json_group.py"
    )
    pipeline = ScanningPipeline(
        scanner_path=str(scanner_path),
        llm_type="none",
        model="none",
        function_first=True,
    )
    # scan() normally sets this; these tests drive a single pass directly.
    pipeline.root_path = str(root)
    pipeline.function_analyzer.root_path = str(root)
    return pipeline


def _abstain_finding(function):
    from tacs.core.schema import Finding, Y2038Issue

    return Finding(
        file=function.file_path,
        region={"start_line": function.start_line, "end_line": function.end_line},
        lines=list(function.candidate_lines),
        symbol=function.symbol,
        confidence=0.4,
        reason="Function analysis: abstain (needs more context: header)",
        source_snippet="time_t now = time(NULL);",
        y2038_issue=Y2038Issue.ABSTAIN,
        needs_more_context=True,
        function_id=function.function_id,
    )


def _run_stage_9(tmp_path: Path, level: str):
    from tacs.core.function_schemas import FunctionAnalysis, Y2038Summary

    class _StubLLMClient:
        llm_type = "stub"
        model = "stub"

        def _build_pass_f3_prompt(self, function_batch):  # noqa: ANN001
            return "stage 9 prompt"

        def analyze_functions_pass_f3(self, function_batch):  # noqa: ANN001
            return [
                FunctionAnalysis(
                    function_id=func.function_id,
                    y2038_summary=Y2038Summary.NO,
                    confidence=0.9,
                    needs_more_context=False,
                )
                for func in function_batch.functions
            ]

    root = _write_repo(tmp_path)
    function = _extract(root, root / "benchmark" / "timezone_gmt_time.c")[0]
    configure_logging(level)
    pipeline = _pass_pipeline(root)
    pipeline.function_llm_client = _StubLLMClient()
    session = ScanSession(root_path=str(root), output_base=str(tmp_path / "out"))

    pipeline._run_pass_f3(
        [_abstain_finding(function)], {function.function_id: function}, session
    )
    return root


def test_stage_9_info_output_has_no_host_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _run_stage_9(tmp_path, "INFO")
    err = capsys.readouterr().err

    assert "Stage 9 results:" in err
    assert str(root) not in err
    assert "../" not in err


def test_stage_9_debug_names_file_as_repository_does(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = _run_stage_9(tmp_path, "DEBUG")
    err = capsys.readouterr().err

    assert "from benchmark/timezone_gmt_time.c" in err
    assert str(root) not in err


# --- batch runs -------------------------------------------------------------


def test_batch_run_findings_are_repo_relative(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Batch findings must not carry the clone cache path."""
    sample = _write_repo(tmp_path)

    def fake_prepare(identity, repo_url: str) -> None:
        identity.cache_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(sample, identity.cache_path, dirs_exist_ok=True)

    monkeypatch.setattr(bsr, "_prepare_repo", fake_prepare)
    monkeypatch.setattr(bsr, "_resolve_ref", lambda repo, ref: ("master", "a" * 40, "master"))
    monkeypatch.setattr(bsr, "_checkout_clean", lambda repo, ref, sha: None)

    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps({"repo_url": "https://example.com/local/sample.git"}) + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "batch_out"
    cache_dir = tmp_path / "cache"

    assert (
        bsr.main(
            [
                "--repos-file",
                str(repos_file),
                "--out-dir",
                str(out_dir),
                "--cache-dir",
                str(cache_dir),
                "--log-level",
                "error",
            ]
        )
        == 0
    )

    findings_files = list(out_dir.glob("*/repos/*/findings.json"))
    assert findings_files, "expected per-repo findings.json"
    payload = json.loads(findings_files[0].read_text(encoding="utf-8"))
    assert payload["findings"], "expected at least one finding"
    for finding in payload["findings"]:
        assert finding["file"] == "benchmark/timezone_gmt_time.c"
        assert str(cache_dir) not in finding["file"]
        assert ".." not in finding["file"]

    candidate_files = list(out_dir.glob("*/repos/*/ir/candidates.jsonl"))
    assert candidate_files, "expected session candidate artifacts"
    text = candidate_files[0].read_text(encoding="utf-8")
    assert str(cache_dir) not in text
    assert "../" not in text

    meta_files = list(out_dir.glob("*/repos/*/meta.json"))
    assert meta_files, "expected per-repo meta.json"
    meta = json.loads(meta_files[0].read_text(encoding="utf-8"))
    assert "cache_path" not in meta
    blob = json.dumps(meta)
    assert str(tmp_path) not in blob
    assert str(cache_dir) not in blob

    findings_meta = payload.get("meta") or {}
    assert findings_meta.get("root") == "."
    rules = findings_meta.get("rules_path", "")
    assert not Path(rules).is_absolute()
    assert "/home/" not in rules

    summaries = list(out_dir.glob("*/summary.json"))
    assert summaries, "expected batch summary.json"
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    args = summary.get("args") or {}
    for key in ("repos_file", "cache_dir", "out_dir"):
        value = args.get(key, "")
        assert value, f"missing args.{key}"
        assert not Path(value).is_absolute(), f"args.{key} should not be absolute: {value}"
        assert str(tmp_path) not in value


# --- display helpers for published metadata ---------------------------------


def test_display_local_path_prefers_cwd_relative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    nested = tmp_path / "results" / "batches" / "run1"
    nested.mkdir(parents=True)
    assert display_local_path(nested) == "results/batches/run1"
    assert display_local_path("already/relative") == "already/relative"
    outside = Path("/tmp/tacs-unrelated-display-path")
    assert display_local_path(outside) == "tacs-unrelated-display-path"


def test_display_rules_path_package_relative(tmp_path: Path) -> None:
    packaged = tmp_path / "site-packages" / "tacs" / "rules" / "y2038_sample_rules.json"
    packaged.parent.mkdir(parents=True)
    packaged.write_text("[]", encoding="utf-8")
    assert display_rules_path(packaged) == "tacs/rules/y2038_sample_rules.json"


def test_display_scan_root_cache_clone_is_dot(tmp_path: Path) -> None:
    cache = tmp_path / ".repo_cache" / "github.com" / "o" / "r.gitwork"
    cache.mkdir(parents=True)
    assert display_scan_root(cache) == "."
