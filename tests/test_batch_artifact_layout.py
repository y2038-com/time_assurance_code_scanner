# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the flattened ``tacs repos`` per-repo artifact layout.

A batch run identifies each scan by run id and repo key, so the per-repo directory
is the scan's artifact root. These tests pin that shape: no nested
``scan/results/scans/<session-id>/`` tree, one canonical ``findings.json``, and no
session-history furniture (index, latest link, empty stage directories) inside a
batch bundle. Standalone ``tacs scan`` keeps its session history and is covered
here too, so flattening cannot quietly change it.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tacs.core.run_ids import RUN_ID_PATTERN
from click.testing import CliRunner

import tacs.batch_scan_repos as bsr
from tacs.cli import app
from tacs.core.function_schemas import FunctionAnalysis, Y2038Summary

SOURCE = """#include <time.h>

int measure_window(void) {
    time_t now = time(NULL);
    long later = now + 86400;
    return (int)later;
}
"""


def _write_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "benchmark").mkdir(parents=True)
    (repo / "benchmark" / "timezone_gmt_time.c").write_text(SOURCE, encoding="utf-8")
    return repo


class _StubLLMClient:
    """Stands in for FunctionLLMClient so an LLM batch run needs no provider."""

    def __init__(self, summary: Y2038Summary = Y2038Summary.YES) -> None:
        self.summary = summary
        self.llm_type = "stub"
        self.model = "stub"
        self.migration_mode = False

    def _analyses(self, function_batch):  # noqa: ANN001
        return [
            FunctionAnalysis(
                function_id=func.function_id,
                y2038_summary=self.summary,
                confidence=0.95,
                needs_more_context=False,
            )
            for func in function_batch.functions
        ]

    def _build_pass_f1_prompt(self, function_batch):  # noqa: ANN001
        return "stage 8 pass 2a prompt"

    def _build_pass_f2_prompt(self, function_batch, iteration):  # noqa: ANN001
        return "stage 8 pass 2b prompt"

    def _build_pass_f3_prompt(self, function_batch):  # noqa: ANN001
        return "stage 9 prompt"

    def analyze_functions_pass_f1(self, function_batch):  # noqa: ANN001
        return self._analyses(function_batch)

    def analyze_functions_pass_f2(self, function_batch, iteration):  # noqa: ANN001
        return self._analyses(function_batch)

    def analyze_functions_pass_f3(self, function_batch):  # noqa: ANN001
        return self._analyses(function_batch)


def _run_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    enable_llm: bool = False,
    fail_repo: bool = False,
) -> Path:
    """Run a batch over one local repository and return the per-repo directory."""
    sample = _write_repo(tmp_path)

    def fake_prepare(identity, repo_url: str) -> None:
        if fail_repo:
            raise RuntimeError("clone failed: simulated network outage")
        identity.cache_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(sample, identity.cache_path, dirs_exist_ok=True)

    monkeypatch.setattr(bsr, "_prepare_repo", fake_prepare)
    monkeypatch.setattr(
        bsr, "_resolve_ref", lambda repo, ref: ("master", "a" * 40, "master")
    )
    monkeypatch.setattr(bsr, "_checkout_clean", lambda repo, ref, sha: None)

    if enable_llm:
        real_build = bsr._build_pipeline

        def build_with_stub(**kwargs):
            pipeline = real_build(**kwargs)
            pipeline.function_llm_client = _StubLLMClient()
            return pipeline

        monkeypatch.setattr(bsr, "_build_pipeline", build_with_stub)

    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps({"repo_url": "https://example.com/local/sample.git"}) + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "batch_out"

    argv = [
        "--repos-file",
        str(repos_file),
        "--out-dir",
        str(out_dir),
        "--cache-dir",
        str(tmp_path / "cache"),
        "--log-level",
        "error",
    ]
    if enable_llm:
        argv += ["--enable-llm", "--llm-type", "ollama", "--model", "stub"]

    assert bsr.main(argv) == 0

    # out_dir/latest is a symlink to the run directory, so match the run itself.
    runs = [p for p in out_dir.iterdir() if p.is_dir() and not p.is_symlink()]
    assert len(runs) == 1, f"expected one batch run directory, got {runs}"
    repo_dirs = list((runs[0] / "repos").iterdir())
    assert len(repo_dirs) == 1, f"expected one per-repo directory, got {repo_dirs}"
    return repo_dirs[0]


# --- flattened batch layout -------------------------------------------------


def test_batch_repo_has_no_nested_session_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The redundant scan/results/scans/<session-id>/ layer must be gone."""
    repo_dir = _run_batch(tmp_path, monkeypatch)

    assert not (repo_dir / "scan").exists()
    assert not (repo_dir / "results").exists()
    assert not list(repo_dir.glob("**/results/scans"))
    # No per-repo scan-session directory at any depth. Batch identity comes
    # from the run id and repo key, so a nested run-id folder would be the
    # session tree growing back.
    assert not [
        path
        for path in repo_dir.glob("**/*")
        if path.is_dir() and RUN_ID_PATTERN.match(path.name)
    ]


def test_canonical_findings_json_at_repo_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """findings.json sits at the repo root and carries meta plus findings."""
    repo_dir = _run_batch(tmp_path, monkeypatch)

    findings_file = repo_dir / "findings.json"
    assert findings_file.is_file()
    payload = json.loads(findings_file.read_text(encoding="utf-8"))
    assert "meta" in payload and "findings" in payload
    assert payload["findings"], "expected at least one finding"
    assert payload["findings"][0]["file"] == "benchmark/timezone_gmt_time.c"


def test_no_duplicate_findings_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The session's bare-array copy is not retained alongside the canonical file."""
    repo_dir = _run_batch(tmp_path, monkeypatch)

    assert [p.relative_to(repo_dir) for p in repo_dir.glob("**/findings.json")] == [
        Path("findings.json")
    ]
    assert not (repo_dir / "findings").exists()


def test_scan_summary_and_stage_stats_at_repo_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reproducibility artifacts survive flattening at the repo root."""
    repo_dir = _run_batch(tmp_path, monkeypatch)

    for name in (
        "summary.txt",
        "stage_stats.json",
        "config.snapshot.json",
        "metrics.json",
        "scan_meta.json",
    ):
        assert (repo_dir / name).is_file(), f"missing {name}"

    assert (repo_dir / "ir" / "candidates.jsonl").is_file()
    assert (repo_dir / "logs" / "run.log").is_file()


def test_repo_meta_and_scan_meta_do_not_collide(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """meta.json stays repo identity; the scanner's metadata keeps its own file."""
    repo_dir = _run_batch(tmp_path, monkeypatch)

    repo_meta = json.loads((repo_dir / "meta.json").read_text(encoding="utf-8"))
    assert repo_meta["repo_url"] == "https://example.com/local/sample.git"
    assert repo_meta["resolved_ref"] == "master"

    scan_meta = json.loads((repo_dir / "scan_meta.json").read_text(encoding="utf-8"))
    assert scan_meta["scan_id"]
    assert "timing_ms" in scan_meta
    assert scan_meta["version"]["scanner_cli"]


def test_no_index_or_latest_link_inside_batch_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scan history belongs to standalone runs, not a batch bundle."""
    repo_dir = _run_batch(tmp_path, monkeypatch)

    assert not list(repo_dir.glob("**/index.json"))
    assert not list(repo_dir.glob("**/latest"))
    assert [p for p in repo_dir.glob("**/*") if p.is_symlink()] == []


def test_no_llm_run_leaves_no_empty_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A discovery-only run must not publish empty llm/ or artifacts/ shells."""
    repo_dir = _run_batch(tmp_path, monkeypatch)

    assert not (repo_dir / "llm").exists()
    assert not (repo_dir / "artifacts").exists()
    assert not list(repo_dir.glob("**/*_input.json"))

    empty = [
        p.relative_to(repo_dir)
        for p in repo_dir.glob("**/*")
        if p.is_dir() and not any(p.iterdir())
    ]
    assert empty == [], f"empty directories published: {empty}"


def test_no_llm_run_omits_empty_id_mappings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ids.json records cross-pass mappings; nothing writes them, so omit it."""
    repo_dir = _run_batch(tmp_path, monkeypatch)

    assert not (repo_dir / "ids.json").exists()


def test_llm_batch_manifests_sit_under_repo_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LLM artifacts land at repos/<repo-key>/llm/stage_8_pass_2a/batches/."""
    repo_dir = _run_batch(tmp_path, monkeypatch, enable_llm=True)

    manifest = repo_dir / "llm" / "stage_8_pass_2a" / "batches" / "0001_input.json"
    assert manifest.is_file(), sorted(
        str(p.relative_to(repo_dir)) for p in repo_dir.glob("**/*")
    )
    assert not (repo_dir / "scan").exists()

    # Privacy gating is unchanged by the layout move.
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert "full_prompt" not in payload
    assert "body" not in payload["functions"][0]
    assert payload["functions"][0]["file_path"] == "benchmark/timezone_gmt_time.c"


def test_failed_repo_retains_status_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repo that never scanned still gets a per-repo directory and status.json."""
    sample = _write_repo(tmp_path)

    def fake_prepare(identity, repo_url: str) -> None:
        raise RuntimeError("clone failed: simulated network outage")

    monkeypatch.setattr(bsr, "_prepare_repo", fake_prepare)
    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps({"repo_url": "https://example.com/local/sample.git"}) + "\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / "batch_out"

    assert (
        bsr.main(
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
        == 1
    )

    runs = [p for p in out_dir.iterdir() if p.is_dir() and not p.is_symlink()]
    status_files = list(runs[0].glob("repos/*/status.json"))
    assert status_files, "failed repo must still leave status.json"
    status = json.loads(status_files[0].read_text(encoding="utf-8"))
    assert status["status"] == "failed"
    assert status["error_code"] == "CLONE_FAILED"
    assert status["repo_url"] == "https://example.com/local/sample.git"
    assert not (status_files[0].parent / "findings.json").exists()


# --- batch consumers --------------------------------------------------------


def test_stage_stats_extraction_reads_structured_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stage stats come from stage_stats.json, not parsed summary prose."""
    repo_dir = _run_batch(tmp_path, monkeypatch)

    persisted = json.loads((repo_dir / "stage_stats.json").read_text(encoding="utf-8"))
    assert persisted["ir"]["candidates"] > 0
    assert persisted["ir"]["after_structural_filter"] is not None

    extracted = bsr._extract_stage_stats(repo_dir)
    assert extracted["ir"]["candidates"] == persisted["ir"]["candidates"]
    assert (
        extracted["ir"]["after_structural_filter"]
        == persisted["ir"]["after_structural_filter"]
    )

    summary = json.loads(
        (repo_dir.parents[1] / "summary.json").read_text(encoding="utf-8")
    )
    aggregate = summary["aggregates"]["stage_stats"]
    assert aggregate["ir"]["candidates"] == persisted["ir"]["candidates"]
    assert summary["results"][0]["stage_stats"]["ir"]["candidates"] > 0


def test_stage_stats_extraction_tolerates_missing_file(tmp_path: Path) -> None:
    """A repo that failed before scanning aggregates as zeroes, not an error."""
    stats = bsr._extract_stage_stats(tmp_path)

    assert stats["ir"]["candidates"] == 0
    assert stats["io_boundary"]["candidates"] is None
    assert stats["llm"]["by_pass"] == {}


def test_render_reads_flattened_batch_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tacs render finds the canonical findings.json at the repo root."""
    repo_dir = _run_batch(tmp_path, monkeypatch)
    batch_run_dir = repo_dir.parents[1]

    result = CliRunner().invoke(
        app, ["render", str(batch_run_dir), "--format", "text"]
    )

    assert result.exit_code == 0, result.output
    reports = batch_run_dir / "reports" / "text"
    index = json.loads((reports / "index.json").read_text(encoding="utf-8"))
    assert index["counts"]["rendered"] == 1, index
    assert (reports / f"{repo_dir.name}.txt").is_file()
    assert "benchmark/timezone_gmt_time.c" in (
        reports / f"{repo_dir.name}.txt"
    ).read_text(encoding="utf-8")


# --- standalone sessions are unchanged --------------------------------------


def test_standalone_scan_keeps_session_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tacs scan still writes results/scans/<session-id>/ with its own furniture."""
    monkeypatch.chdir(tmp_path)
    repo = _write_repo(tmp_path)
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps([{"symbol": "time", "risk": "high", "category": "function",
                     "description": "time"}]),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--root",
            str(repo),
            "--rules",
            str(rules),
            "--llm",
            "none",
            "--out",
            str(tmp_path / "out.json"),
            "--log-level",
            "ERROR",
        ],
    )
    assert result.exit_code == 0, result.stderr or result.output

    sessions = [
        p
        for p in (tmp_path / "results" / "scans").iterdir()
        if p.is_dir() and not p.is_symlink()
    ]
    assert len(sessions) == 1
    session = sessions[0]

    # Session history furniture that a batch bundle omits.
    assert (session / "meta.json").is_file()
    assert not (session / "scan_meta.json").exists()
    assert (session / "findings" / "findings.json").is_file()
    assert (session / "findings" / "summary.txt").is_file()
    assert (session / "README.txt").is_file()
    assert (session / "ids.json").is_file()
    assert (tmp_path / "results" / "scans" / "latest").is_symlink()
    assert (tmp_path / "results" / "index.json").is_file()

    # The session copy stays a bare findings array; --out holds meta + findings.
    session_findings = json.loads(
        (session / "findings" / "findings.json").read_text(encoding="utf-8")
    )
    assert isinstance(session_findings, list)
    published = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    assert set(published) >= {"meta", "findings"}
    assert len(published["findings"]) == len(session_findings)


def test_standalone_scan_omits_unused_stage_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Lazy directory creation also spares standalone sessions empty shells."""
    monkeypatch.chdir(tmp_path)
    repo = _write_repo(tmp_path)
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps([{"symbol": "time", "risk": "high", "category": "function",
                     "description": "time"}]),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--root",
            str(repo),
            "--rules",
            str(rules),
            "--llm",
            "none",
            "--out",
            str(tmp_path / "out.json"),
            "--log-level",
            "ERROR",
        ],
    )
    assert result.exit_code == 0, result.stderr or result.output

    session = next(
        p
        for p in (tmp_path / "results" / "scans").iterdir()
        if p.is_dir() and not p.is_symlink()
    )
    assert not (session / "llm").exists()
    assert not (session / "artifacts").exists()
