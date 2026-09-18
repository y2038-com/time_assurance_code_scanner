# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the per-repository ``scan_overrides`` contract.

Provider selection uses ``llm`` (including ``none``) and ``model``, matching
``tacs scan --llm`` / ``--model``. Former keys ``enable_llm`` and ``llm_type``
are rejected. ``max_file_size`` must reach enumeration and be recorded.

These tests pin the contract: which keys are supported, that per-repo values beat
the batch-wide CLI defaults and reach the constructed client, that an invalid
value fails one repository cleanly, and that the size limit really keeps
oversized files out of the scan and says so in the run's artifacts.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import tacs.batch_scan_repos as bsr
from tacs.core.file_limits import validate_max_file_size
from tacs.core.metrics import calculate_metrics
from tacs.core.pipeline import ScanningPipeline

SCANNER = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tacs"
    / "python"
    / "y2038scan_fast_json_group.py"
)

SOURCE = """#include <time.h>

int measure_window(void) {
    time_t now = time(NULL);
    long later = now + 86400;
    return (int)later;
}
"""


# --- the supported key set --------------------------------------------------


def test_supported_keys_are_exactly_the_documented_contract() -> None:
    assert set(bsr.SUPPORTED_SCAN_OVERRIDES) == {
        "include",
        "exclude",
        "max_file_size",
        "llm",
        "model",
        "min_risk",
        "detect_y2106",
        "confidence_floor",
        "include_no_findings",
        "config_override",
    }


@pytest.mark.parametrize("key", ["llm", "model", "max_file_size", "include", "exclude", "min_risk"])
def test_newly_supported_keys_survive_cleaning(key: str) -> None:
    """These used to be dropped with an "unknown key" warning, or ignored."""
    cleaned, warnings = bsr._scan_overrides({key: "value"})

    assert key in cleaned
    assert warnings == []


@pytest.mark.parametrize(
    "key",
    [
        "enable_llm",
        "llm_type",
        "file_extensions",
        "exclude_patterns",
        "confidence_threshold",
        "disable_stage1",
    ],
)
def test_removed_override_keys_fail_clearly(key: str) -> None:
    with pytest.raises(ValueError, match=key):
        bsr._scan_overrides({key: "anything"})


def test_unknown_keys_are_still_reported_and_dropped() -> None:
    cleaned, warnings = bsr._scan_overrides({"nonsense": 1})

    assert cleaned == {}
    assert any("nonsense" in w for w in warnings)


def test_confidence_floor_is_the_only_confidence_override_key() -> None:
    cleaned, warnings = bsr._scan_overrides({"confidence_floor": 0.9})

    assert cleaned == {"confidence_floor": 0.9}
    assert warnings == []


# --- max_file_size validation ----------------------------------------------


def test_absent_limit_means_unlimited() -> None:
    assert validate_max_file_size(None) is None


def test_positive_integer_limit_is_accepted() -> None:
    assert validate_max_file_size(5_242_880) == 5_242_880


@pytest.mark.parametrize("value", [0, -1, -5_242_880])
def test_non_positive_limits_are_rejected(value: int) -> None:
    with pytest.raises(ValueError, match="greater than 0"):
        validate_max_file_size(value)


@pytest.mark.parametrize("value", ["5242880", 1.5, 5_242_880.0, True, [1], {"a": 1}])
def test_non_integer_limits_are_rejected(value: object) -> None:
    with pytest.raises(ValueError, match="must be an integer"):
        validate_max_file_size(value)


# --- max_file_size enforcement at enumeration ------------------------------


def _sized_repo(tmp_path: Path) -> tuple[Path, int]:
    """A repo with a small file and one padded past it. Returns the small size."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    small = repo / "src" / "small.c"
    small.write_text(SOURCE, encoding="utf-8")
    padding = "\n// " + ("x" * 4000)
    (repo / "src" / "huge.c").write_text(SOURCE + padding, encoding="utf-8")
    return repo, small.stat().st_size


def test_metrics_without_a_limit_count_every_file(tmp_path: Path) -> None:
    repo, _ = _sized_repo(tmp_path)

    metrics = calculate_metrics(str(repo), ["**/*.c"], [])

    assert metrics.total_files == 2
    assert metrics.max_file_size is None
    assert metrics.files_skipped_too_large == 0
    assert metrics.skipped_too_large == []


def test_file_above_the_limit_is_skipped(tmp_path: Path) -> None:
    repo, small_size = _sized_repo(tmp_path)

    metrics = calculate_metrics(str(repo), ["**/*.c"], [], small_size)

    assert metrics.total_files == 1, "the oversized file should not be scanned"
    assert metrics.files_skipped_too_large == 1


def test_file_exactly_at_the_limit_is_scanned(tmp_path: Path) -> None:
    """The threshold is inclusive, so a file of exactly N bytes is not skipped."""
    repo, small_size = _sized_repo(tmp_path)

    at_threshold = calculate_metrics(str(repo), ["**/*.c"], [], small_size)
    one_byte_under = calculate_metrics(str(repo), ["**/*.c"], [], small_size - 1)

    assert at_threshold.total_files == 1
    assert at_threshold.files_skipped_too_large == 1
    assert one_byte_under.total_files == 0
    assert one_byte_under.files_skipped_too_large == 2


def test_oversized_file_does_not_stop_the_others(tmp_path: Path) -> None:
    repo, small_size = _sized_repo(tmp_path)

    metrics = calculate_metrics(str(repo), ["**/*.c"], [], small_size)

    assert metrics.total_files == 1
    assert metrics.total_lines > 0, "the in-limit file was still measured"


def test_skipped_paths_are_recorded_repo_relative(tmp_path: Path) -> None:
    repo, small_size = _sized_repo(tmp_path)

    metrics = calculate_metrics(str(repo), ["**/*.c"], [], small_size)

    assert [entry["path"] for entry in metrics.skipped_too_large] == ["src/huge.c"]
    assert metrics.skipped_too_large[0]["size_bytes"] > small_size
    for entry in metrics.skipped_too_large:
        assert not Path(entry["path"]).is_absolute()
        assert ".." not in entry["path"]
        assert str(tmp_path) not in entry["path"]


def test_recorded_detail_is_capped_but_the_count_stays_exact(tmp_path: Path) -> None:
    """The detail list is for spot checks, not a second manifest of the repo."""
    from tacs.core.file_limits import MAX_RECORDED_SKIPS

    repo = tmp_path / "repo"
    repo.mkdir()
    for index in range(MAX_RECORDED_SKIPS + 5):
        (repo / f"f{index:03d}.c").write_text("x" * 100, encoding="utf-8")

    metrics = calculate_metrics(str(repo), ["**/*.c"], [], 10)

    assert metrics.files_skipped_too_large == MAX_RECORDED_SKIPS + 5
    assert len(metrics.skipped_too_large) == MAX_RECORDED_SKIPS


def test_scanner_subprocess_honors_the_limit(tmp_path: Path) -> None:
    """The IR scan runs out of process, so the limit has to travel with it."""
    import sys

    sys.path.insert(0, str(SCANNER.parent))
    try:
        from y2038scan_fast_json_group import iter_source_files
    finally:
        sys.path.pop(0)

    repo, small_size = _sized_repo(tmp_path)

    unlimited = list(iter_source_files(str(repo), ["**/*.c"], []))
    limited = list(iter_source_files(str(repo), ["**/*.c"], [], small_size))

    assert len(unlimited) == 2
    assert [Path(p).name for p in limited] == ["small.c"]


def test_limit_reaches_every_file_reading_component(tmp_path: Path) -> None:
    """One bypassed enumeration layer would read the file the limit excluded."""
    pipeline = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        max_file_size=4096,
    )

    assert pipeline.max_file_size == 4096
    assert pipeline.ir_adapter.max_file_size == 4096
    assert pipeline.discovery_manager.max_file_size == 4096
    assert pipeline.discovery_manager.typedef_scanner.max_file_size == 4096
    assert pipeline.io_analyzer.max_file_size == 4096


def test_pipeline_rejects_an_invalid_limit() -> None:
    with pytest.raises(ValueError, match="greater than 0"):
        ScanningPipeline(
            scanner_path=str(SCANNER),
            llm_type="none",
            model="none",
            max_file_size=0,
        )


# --- end to end through tacs repos -----------------------------------------


def _run_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    scan_overrides: dict | None = None,
    cli_args: list[str] | None = None,
    repo: Path | None = None,
) -> tuple[int, Path]:
    """Run a batch over one local repository; return (exit code, run directory)."""
    sample = repo if repo is not None else tmp_path / "repo"
    if repo is None:
        (sample / "src").mkdir(parents=True)
        (sample / "src" / "small.c").write_text(SOURCE, encoding="utf-8")

    def fake_prepare(identity, repo_url: str) -> None:
        identity.cache_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(sample, identity.cache_path, dirs_exist_ok=True)

    monkeypatch.setattr(bsr, "_prepare_repo", fake_prepare)
    monkeypatch.setattr(
        bsr, "_resolve_ref", lambda repo, ref: ("master", "a" * 40, "master")
    )
    monkeypatch.setattr(bsr, "_checkout_clean", lambda repo, ref, sha: None)

    entry: dict = {"repo_url": "https://example.com/local/sample.git"}
    if scan_overrides is not None:
        entry["scan_overrides"] = scan_overrides
    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(json.dumps(entry) + "\n", encoding="utf-8")
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
    ] + (cli_args or [])

    code = bsr.main(argv)
    runs = [p for p in out_dir.iterdir() if p.is_dir() and not p.is_symlink()]
    assert len(runs) == 1, f"expected one batch run directory, got {runs}"
    return code, runs[0]


def _repo_dir(run_dir: Path) -> Path:
    repo_dirs = list((run_dir / "repos").iterdir())
    assert len(repo_dirs) == 1, f"expected one per-repo directory, got {repo_dirs}"
    return repo_dirs[0]


def _effective_options(run_dir: Path) -> dict:
    return json.loads((_repo_dir(run_dir) / "meta.json").read_text())["effective_options"]


def _stub_successful_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Complete the scan phase without calling a real provider.

    Precedence tests only need the parent to record the job's effective LLM
    settings; reaching a remote endpoint would make them flaky.
    """
    from tacs.batch_repo_scan import RepoScanOutcome

    def fake_run(job, *, deadline_sec):  # noqa: ANN001
        return RepoScanOutcome(
            status="completed",
            payload={
                "ok": True,
                "findings_summary": {
                    "total_findings": 0,
                    "yes_findings": 0,
                    "no_findings": 0,
                    "abstain_findings": 0,
                },
                "classification_counts": {"yes": 0, "no": 0, "abstain": 0},
                "function_classification_counts": {"yes": 0, "no": 0, "abstain": 0},
                "scan_metrics": {
                    "total_files": 0,
                    "total_lines": 0,
                    "total_chars": 0,
                    "total_words": 0,
                },
                "stage_stats": {
                    "prescan": {"time_t_aliases": 0},
                    "ir": {"candidates": 0, "after_structural_filter": None},
                    "io_boundary": {"candidates": None},
                    "llm": {
                        "total_tokens": 0,
                        "prompt_tokens": 0,
                        "completion_tokens": 0,
                        "requests": 0,
                        "by_pass": {},
                    },
                },
                "effective": {
                    "llm": job.llm,
                    "model": job.model,
                    "max_file_size": job.max_file_size,
                    "request_timeout_sec": job.request_timeout_sec,
                },
            },
        )

    monkeypatch.setattr(bsr, "_run_repo_scan", fake_run)


# --- provider and model precedence -----------------------------------------


def test_without_overrides_the_cli_provider_and_model_are_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_successful_scan(monkeypatch)
    _, run_dir = _run_batch(
        tmp_path,
        monkeypatch,
        cli_args=["--llm", "openai", "--model", "cli-model"],
    )

    options = _effective_options(run_dir)
    assert options["llm"] == "openai"
    assert options["model"] == "cli-model"


def test_per_repo_llm_overrides_the_cli_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_successful_scan(monkeypatch)
    _, run_dir = _run_batch(
        tmp_path,
        monkeypatch,
        scan_overrides={"llm": "anthropic"},
        cli_args=["--llm", "ollama", "--model", "cli-model"],
    )

    options = _effective_options(run_dir)
    assert options["llm"] == "anthropic"
    assert options["model"] == "cli-model", "the model default should be untouched"


def test_per_repo_model_overrides_the_cli_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_successful_scan(monkeypatch)
    _, run_dir = _run_batch(
        tmp_path,
        monkeypatch,
        scan_overrides={"model": "repo-model"},
        cli_args=["--llm", "ollama", "--model", "cli-model"],
    )

    options = _effective_options(run_dir)
    assert options["llm"] == "ollama"
    assert options["model"] == "repo-model"


def test_per_repo_provider_and_model_override_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_successful_scan(monkeypatch)
    _, run_dir = _run_batch(
        tmp_path,
        monkeypatch,
        scan_overrides={"llm": "gemini", "model": "repo-model"},
        cli_args=["--llm", "ollama", "--model", "cli-model"],
    )

    options = _effective_options(run_dir)
    assert options["llm"] == "gemini"
    assert options["model"] == "repo-model"


def test_effective_provider_and_model_reach_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Metadata agreeing with itself is not evidence the scan was configured.

    The scan runs in a child process, so the pipeline object is out of this
    process's reach; the job handed to that child is the crossing point.
    """
    seen: list[tuple] = []
    _stub_successful_scan(monkeypatch)
    stub = bsr._run_repo_scan

    def capture(job, *, deadline_sec):
        outcome = stub(job, deadline_sec=deadline_sec)
        seen.append((job, outcome))
        return outcome

    monkeypatch.setattr(bsr, "_run_repo_scan", capture)

    _run_batch(
        tmp_path,
        monkeypatch,
        scan_overrides={"llm": "gemini", "model": "repo-model"},
        cli_args=["--llm", "ollama", "--model", "cli-model"],
    )

    assert len(seen) == 1
    job, _outcome = seen[0]
    assert job.llm == "gemini"
    assert job.model == "repo-model"


def test_build_pipeline_configures_the_client_from_its_arguments(
    tmp_path: Path,
) -> None:
    """The other half: what _build_pipeline is given is what the client gets."""
    env_config = tmp_path / "env_config.json"
    env_config.write_text(
        json.dumps(bsr._config_id_to_env_json("ilp32_signed_32bit")), encoding="utf-8"
    )

    pipeline = bsr._build_pipeline(
        include_no_findings=False,
        llm="gemini",
        model="repo-model",
        detect_y2106=False,
        confidence_floor=0.7,
        timeout_sec=30,
        environment_config_path=str(env_config),
    )

    assert pipeline.llm_type == "gemini"
    assert pipeline.function_llm_client.llm_type == "gemini"
    assert pipeline.function_llm_client.model == "repo-model"


def test_invalid_provider_fails_that_repo_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, run_dir = _run_batch(
        tmp_path, monkeypatch, scan_overrides={"llm": "not-a-provider"}
    )

    status = json.loads((_repo_dir(run_dir) / "status.json").read_text())
    assert status["status"] == "failed"
    assert status["error_code"] == "INVALID_SCAN_OVERRIDE"
    assert "not-a-provider" in status["error_message"]
    for provider in bsr.SUPPORTED_LLM_PROVIDERS:
        assert provider in status["error_message"]
    assert code != 0 or status["status"] == "failed"


def test_invalid_max_file_size_fails_that_repo_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, run_dir = _run_batch(tmp_path, monkeypatch, scan_overrides={"max_file_size": 0})

    status = json.loads((_repo_dir(run_dir) / "status.json").read_text())
    assert status["status"] == "failed"
    assert status["error_code"] == "INVALID_SCAN_OVERRIDE"
    assert "max_file_size" in status["error_message"]


def test_llm_none_disables_execution_and_records_none_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``llm=none`` is the only batch disable switch; metadata must not name a dormant provider."""
    seen: list[tuple] = []
    real_run = bsr._run_repo_scan

    def capture(job, *, deadline_sec):
        outcome = real_run(job, deadline_sec=deadline_sec)
        seen.append((job, outcome))
        return outcome

    monkeypatch.setattr(bsr, "_run_repo_scan", capture)

    def explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("an LLM request was attempted with llm=none")

    monkeypatch.setattr("requests.post", explode)

    _, run_dir = _run_batch(
        tmp_path,
        monkeypatch,
        scan_overrides={"llm": "none"},
        cli_args=["--llm", "openai", "--model", "repo-model"],
    )

    assert len(seen) == 1
    job, outcome = seen[0]
    assert job.llm == "none"
    assert job.model == "none"
    assert outcome.status == "completed", outcome
    assert outcome.payload["effective"]["llm"] == "none"
    assert outcome.payload["effective"]["model"] == "none"

    options = _effective_options(run_dir)
    assert options["llm"] == "none"
    assert options["model"] == "none"
    assert "enable_llm" not in options
    assert "llm_type" not in options
    assert "llm_executed" not in options

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["args"]["llm"] == "openai"
    assert summary["args"]["model"] == "repo-model"
    assert summary["aggregates"]["llm_enabled_count"] == 0


@pytest.mark.parametrize(
    "removed_key",
    [
        "enable_llm",
        "llm_type",
        "file_extensions",
        "exclude_patterns",
        "confidence_threshold",
        "disable_stage1",
    ],
)
def test_removed_scan_override_keys_fail_the_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, removed_key: str
) -> None:
    _, run_dir = _run_batch(
        tmp_path, monkeypatch, scan_overrides={removed_key: False}
    )

    status = json.loads((_repo_dir(run_dir) / "status.json").read_text())
    assert status["status"] == "failed"
    assert status["error_code"] == "INVALID_SCAN_OVERRIDE"
    assert removed_key in status["error_message"]


# --- include / exclude / min-risk ------------------------------------------


def test_batch_cli_include_exclude_defaults_are_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_successful_scan(monkeypatch)
    _, run_dir = _run_batch(tmp_path, monkeypatch)

    options = _effective_options(run_dir)
    assert options["include"] == ["**/*.c", "**/*.h"]
    assert options["exclude"] == ["**/tests/**"]
    assert options["min_risk"] == "medium"

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["args"]["include"] == ["**/*.c", "**/*.h"]
    assert summary["args"]["exclude"] == ["**/tests/**"]
    assert summary["args"]["min_risk"] == "medium"


def test_per_repo_include_exclude_override_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_successful_scan(monkeypatch)
    seen: list = []
    stub = bsr._run_repo_scan

    def capture(job, *, deadline_sec):
        outcome = stub(job, deadline_sec=deadline_sec)
        seen.append(job)
        return outcome

    monkeypatch.setattr(bsr, "_run_repo_scan", capture)

    _, run_dir = _run_batch(
        tmp_path,
        monkeypatch,
        scan_overrides={
            "include": ["**/*.cpp"],
            "exclude": ["**/vendor/**"],
            "min_risk": "high",
        },
        cli_args=[
            "--include",
            "**/*.c",
            "--exclude",
            "**/tests/**",
            "--min-risk",
            "low",
        ],
    )

    assert len(seen) == 1
    assert seen[0].include_patterns == ["**/*.cpp"]
    assert seen[0].exclude_patterns == ["**/vendor/**"]
    assert seen[0].min_risk == "high"

    options = _effective_options(run_dir)
    assert options["include"] == ["**/*.cpp"]
    assert options["exclude"] == ["**/vendor/**"]
    assert options["min_risk"] == "high"


def test_batch_cli_include_exclude_reach_the_job(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_successful_scan(monkeypatch)
    seen: list = []
    stub = bsr._run_repo_scan

    def capture(job, *, deadline_sec):
        outcome = stub(job, deadline_sec=deadline_sec)
        seen.append(job)
        return outcome

    monkeypatch.setattr(bsr, "_run_repo_scan", capture)

    _run_batch(
        tmp_path,
        monkeypatch,
        cli_args=[
            "--include",
            "src/**/*.c",
            "--include",
            "inc/**/*.h",
            "--exclude",
            "**/third_party/**",
            "--min-risk",
            "low",
        ],
    )

    assert len(seen) == 1
    assert seen[0].include_patterns == ["src/**/*.c", "inc/**/*.h"]
    assert seen[0].exclude_patterns == ["**/third_party/**"]
    assert seen[0].min_risk == "low"


# --- max_file_size end to end ----------------------------------------------


def test_batch_records_the_effective_limit_and_skip_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, small_size = _sized_repo(tmp_path)

    _, run_dir = _run_batch(
        tmp_path,
        monkeypatch,
        scan_overrides={"max_file_size": small_size},
        repo=repo,
    )

    repo_dir = _repo_dir(run_dir)
    options = json.loads((repo_dir / "meta.json").read_text())["effective_options"]
    assert options["max_file_size"] == small_size

    stage_stats = json.loads((repo_dir / "stage_stats.json").read_text())
    assert stage_stats["files"]["max_file_size"] == small_size
    assert stage_stats["files"]["files_skipped_too_large"] == 1

    metrics = json.loads((repo_dir / "metrics.json").read_text())
    assert metrics["files_skipped_too_large"] == 1
    assert [entry["path"] for entry in metrics["skipped_too_large"]] == ["src/huge.c"]
    assert metrics.get("files_skipped_external", 0) == 0


def test_omitted_limit_leaves_the_run_unlimited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, _ = _sized_repo(tmp_path)

    _, run_dir = _run_batch(tmp_path, monkeypatch, repo=repo)

    repo_dir = _repo_dir(run_dir)
    options = json.loads((repo_dir / "meta.json").read_text())["effective_options"]
    assert options["max_file_size"] is None

    stage_stats = json.loads((repo_dir / "stage_stats.json").read_text())
    assert stage_stats["files"]["max_file_size"] is None
    assert stage_stats["files"]["files_skipped_too_large"] == 0

    metrics = json.loads((repo_dir / "metrics.json").read_text())
    assert metrics["total_files"] == 2, "both files scanned when no limit applies"


def test_oversized_file_yields_no_findings_while_others_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The skipped file must not reach parsing, so it cannot produce candidates."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "small.c").write_text(SOURCE, encoding="utf-8")
    huge = repo / "src" / "huge.c"
    huge.write_text(SOURCE + "\n// " + ("x" * 4000), encoding="utf-8")
    limit = (repo / "src" / "small.c").stat().st_size

    _, run_dir = _run_batch(
        tmp_path,
        monkeypatch,
        scan_overrides={"max_file_size": limit},
        repo=repo,
    )

    repo_dir = _repo_dir(run_dir)
    candidates = repo_dir / "ir" / "candidates.jsonl"
    if candidates.exists():
        files = {
            json.loads(line)["file"]
            for line in candidates.read_text().splitlines()
            if line.strip()
        }
        assert "src/huge.c" not in files
        assert "src/small.c" in files, "the in-limit file was still scanned"
