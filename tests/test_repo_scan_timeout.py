# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the hard per-repository timeout in ``tacs repos``.

Two layers are covered. The deadline machinery is exercised with real child
processes and tiny sleeps, because termination and orphan cleanup are only
meaningful against real processes. The batch loop's reaction to a timeout is
driven through the scan seam, so those tests cost nothing in wall clock.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

import tacs.batch_repo_scan as brs
import tacs.batch_scan_repos as bsr
from tacs.batch_repo_scan import (
    STAGED_FINDINGS_NAME,
    RepoScanJob,
    RepoScanOutcome,
    run_child_with_deadline,
)

HAS_FORK = "fork" in multiprocessing.get_all_start_methods()

SOURCE = """#include <time.h>

int measure_window(void) {
    time_t now = time(NULL);
    return (int)now;
}
"""


# --- child targets, importable so any start method can run them -------------


def _finish_quickly(result_path: str) -> None:
    Path(result_path).write_text(json.dumps({"ok": True, "hello": "world"}), encoding="utf-8")


def _sleep_forever(result_path: str) -> None:
    time.sleep(120)
    Path(result_path).write_text(json.dumps({"ok": True}), encoding="utf-8")  # pragma: no cover


def _exit_without_result(result_path: str) -> None:
    os._exit(3)


def _report_process_group(result_path: str) -> None:
    Path(result_path).write_text(
        json.dumps({"pid": os.getpid(), "pgid": os.getpgid(0)}), encoding="utf-8"
    )


def _spawn_grandchild_then_sleep(pid_file: str, result_path: str) -> None:
    """Start a long-lived grandchild, as a real scan does, then block."""
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    Path(pid_file).write_text(str(child.pid), encoding="utf-8")
    time.sleep(120)


def _is_running(pid: int) -> bool:
    """True while the pid is a live process. A reaped zombie counts as gone."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # pragma: no cover - someone else's process
        return True
    status = Path(f"/proc/{pid}/stat")
    if status.is_file():
        try:
            # "... (comm) S ..." - Z is a zombie awaiting reaping, not running.
            return status.read_text(encoding="utf-8").rsplit(")", 1)[1].split()[0] != "Z"
        except (OSError, IndexError):  # pragma: no cover
            return True
    return True


def _wait_until_gone(pid: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _is_running(pid):
            return True
        time.sleep(0.05)
    return False


# --- 1/2/3/10: the deadline machinery ---------------------------------------


def test_child_finishing_before_the_deadline_returns_its_result() -> None:
    outcome = run_child_with_deadline(_finish_quickly, (), deadline_sec=30)

    assert outcome.status == "completed"
    assert outcome.payload == {"ok": True, "hello": "world"}
    assert outcome.exit_code == 0
    assert not outcome.killed


def test_child_outstaying_the_deadline_is_reported_as_timeout() -> None:
    started = time.time()
    outcome = run_child_with_deadline(
        _sleep_forever, (), deadline_sec=0.3, grace_sec=5
    )

    assert outcome.status == "timeout"
    assert outcome.timed_out
    assert outcome.payload == {}
    # The deadline is what ended it, not the child's own 120s sleep.
    assert time.time() - started < 30


def test_timed_out_child_is_actually_terminated() -> None:
    outcome = run_child_with_deadline(
        _sleep_forever, (), deadline_sec=0.3, grace_sec=5
    )

    assert outcome.status == "timeout"
    assert outcome.pid is not None
    assert _wait_until_gone(outcome.pid), f"pid {outcome.pid} survived the timeout"


def test_child_that_exits_without_a_result_is_reported_as_crashed() -> None:
    outcome = run_child_with_deadline(_exit_without_result, (), deadline_sec=30)

    assert outcome.status == "crashed"
    assert outcome.exit_code == 3


@pytest.mark.skipif(not hasattr(os, "killpg"), reason="needs POSIX process groups")
def test_timeout_leaves_no_orphan_grandchild(tmp_path: Path) -> None:
    """A scan's own subprocess must go down with it, not outlive the batch."""
    pid_file = tmp_path / "grandchild.pid"

    outcome = run_child_with_deadline(
        _spawn_grandchild_then_sleep, (str(pid_file),), deadline_sec=1.0, grace_sec=5
    )

    assert outcome.status == "timeout"
    assert pid_file.is_file(), "grandchild never started; test proves nothing"
    grandchild = int(pid_file.read_text(encoding="utf-8").strip())
    assert _wait_until_gone(outcome.pid or -1), "scan child survived"
    assert _wait_until_gone(grandchild), f"orphan grandchild {grandchild} survived"


@pytest.mark.skipif(not hasattr(os, "setsid"), reason="needs POSIX process groups")
def test_child_leads_its_own_process_group() -> None:
    """Leading the group is what lets one signal take down a whole scan.

    It also keeps the parent safe: signalling a group the child had not yet left
    would hit the batch runner itself, so ``_signal_group`` checks membership.
    """
    outcome = run_child_with_deadline(_report_process_group, (), deadline_sec=30)

    assert outcome.status == "completed"
    assert outcome.payload["pgid"] == outcome.payload["pid"], outcome.payload
    assert outcome.payload["pid"] == outcome.pid
    assert outcome.payload["pgid"] != os.getpgid(0), "still in the parent's group"


# --- the batch loop's reaction ----------------------------------------------


def _sample_repo(tmp_path: Path) -> Path:
    sample = tmp_path / "sample_src"
    sample.mkdir(exist_ok=True)
    (sample / "t.c").write_text(SOURCE, encoding="utf-8")
    return sample


def _stub_git(monkeypatch: pytest.MonkeyPatch, sample: Path) -> None:
    def fake_prepare(identity, repo_url: str) -> None:
        identity.cache_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(sample, identity.cache_path, dirs_exist_ok=True)

    monkeypatch.setattr(bsr, "_prepare_repo", fake_prepare)
    monkeypatch.setattr(
        bsr, "_resolve_ref", lambda repo, ref: ("master", "a" * 40, "master")
    )
    monkeypatch.setattr(bsr, "_checkout_clean", lambda repo, ref, sha: None)


def _repos_file(tmp_path: Path, count: int) -> Path:
    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        "\n".join(
            json.dumps({"repo_url": f"https://example.com/local/sample{i}.git"})
            for i in range(count)
        )
        + "\n",
        encoding="utf-8",
    )
    return repos_file


def _run_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    repos: int = 1,
    cli_args: list[str] | None = None,
    out_name: str = "batch_out",
) -> tuple[int, Path]:
    _stub_git(monkeypatch, _sample_repo(tmp_path))
    out_dir = tmp_path / out_name
    code = bsr.main(
        [
            "--repos-file",
            str(_repos_file(tmp_path, repos)),
            "--out-dir",
            str(out_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--log-level",
            "error",
            *(cli_args or []),
        ]
    )
    runs = [p for p in out_dir.iterdir() if p.is_dir() and not p.is_symlink()]
    assert len(runs) == 1, runs
    return code, runs[0]


def _always_timeout(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
    return RepoScanOutcome(status="timeout", pid=-1, duration_sec=deadline_sec, killed=True)


def _statuses(run_dir: Path) -> dict[str, dict]:
    return {
        repo_dir.name: json.loads((repo_dir / "status.json").read_text(encoding="utf-8"))
        for repo_dir in (run_dir / "repos").iterdir()
        if (repo_dir / "status.json").is_file()
    }


def test_timeout_marks_the_repo_and_keeps_its_status_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bsr, "_run_repo_scan", _always_timeout)

    code, run_dir = _run_batch(tmp_path, monkeypatch)

    assert code == 1
    statuses = _statuses(run_dir)
    assert len(statuses) == 1
    status = next(iter(statuses.values()))
    assert status["status"] == "timeout"
    assert status["error_code"] == "SCAN_TIMEOUT"
    assert "3600" in status["error_message"], status["error_message"]
    assert "timeout" in status["error_message"]


def test_timeout_publishes_no_findings_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A findings.json here would read as a scan that finished and found nothing."""
    monkeypatch.setattr(bsr, "_run_repo_scan", _always_timeout)

    _, run_dir = _run_batch(tmp_path, monkeypatch)

    repo_dir = next((run_dir / "repos").iterdir())
    assert not (repo_dir / "findings.json").exists()
    assert not (repo_dir / STAGED_FINDINGS_NAME).exists()


def test_staged_findings_left_by_a_killed_child_are_discarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Half-written findings must not be promoted or left lying around."""

    def timeout_after_staging(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        staged = Path(job.per_repo_dir) / STAGED_FINDINGS_NAME
        staged.write_text('{"meta": {}, "findings": [', encoding="utf-8")
        return RepoScanOutcome(status="timeout", pid=-1, killed=True)

    monkeypatch.setattr(bsr, "_run_repo_scan", timeout_after_staging)

    _, run_dir = _run_batch(tmp_path, monkeypatch)

    repo_dir = next((run_dir / "repos").iterdir())
    assert not (repo_dir / STAGED_FINDINGS_NAME).exists()
    assert not (repo_dir / "findings.json").exists()


def test_timeout_is_reported_in_the_run_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bsr, "_run_repo_scan", _always_timeout)

    _, run_dir = _run_batch(tmp_path, monkeypatch)

    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["timeout"] == 1
    assert summary["counts"]["success"] == 0
    result = summary["results"][0]
    assert result["status"] == "timeout"
    assert result["error_code"] == "SCAN_TIMEOUT"


def test_timeout_logs_one_concise_error_without_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(bsr, "_run_repo_scan", _always_timeout)

    with caplog.at_level("ERROR", logger="tacs.batch_scan_repos"):
        _run_batch(tmp_path, monkeypatch)

    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert "scan exceeded timeout (3600s)" in message
    assert "SCAN_TIMEOUT" in message
    assert errors[0].exc_info is None, "no traceback at ERROR"


def test_next_repo_still_runs_after_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default continue-on-error: one slow repository must not end the batch."""
    calls: list[str] = []
    real_run = bsr._run_repo_scan

    def timeout_first(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        calls.append(job.repo_key)
        if len(calls) == 1:
            return RepoScanOutcome(status="timeout", pid=-1, killed=True)
        return real_run(job, deadline_sec=deadline_sec)

    monkeypatch.setattr(bsr, "_run_repo_scan", timeout_first)

    code, run_dir = _run_batch(tmp_path, monkeypatch, repos=2)

    assert len(calls) == 2, "the second repository never ran"
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["timeout"] == 1
    assert summary["counts"]["success"] == 1
    assert code == 1  # a timeout still fails the run overall


def test_fail_fast_stops_after_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def timeout_always(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        calls.append(job.repo_key)
        return RepoScanOutcome(status="timeout", pid=-1, killed=True)

    monkeypatch.setattr(bsr, "_run_repo_scan", timeout_always)

    code, run_dir = _run_batch(tmp_path, monkeypatch, repos=3, cli_args=["--fail-fast"])

    assert calls == calls[:1], f"stopped after the first timeout, ran {calls}"
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["processed"] == 1
    assert code == 1


def test_no_continue_on_error_stops_after_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def timeout_always(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        calls.append(job.repo_key)
        return RepoScanOutcome(status="timeout", pid=-1, killed=True)

    monkeypatch.setattr(bsr, "_run_repo_scan", timeout_always)

    code, run_dir = _run_batch(
        tmp_path, monkeypatch, repos=3, cli_args=["--no-continue-on-error"]
    )

    assert len(calls) == 1, f"stopped after the first timeout, ran {calls}"
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["processed"] == 1
    assert code == 1


def test_crashed_child_is_failed_not_timed_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        return RepoScanOutcome(status="crashed", exit_code=-9, pid=-1)

    monkeypatch.setattr(bsr, "_run_repo_scan", crash)

    _, run_dir = _run_batch(tmp_path, monkeypatch)

    status = next(iter(_statuses(run_dir).values()))
    assert status["status"] == "failed"
    assert status["error_code"] == "SCAN_CRASHED"


def test_child_reported_scanner_timeout_stays_a_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The inner subprocess timeout kept its old status now that it is reported."""

    def inner_timeout(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        return RepoScanOutcome(
            status="completed",
            payload={
                "ok": False,
                "error_type": "TimeoutExpired",
                "error_message": "Command 'y2038scan' timed out after 300 seconds",
            },
        )

    monkeypatch.setattr(bsr, "_run_repo_scan", inner_timeout)

    _, run_dir = _run_batch(tmp_path, monkeypatch)

    status = next(iter(_statuses(run_dir).values()))
    assert status["status"] == "timeout"
    assert status["error_code"] == "SCAN_TIMEOUT"


def test_child_error_is_reported_as_a_failed_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        return RepoScanOutcome(
            status="completed",
            payload={
                "ok": False,
                "error_type": "ValueError",
                "error_message": "something went wrong",
            },
        )

    monkeypatch.setattr(bsr, "_run_repo_scan", failed)

    _, run_dir = _run_batch(tmp_path, monkeypatch)

    status = next(iter(_statuses(run_dir).values()))
    assert status["status"] == "failed"
    assert status["error_code"] == "SCAN_FAILED"
    assert "something went wrong" in status["error_message"]


def test_child_traceback_is_debug_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The stack came from another process, so it belongs at DEBUG, not ERROR."""

    def failed(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        return RepoScanOutcome(
            status="completed",
            payload={
                "ok": False,
                "error_type": "ValueError",
                "error_message": "something went wrong",
                "error_traceback": 'Traceback (most recent call last):\n  ...\nValueError',
            },
        )

    monkeypatch.setattr(bsr, "_run_repo_scan", failed)

    with caplog.at_level("ERROR", logger="tacs.batch_scan_repos"):
        _run_batch(tmp_path, monkeypatch, out_name="run_error")
    assert not [r for r in caplog.records if "Traceback" in r.getMessage()]

    caplog.clear()
    with caplog.at_level("DEBUG", logger="tacs.batch_scan_repos"):
        _run_batch(tmp_path, monkeypatch, out_name="run_debug")
    detail = [r for r in caplog.records if "Traceback" in r.getMessage()]
    assert len(detail) == 1
    assert detail[0].levelname == "DEBUG"


# --- 9: a successful scan's data still reaches aggregation ------------------


def test_successful_child_result_reaches_batch_aggregation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Metrics and stage stats now cross a process boundary to get here."""
    code, run_dir = _run_batch(tmp_path, monkeypatch)

    assert code == 0
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["counts"]["success"] == 1
    aggregate = summary["aggregates"]["scan_metrics"]
    assert aggregate["total_files_scanned"] >= 1
    assert aggregate["total_lines_scanned"] >= 1
    assert aggregate["repos_with_metrics"] == 1

    status = next(iter(_statuses(run_dir).values()))
    assert status["status"] == "success"
    assert status["scan_metrics"]["total_files"] >= 1
    assert status["stage_stats"]["ir"]["candidates"] >= 1
    assert status["findings_summary"]["total_findings"] >= 0
    repo_dir = next((run_dir / "repos").iterdir())
    assert (repo_dir / "findings.json").is_file()


# --- 2/3 end to end: a real slow scan is really killed ----------------------


class _SleepingPipeline:
    """Stands in for a scan that will not return before the deadline."""

    llm_type = "none"
    model = "none"

    def scan(self, **kwargs):  # noqa: ANN003
        time.sleep(120)  # pragma: no cover - killed first

    def save_results(self, results, path):  # noqa: ANN001 - pragma: no cover
        raise AssertionError("the scan should never have got this far")


@pytest.mark.skipif(not HAS_FORK, reason="the stub reaches the child by fork")
def test_hanging_scan_is_killed_and_the_batch_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: a scan that hangs is cut off at the configured deadline."""
    pids: list[int] = []
    real_run = bsr._run_repo_scan

    def record(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        outcome = real_run(job, deadline_sec=deadline_sec)
        pids.append(outcome.pid or -1)
        return outcome

    monkeypatch.setattr(bsr, "_run_repo_scan", record)
    monkeypatch.setattr(bsr, "_build_pipeline", lambda **kwargs: _SleepingPipeline())

    started = time.time()
    code, run_dir = _run_batch(
        tmp_path, monkeypatch, cli_args=["--scanner-timeout-sec", "1"]
    )
    elapsed = time.time() - started

    assert code == 1
    assert elapsed < 60, f"the deadline did not cut the scan off ({elapsed:.1f}s)"
    status = next(iter(_statuses(run_dir).values()))
    assert status["status"] == "timeout"
    assert status["error_code"] == "SCAN_TIMEOUT"
    assert "1s" in status["error_message"]
    repo_dir = next((run_dir / "repos").iterdir())
    assert not (repo_dir / "findings.json").exists()
    assert _wait_until_gone(pids[0]), f"scan child {pids[0]} survived the deadline"


# --- the two limits stay distinct ------------------------------------------


def test_production_defaults(tmp_path: Path) -> None:
    """Pin the shipped defaults: a short deadline would time out normal work.

    A ten-repository Ollama Cloud validation batch spent 0.4-60s per repository,
    so an hour of headroom per repository and 300s per request is generous
    without being unbounded.
    """
    args = bsr._build_parser().parse_args(["--repos-file", str(tmp_path / "x")])

    assert args.scanner_timeout_sec == 3600
    assert args.request_timeout_sec == 300


def test_standalone_scan_request_timeout_default_matches_batch() -> None:
    """The same clients do the same work, so the inner limit is the same."""
    from tacs.scan_command import main as scan_cmd

    default = {p.name: p.default for p in scan_cmd.params}["request_timeout_sec"]
    assert default == 300
    assert default == bsr._build_parser().parse_args(["--repos-file", "x"]).request_timeout_sec


def test_scan_help_uses_request_timeout_sec_not_timeout_sec() -> None:
    from click.testing import CliRunner

    from tacs.cli import app

    result = CliRunner().invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--request-timeout-sec" in result.output
    assert "--timeout-sec" not in result.output.replace("--request-timeout-sec", "")


def test_deadline_and_request_timeout_are_separate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One wedged request must not be able to spend a whole repository budget."""
    seen: list[tuple[RepoScanJob, float]] = []
    real_run = bsr._run_repo_scan

    def capture(job: RepoScanJob, *, deadline_sec: float) -> RepoScanOutcome:
        seen.append((job, deadline_sec))
        return real_run(job, deadline_sec=deadline_sec)

    monkeypatch.setattr(bsr, "_run_repo_scan", capture)

    _run_batch(
        tmp_path,
        monkeypatch,
        cli_args=["--scanner-timeout-sec", "123", "--request-timeout-sec", "7"],
    )

    job, deadline = seen[0]
    assert deadline == 123
    assert job.request_timeout_sec == 7


def test_request_timeout_reaches_the_llm_client(tmp_path: Path) -> None:
    """The inner limit is only meaningful if the client actually gets it."""
    env_config = tmp_path / "env_config.json"
    env_config.write_text(
        json.dumps(bsr._config_id_to_env_json("ilp32_signed_32bit")), encoding="utf-8"
    )

    pipeline = bsr._build_pipeline(
        include_no_findings=False,
        llm="ollama",
        model="test-model",
        detect_y2106=False,
        confidence_floor=0.7,
        timeout_sec=42,
        environment_config_path=str(env_config),
    )

    assert pipeline.timeout_sec == 42
    assert pipeline.function_llm_client.timeout_sec == 42


def test_both_timeouts_are_recorded_in_the_run_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, run_dir = _run_batch(
        tmp_path,
        monkeypatch,
        cli_args=["--scanner-timeout-sec", "1200", "--request-timeout-sec", "90"],
    )

    args = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))["args"]
    assert args["scanner_timeout_sec"] == 1200
    assert args["request_timeout_sec"] == 90


@pytest.mark.parametrize("option", ["--scanner-timeout-sec", "--request-timeout-sec"])
def test_non_positive_timeouts_are_rejected(tmp_path: Path, option: str) -> None:
    """A zero deadline would time out every repository before it began."""
    repos_file = _repos_file(tmp_path, 1)

    with pytest.raises(SystemExit) as excinfo:
        bsr.main(
            [
                "--repos-file",
                str(repos_file),
                "--out-dir",
                str(tmp_path / "out"),
                option,
                "0",
            ]
        )

    assert option in str(excinfo.value)


# --- grace period -----------------------------------------------------------


def _ignore_sigterm_and_sleep(result_path: str) -> None:
    """Stands in for a scan that does not stop when asked politely."""
    import signal as signal_module

    signal_module.signal(signal_module.SIGTERM, signal_module.SIG_IGN)
    time.sleep(120)


@pytest.mark.skipif(not HAS_FORK, reason="needs POSIX signal semantics")
def test_child_ignoring_sigterm_is_killed_after_the_grace_period() -> None:
    """The deadline starts termination; the grace period bounds the wind-down."""
    started = time.time()
    outcome = run_child_with_deadline(
        _ignore_sigterm_and_sleep, (), deadline_sec=0.3, grace_sec=0.5
    )
    elapsed = time.time() - started

    assert outcome.status == "timeout"
    assert outcome.killed, "SIGTERM was ignored, so a kill was required"
    assert _wait_until_gone(outcome.pid or -1)
    # Deadline plus grace, not deadline alone, and nowhere near the 120s sleep.
    assert 0.3 < elapsed < 20, elapsed


def test_grace_period_is_a_named_constant_the_help_text_quotes() -> None:
    """The documented wind-down and the code must not drift apart."""
    assert brs.DEFAULT_GRACE_SEC == 10.0

    help_text = bsr._build_parser().format_help()
    assert f"{int(brs.DEFAULT_GRACE_SEC)}s more" in help_text
    # The deadline is when termination begins, not the total elapsed time.
    assert "Per-repository scan timeout" in help_text


def test_scanner_timeout_help_scopes_itself_to_the_scan_phase() -> None:
    """Preparation happens in the parent and is not on the clock."""
    help_text = bsr._build_parser().format_help()

    assert "not counted" in help_text
    assert "config detection" in help_text


# --- what the deadline does and does not cover ------------------------------


def test_repository_preparation_is_not_on_the_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It is a per-repository scan timeout: cloning happens before it starts."""
    sample = _sample_repo(tmp_path)

    def slow_prepare(identity, repo_url: str) -> None:
        time.sleep(1.2)  # longer than the deadline below
        identity.cache_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(sample, identity.cache_path, dirs_exist_ok=True)

    _stub_git(monkeypatch, sample)
    monkeypatch.setattr(bsr, "_prepare_repo", slow_prepare)

    out_dir = tmp_path / "batch_out"
    code = bsr.main(
        [
            "--repos-file",
            str(_repos_file(tmp_path, 1)),
            "--out-dir",
            str(out_dir),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--scanner-timeout-sec",
            "1",
            "--log-level",
            "error",
        ]
    )

    assert code == 0, "preparation time was counted against the scan deadline"
    run_dir = next(p for p in out_dir.iterdir() if p.is_dir() and not p.is_symlink())
    assert next(iter(_statuses(run_dir).values()))["status"] == "success"


def test_git_operations_keep_their_own_limit() -> None:
    """Preparation is bounded separately, by the git subprocess timeout."""
    import inspect

    assert inspect.signature(bsr._git).parameters["timeout"].default == 300


# --- status propagation -----------------------------------------------------


def test_render_skips_a_timed_out_repo_and_says_why(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Report tooling must not present a timed-out repository as scanned."""
    import tacs.batch_render_reports as brr

    monkeypatch.setattr(bsr, "_run_repo_scan", _always_timeout)
    _, run_dir = _run_batch(tmp_path, monkeypatch)

    assert brr.main([str(run_dir), "--format", "text"]) == 0

    index = json.loads(
        (run_dir / "reports" / "text" / "index.json").read_text(encoding="utf-8")
    )
    assert index["rendered"] == []
    assert len(index["skipped_or_failed"]) == 1
    reason = index["skipped_or_failed"][0]["reason"]
    assert "timeout" in reason
    assert "SCAN_TIMEOUT" in reason
