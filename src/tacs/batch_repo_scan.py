# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Run one repository's scan in a child process under a wall-clock deadline.

``tacs repos`` must not let a single repository hang a batch. A deadline can only
be enforced from outside the work: a scan spends its time in C extensions,
provider sockets, and subprocesses, none of which a timer thread or a signal
handler in the same interpreter can reliably interrupt. So the scan phase runs in
a child process, the parent waits for it, and a child that outstays the deadline
is signalled rather than asked to stop.

Two distinct limits meet here, and the names keep them apart:

``deadline_sec``
    The outer, parent-enforced wall clock for the scan phase of one repository.
    This is what ``--scanner-timeout-sec`` means. It is when termination begins,
    not the total elapsed time: see ``DEFAULT_GRACE_SEC``.
``request_timeout_sec``
    The inner limit the pipeline hands to its LLM clients, bounding one request.
    A scan makes as many requests as the code needs, so this never bounds the
    repository. ``--request-timeout-sec`` sets it.

What the deadline covers is the scan phase alone: pipeline construction, the
deterministic scanner, parsing and function analysis, every LLM stage, and the
artifact writes that finish the scan. Cloning, ref resolution, config detection
and override validation run in the parent beforehand and are not counted.

Platform guarantees differ, and the weaker one is worth knowing:

POSIX
    The child leads its own process group, so terminating a scan also reaches
    the scanner subprocess and anything else it started. ``SIGTERM`` first, then
    ``SIGKILL`` if the group is still alive after the grace period.
Windows
    There are no process groups to signal here, so the fallback terminates the
    Python scan child only. A scanner subprocess it had already started may
    outlive it, which makes the descendant half of the guarantee weaker.
"""

from __future__ import annotations

import json
import logging
import multiprocessing
import os
import signal
import tempfile
import time
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

LOGGER = logging.getLogger(__name__)

# How long a child gets to wind down after SIGTERM before it is killed outright.
# The deadline says when termination begins; this says how much longer shutting
# down may take, so a repository can run for deadline + grace in the worst case.
# Ten seconds is enough for a scan to close its files and for the kernel to reap
# the group, without making a wedged repository noticeably slower to abandon.
DEFAULT_GRACE_SEC = 10.0

# The canonical findings file is written under this name and renamed into place,
# so a child killed mid-write cannot leave a half-written findings.json looking
# like a completed scan.
STAGED_FINDINGS_NAME = ".findings.json.partial"


@dataclass(frozen=True)
class RepoScanJob:
    """Everything the scan phase needs, as plain data that survives pickling."""

    repo_key: str
    repo_root: str
    rules_path: str
    per_repo_dir: str
    env_config_path: str
    include_patterns: list[str]
    exclude_patterns: list[str]
    include_no_findings: bool
    enable_llm: bool
    llm_type: str
    model: str
    disable_stage1: bool
    detect_y2106: bool
    confidence_floor: float
    max_file_size: int | None
    # Inner per-operation limit, not the repository deadline. See module docstring.
    request_timeout_sec: int
    log_level: str


@dataclass
class RepoScanOutcome:
    """What the parent learned about a child run."""

    status: str  # "completed" | "timeout" | "crashed"
    payload: dict[str, Any] = field(default_factory=dict)
    exit_code: int | None = None
    pid: int | None = None
    duration_sec: float = 0.0
    killed: bool = False

    @property
    def timed_out(self) -> bool:
        return self.status == "timeout"


# --- the work itself --------------------------------------------------------


def run_repo_scan(job: RepoScanJob) -> dict[str, Any]:
    """Scan one repository and return the data the batch parent aggregates.

    Runs in the child. Imports the batch module lazily: it is the parent's home
    and importing it at module scope would be circular.
    """
    from tacs.batch_scan_repos import (
        _build_pipeline,
        _classification_counts_payload,
        _extract_scan_metrics,
        _extract_stage_stats,
        _format_llm_repo_summary,
        _format_no_llm_repo_summary,
        _parse_findings_summary,
    )

    per_repo_dir = Path(job.per_repo_dir)
    pipeline = _build_pipeline(
        include_no_findings=job.include_no_findings,
        enable_llm=job.enable_llm,
        llm_type=job.llm_type,
        model=job.model,
        disable_stage1=job.disable_stage1,
        detect_y2106=job.detect_y2106,
        confidence_floor=job.confidence_floor,
        timeout_sec=job.request_timeout_sec,
        environment_config_path=job.env_config_path,
        max_file_size=job.max_file_size,
    )

    # The per-repo directory is the scan's artifact root: the batch run id and
    # repo key already identify this scan, so no session-history folder is
    # nested inside it.
    results_obj = pipeline.scan(
        root_path=job.repo_root,
        rules_path=job.rules_path,
        include_patterns=list(job.include_patterns),
        exclude_patterns=list(job.exclude_patterns),
        min_risk="medium",
        session_dir=str(per_repo_dir.resolve()),
    )

    staged = per_repo_dir / STAGED_FINDINGS_NAME
    scan_out = per_repo_dir / "findings.json"
    pipeline.save_results(results_obj, str(staged))
    os.replace(staged, scan_out)

    finding_summary = _parse_findings_summary(scan_out)
    classification_counts = _classification_counts_payload(pipeline)
    # Logged from the child so it still lands right after that repository's scan
    # output, as it did when the scan ran in the parent.
    if not job.enable_llm:
        LOGGER.info("%s", _format_no_llm_repo_summary(per_repo_dir.name, finding_summary))
    else:
        LOGGER.info(
            "%s",
            _format_llm_repo_summary(
                per_repo_dir.name, finding_summary, classification_counts
            ),
        )

    return {
        "findings_summary": finding_summary,
        "classification_counts": classification_counts,
        "scan_metrics": _extract_scan_metrics(results_obj),
        "stage_stats": _extract_stage_stats(per_repo_dir),
        # What the pipeline was actually configured with, so the parent can
        # record effective settings without reaching into the child's objects.
        "effective": {
            "enable_llm": job.enable_llm,
            "llm_type": getattr(pipeline, "llm_type", job.llm_type),
            "model": getattr(pipeline, "model", job.model),
            "max_file_size": job.max_file_size,
            "request_timeout_sec": job.request_timeout_sec,
        },
    }


def repo_scan_child(job_fields: dict[str, Any], result_path: str) -> None:
    """Child entry point: run the scan and leave the result as JSON.

    Must stay importable at module scope and take only picklable arguments, so
    platforms without ``fork`` can start it too.
    """
    payload: dict[str, Any]
    try:
        job = RepoScanJob(**job_fields)
        # Under spawn the child starts with no logging configuration; under fork
        # this is a harmless no-op because configure_logging is idempotent.
        from tacs.core.logging_config import configure_logging

        configure_logging(job.log_level)
        payload = {"ok": True, **run_repo_scan(job)}
    except Exception as exc:
        payload = {
            "ok": False,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
            "error_traceback": traceback.format_exc(),
        }
    try:
        Path(result_path).write_text(json.dumps(payload, default=str), encoding="utf-8")
    except OSError:  # pragma: no cover - parent reports a missing result instead
        pass


# --- running a child under a deadline --------------------------------------


def _grouped_child(
    target: Callable[..., None], args: tuple[Any, ...], result_path: str
) -> None:
    """Put the child in its own process group, then run the target.

    The group is what lets the parent take down a scan together with any
    subprocess it started; signalling the child alone would orphan them.
    """
    if hasattr(os, "setsid"):
        try:
            os.setsid()
        except OSError:  # pragma: no cover - already a group leader
            pass
    target(*args, result_path)


def _context() -> Any:
    """Prefer fork: it starts faster and the child inherits the parent's setup."""
    methods = multiprocessing.get_all_start_methods()
    return multiprocessing.get_context("fork" if "fork" in methods else "spawn")


def _signal_group(proc: Any, sig: int) -> None:
    """Signal the child's whole process group, falling back to the child alone.

    The group is only signalled once the child is confirmed to lead it. Before
    ``setsid()`` runs, the child still shares the parent's group, and signalling
    that group would take down the batch runner itself.
    """
    pid = proc.pid
    if pid is None:  # pragma: no cover - not started
        return
    if hasattr(os, "killpg"):
        try:
            if os.getpgid(pid) == pid:
                os.killpg(pid, sig)
                return
        except OSError:
            pass
    try:
        if sig == getattr(signal, "SIGKILL", signal.SIGTERM):
            proc.kill()
        else:
            proc.terminate()
    except (OSError, ValueError, AttributeError):  # pragma: no cover
        pass


def _stop_child(proc: Any, grace_sec: float) -> bool:
    """Ask the child to exit, then insist. True if it took a kill."""
    _signal_group(proc, signal.SIGTERM)
    proc.join(grace_sec)
    if not proc.is_alive():
        return False
    _signal_group(proc, getattr(signal, "SIGKILL", signal.SIGTERM))
    proc.join(grace_sec)
    return True


def run_child_with_deadline(
    target: Callable[..., None],
    args: Sequence[Any],
    *,
    deadline_sec: float,
    grace_sec: float = DEFAULT_GRACE_SEC,
    name: str | None = None,
) -> RepoScanOutcome:
    """Run ``target(*args, result_path)`` in a child, bounded by a wall clock.

    The child is expected to write its result to ``result_path`` as JSON. A child
    that misses the deadline is stopped and reported as a timeout; one that exits
    without leaving a readable result is reported as crashed.
    """
    ctx = _context()
    with tempfile.TemporaryDirectory(prefix="tacs-repo-scan-") as tmp_dir:
        result_path = Path(tmp_dir) / "result.json"
        proc = ctx.Process(
            target=_grouped_child,
            args=(target, tuple(args), str(result_path)),
            name=name or "tacs-repo-scan",
        )
        started = time.time()
        proc.start()
        pid = proc.pid
        try:
            proc.join(deadline_sec)
            if proc.is_alive():
                killed = _stop_child(proc, grace_sec)
                LOGGER.debug(
                    "child %s exceeded its %.0fs deadline and was %s",
                    pid,
                    deadline_sec,
                    "killed" if killed else "terminated",
                )
                return RepoScanOutcome(
                    status="timeout",
                    exit_code=proc.exitcode,
                    pid=pid,
                    duration_sec=time.time() - started,
                    killed=killed,
                )

            duration = time.time() - started
            payload = _read_result(result_path)
            if payload is None:
                return RepoScanOutcome(
                    status="crashed",
                    exit_code=proc.exitcode,
                    pid=pid,
                    duration_sec=duration,
                )
            return RepoScanOutcome(
                status="completed",
                payload=payload,
                exit_code=proc.exitcode,
                pid=pid,
                duration_sec=duration,
            )
        finally:
            # Never leave the child running or unreaped, whatever happened above.
            if proc.is_alive():  # pragma: no cover - defensive
                _stop_child(proc, grace_sec)
            try:
                proc.close()
            except (ValueError, AttributeError):  # pragma: no cover
                pass


def _read_result(result_path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return payload if isinstance(payload, dict) else None


def run_repo_scan_with_deadline(
    job: RepoScanJob,
    *,
    deadline_sec: float,
    grace_sec: float = DEFAULT_GRACE_SEC,
) -> RepoScanOutcome:
    """Scan one repository in a child process, bounded by ``deadline_sec``."""
    return run_child_with_deadline(
        repo_scan_child,
        (asdict(job),),
        deadline_sec=deadline_sec,
        grace_sec=grace_sec,
        name=f"tacs-scan-{job.repo_key}",
    )


def discard_staged_findings(per_repo_dir: Path) -> None:
    """Remove a staged findings file left behind by an interrupted child."""
    try:
        (per_repo_dir / STAGED_FINDINGS_NAME).unlink()
    except OSError:
        pass
