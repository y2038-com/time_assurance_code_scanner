# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the ``latest`` convenience symlink."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import tacs.batch_scan_repos as bsr
from tacs.core.path_utils import update_latest_symlink

SOURCE = """#include <time.h>

int measure_window(void) {
    time_t now = time(NULL);
    return (int)now;
}
"""


# --- the helper -------------------------------------------------------------


def test_update_latest_symlink_points_at_target(tmp_path: Path) -> None:
    target = tmp_path / "run_a"
    target.mkdir()
    link = tmp_path / "latest"

    assert update_latest_symlink(link, target) is True
    assert link.is_symlink()
    assert link.resolve() == target.resolve()


def test_update_latest_symlink_target_is_relative(tmp_path: Path) -> None:
    """A relative target keeps the output tree movable."""
    target = tmp_path / "run_a"
    target.mkdir()
    link = tmp_path / "latest"

    update_latest_symlink(link, target)

    assert link.readlink() == Path("run_a")


def test_update_latest_symlink_replaces_existing_link(tmp_path: Path) -> None:
    first = tmp_path / "run_a"
    second = tmp_path / "run_b"
    first.mkdir()
    second.mkdir()
    link = tmp_path / "latest"

    update_latest_symlink(link, first)
    assert update_latest_symlink(link, second) is True

    assert link.resolve() == second.resolve()
    # Repointing must not disturb the run it used to reference.
    assert first.is_dir()


def test_update_latest_symlink_replaces_dangling_link(tmp_path: Path) -> None:
    """exists() is False for a dangling link, so it needs handling on its own."""
    gone = tmp_path / "run_gone"
    gone.mkdir()
    link = tmp_path / "latest"
    update_latest_symlink(link, gone)
    shutil.rmtree(gone)
    assert link.is_symlink() and not link.exists()

    target = tmp_path / "run_new"
    target.mkdir()

    assert update_latest_symlink(link, target) is True
    assert link.resolve() == target.resolve()


def test_update_latest_symlink_declines_real_directory(tmp_path: Path) -> None:
    """A real directory holding the name is left alone rather than removed."""
    link = tmp_path / "latest"
    link.mkdir()
    (link / "keep.txt").write_text("keep", encoding="utf-8")
    target = tmp_path / "run_a"
    target.mkdir()

    assert update_latest_symlink(link, target) is False
    assert (link / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_update_latest_symlink_creates_missing_parent(tmp_path: Path) -> None:
    target = tmp_path / "run_a"
    target.mkdir()
    link = tmp_path / "nested" / "deeper" / "latest"

    assert update_latest_symlink(link, target) is True
    assert link.resolve() == target.resolve()


# --- batch runs -------------------------------------------------------------


def _stub_git(monkeypatch: pytest.MonkeyPatch, sample: Path) -> None:
    def fake_prepare(identity, repo_url: str) -> None:
        identity.cache_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(sample, identity.cache_path, dirs_exist_ok=True)

    monkeypatch.setattr(bsr, "_prepare_repo", fake_prepare)
    monkeypatch.setattr(bsr, "_resolve_ref", lambda repo, ref: ("master", "a" * 40, "master"))
    monkeypatch.setattr(bsr, "_checkout_clean", lambda repo, ref, sha: None)


def _repos_file(tmp_path: Path) -> Path:
    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps({"repo_url": "https://example.com/local/sample.git"}) + "\n",
        encoding="utf-8",
    )
    return repos_file


def _sample_repo(tmp_path: Path) -> Path:
    sample = tmp_path / "sample_src"
    sample.mkdir()
    (sample / "t.c").write_text(SOURCE, encoding="utf-8")
    return sample


def _run_batch(tmp_path: Path, out_dir: Path, *extra: str) -> None:
    assert (
        bsr.main(
            [
                "--repos-file",
                str(_repos_file(tmp_path)),
                "--out-dir",
                str(out_dir),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--log-level",
                "error",
                *extra,
            ]
        )
        == 0
    )


def test_batch_run_creates_latest_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_git(monkeypatch, _sample_repo(tmp_path))
    out_dir = tmp_path / "batch_runs"

    _run_batch(tmp_path, out_dir)

    latest = out_dir / "latest"
    assert latest.is_symlink()
    runs = [p for p in out_dir.iterdir() if p.is_dir() and not p.is_symlink()]
    assert latest.resolve() == runs[0].resolve()
    # The link must be usable the way a run directory is.
    assert (latest / "summary.json").is_file()
    assert (latest / "repos").is_dir()


def test_second_batch_run_repoints_latest_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_git(monkeypatch, _sample_repo(tmp_path))
    out_dir = tmp_path / "batch_runs"

    _run_batch(tmp_path, out_dir)
    first_run = (out_dir / "latest").resolve()
    monkeypatch.setattr(bsr, "new_run_id", lambda: "20260101T000000Z_aaaaaa")
    _run_batch(tmp_path, out_dir)
    second_run = (out_dir / "latest").resolve()

    assert second_run != first_run
    assert second_run.name == "20260101T000000Z_aaaaaa"
    assert first_run.is_dir(), "earlier runs must be left in place"


def test_dry_run_leaves_latest_link_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dry run produces no results, so it must not claim to be the latest."""
    _stub_git(monkeypatch, _sample_repo(tmp_path))
    out_dir = tmp_path / "batch_runs"

    _run_batch(tmp_path, out_dir)
    real_run = (out_dir / "latest").resolve()
    monkeypatch.setattr(bsr, "new_run_id", lambda: "20260101T000000Z_aaaaaa")
    _run_batch(tmp_path, out_dir, "--dry-run")

    assert (out_dir / "latest").resolve() == real_run


def test_batch_latest_link_survives_deleted_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pruning the run that latest referenced must not break the next run."""
    _stub_git(monkeypatch, _sample_repo(tmp_path))
    out_dir = tmp_path / "batch_runs"

    _run_batch(tmp_path, out_dir)
    shutil.rmtree((out_dir / "latest").resolve())
    monkeypatch.setattr(bsr, "new_run_id", lambda: "20260101T000000Z_aaaaaa")
    _run_batch(tmp_path, out_dir)

    assert (out_dir / "latest").resolve().name == "20260101T000000Z_aaaaaa"
    assert ((out_dir / "latest") / "summary.json").is_file()


# --- scan sessions ----------------------------------------------------------


def test_scan_session_latest_link_repoints(tmp_path: Path) -> None:
    """Sessions sharing an output base must repoint rather than fail."""
    from tacs.core.scan_session import ScanSession

    root = _sample_repo(tmp_path)
    base = tmp_path / "out"

    first = ScanSession(root_path=str(root), output_base=str(base))
    first.create_latest_symlink()
    second = ScanSession(root_path=str(root), output_base=str(base))
    second.create_latest_symlink()

    latest = base / "results" / "scans" / "latest"
    assert latest.is_symlink()
    assert latest.resolve() == second.scan_folder.resolve()
