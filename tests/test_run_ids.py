# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for run/session id generation.

The old ids were an MD5 of the current second, so two runs starting in the same
second produced the same id and the same output directory. These tests pin the
documented format and the same-second distinctness that replaced it, for the
generator itself and for both directories built from it.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest

import tacs.batch_scan_repos as bsr
from tacs.core.run_ids import RUN_ID_PATTERN, new_run_id
from tacs.core.scan_session import ScanSession


# --- the generator ----------------------------------------------------------


def test_run_id_matches_documented_format() -> None:
    """YYYYMMDDTHHMMSSZ_<6-hex-random>, e.g. 20260916T151300Z_7c91ab."""
    run_id = new_run_id()

    assert RUN_ID_PATTERN.match(run_id), run_id
    stamp, suffix = run_id.split("_")
    assert len(stamp) == len("20260916T151300Z")
    assert len(suffix) == 6


def test_ids_minted_in_the_same_second_are_distinct() -> None:
    """The failure the random suffix exists to prevent."""
    ids = [new_run_id() for _ in range(200)]
    stamps = {run_id.split("_")[0] for run_id in ids}

    # A tight loop stays within a second or two, so the timestamps alone could
    # not have separated these.
    assert len(stamps) <= 2
    assert len(set(ids)) == len(ids)
    assert all(RUN_ID_PATTERN.match(run_id) for run_id in ids)


def test_suffix_is_lowercase_hex_and_filesystem_safe() -> None:
    suffixes = {new_run_id().split("_")[1] for _ in range(50)}

    assert all(re.fullmatch(r"[0-9a-f]{6}", suffix) for suffix in suffixes)
    # More than one suffix seen, so the value is actually random.
    assert len(suffixes) > 1


def test_suffix_is_not_derived_from_the_current_second() -> None:
    """An MD5-of-the-second scheme would give same-second runs one suffix."""
    import hashlib

    forbidden = {
        hashlib.md5(str(int(datetime.now(timezone.utc).timestamp()) + offset).encode())
        .hexdigest()[:6]
        for offset in range(-2, 3)
    }
    suffixes = {new_run_id().split("_")[1] for _ in range(20)}

    assert not suffixes <= forbidden


def test_timestamp_prefix_is_utc_and_sorts_chronologically() -> None:
    before = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = new_run_id()
    after = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    stamp = run_id.split("_")[0]
    assert before <= stamp <= after
    # Lexical order is chronological order for this format.
    assert sorted(["20260916T151300Z_ffffff", "20260916T151259Z_000000"])[0].startswith(
        "20260916T151259Z"
    )


# --- standalone tacs scan session directories -------------------------------


def test_scan_session_directory_uses_the_run_id(tmp_path: Path) -> None:
    session = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path))

    assert session.scan_folder.parent == (tmp_path / "results" / "scans").resolve()
    assert RUN_ID_PATTERN.match(session.scan_folder.name), session.scan_folder.name
    assert session.scan_folder.name == session.scan_id


def test_two_scan_sessions_in_the_same_second_get_separate_directories(
    tmp_path: Path,
) -> None:
    """Previously both sessions hashed the same second into the same folder."""
    first = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path))
    second = ScanSession(root_path=str(tmp_path), output_base=str(tmp_path))

    assert first.scan_id != second.scan_id
    assert first.scan_folder != second.scan_folder
    assert first.scan_folder.is_dir() and second.scan_folder.is_dir()
    sessions = sorted(
        path.name
        for path in (tmp_path / "results" / "scans").iterdir()
        if path.is_dir() and not path.is_symlink()
    )
    assert len(sessions) == 2, sessions
    assert all(RUN_ID_PATTERN.match(name) for name in sessions)


def test_batch_mode_session_does_not_mint_a_directory_name(tmp_path: Path) -> None:
    """The supplied directory stays the artifact root; the id is metadata only."""
    repo_dir = tmp_path / "repos" / "github__acme__demo__main"
    session = ScanSession(root_path=str(tmp_path), session_dir=str(repo_dir))

    assert session.scan_folder == repo_dir.resolve()
    assert RUN_ID_PATTERN.match(session.scan_id), session.scan_id


# --- tacs repos batch run directories ---------------------------------------

SOURCE = """#include <time.h>

int measure_window(void) {
    time_t now = time(NULL);
    return (int)now;
}
"""


def _stub_git(monkeypatch: pytest.MonkeyPatch, sample: Path) -> None:
    """Serve the sample tree in place of clone/fetch so no network is needed."""

    def fake_prepare(identity, repo_url: str) -> None:
        identity.cache_path.mkdir(parents=True, exist_ok=True)
        shutil.copytree(sample, identity.cache_path, dirs_exist_ok=True)

    monkeypatch.setattr(bsr, "_prepare_repo", fake_prepare)
    monkeypatch.setattr(
        bsr, "_resolve_ref", lambda repo, ref: ("master", "a" * 40, "master")
    )
    monkeypatch.setattr(bsr, "_checkout_clean", lambda repo, ref, sha: None)


def _run_batch(tmp_path: Path, out_dir: Path) -> None:
    sample = tmp_path / "sample_src"
    sample.mkdir(exist_ok=True)
    (sample / "t.c").write_text(SOURCE, encoding="utf-8")
    repos_file = tmp_path / "repos.jsonl"
    repos_file.write_text(
        json.dumps({"repo_url": "https://example.com/local/sample.git"}) + "\n",
        encoding="utf-8",
    )
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
        == 0
    )


def _run_dirs(out_dir: Path) -> list[str]:
    return sorted(
        path.name
        for path in out_dir.iterdir()
        if path.is_dir() and not path.is_symlink()
    )


def test_batch_run_directory_uses_the_run_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "sample_src"
    sample.mkdir()
    _stub_git(monkeypatch, sample)
    out_dir = tmp_path / "batch_runs"

    _run_batch(tmp_path, out_dir)

    runs = _run_dirs(out_dir)
    assert len(runs) == 1, runs
    assert RUN_ID_PATTERN.match(runs[0]), runs[0]


def test_two_batch_runs_in_the_same_second_get_separate_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "sample_src"
    sample.mkdir()
    _stub_git(monkeypatch, sample)
    out_dir = tmp_path / "batch_runs"

    _run_batch(tmp_path, out_dir)
    _run_batch(tmp_path, out_dir)

    runs = _run_dirs(out_dir)
    assert len(runs) == 2, runs
    assert all(RUN_ID_PATTERN.match(name) for name in runs)
    # latest still resolves to one of them, not to a clobbered merge of both.
    assert (out_dir / "latest").resolve().name in runs
