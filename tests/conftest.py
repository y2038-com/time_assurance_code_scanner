# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Pytest collection defaults for this package."""

from __future__ import annotations

from pathlib import Path

import pytest

# Manual / historical harnesses live under tests/manual/ and are not collected
# (they are not named test_*.py). Keep this list empty unless a stray module
# must be ignored without relocating it.
collect_ignore: list[str] = []

REPO_ROOT = Path(__file__).resolve().parents[1]


def _results_tree() -> set[Path]:
    """Every path under the checkout's real results/, if it exists."""
    results = REPO_ROOT / "results"
    if not results.is_dir():
        return set()
    return set(results.rglob("*"))


@pytest.fixture(autouse=True, scope="session")
def repo_results_tree_is_untouched() -> None:
    """Fail the run if the suite wrote into the checkout's own results/ tree.

    ``tacs scan`` has no flag for relocating its session root: the session lands
    under ``results/scans/`` relative to the working directory. A test that runs
    a scan from the repository root therefore litters the developer's real
    results tree, which is how several session directories per run used to
    appear. Tests avoid that by working from ``tmp_path``; this guard notices if
    a new one forgets.

    Only additions are reported. A scan the developer runs themselves between
    collection and teardown would show up here too, but nothing in the suite
    removes paths, so deletions are not treated as failures.
    """
    before = _results_tree()
    yield
    added = sorted(str(path.relative_to(REPO_ROOT)) for path in _results_tree() - before)
    if added:
        shown = "\n  ".join(added[:10])
        more = f"\n  ... and {len(added) - 10} more" if len(added) > 10 else ""
        pytest.fail(
            "the suite wrote into the checkout's real results/ tree:\n  "
            f"{shown}{more}\n"
            "Run scans from tmp_path (monkeypatch.chdir) or pass output_base/"
            "session_dir so artifacts stay in the temporary directory.",
            pytrace=False,
        )
