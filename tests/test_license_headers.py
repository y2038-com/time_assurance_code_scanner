# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Audit first-party source files for the copyright/SPDX header.

The repository is Apache-2.0 and every first-party source file says so in two
lines. A file added without them is not a licensing emergency, but it is the
kind of omission nobody notices until someone downstream asks what terms the
file came under.

The policy is expressed as directories and suffixes rather than a list of
files, so a new module is covered the moment it lands. Formats that cannot
carry a comment, and prose that never did, are out of scope by construction.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

HOLDER = "Copyright (c) 2026 Y2038.com LLC"
SPDX = "SPDX-License-Identifier: Apache-2.0"

#: Suffixes that must carry the header, with the comment marker each one uses.
HEADER_MARKERS = {
    ".py": "#",
    ".sh": "#",
    ".c": "//",
    ".h": "//",
    ".cpp": "//",
}

#: Trees that hold first-party source. Anything outside them is not audited.
SOURCE_TREES = ("src", "scripts", "tests")

#: Directories that hold caches, build output, scan results or clones of other
#: people's code, none of which this policy speaks for.
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".repo_cache",
    "results",
    "build",
    "dist",
    "node_modules",
}


def _source_files() -> list[Path]:
    found: list[Path] = []
    for tree in SOURCE_TREES:
        for path in sorted((REPO_ROOT / tree).rglob("*")):
            if path.suffix not in HEADER_MARKERS or not path.is_file():
                continue
            if SKIP_DIRS.intersection(path.relative_to(REPO_ROOT).parts):
                continue
            found.append(path)
    return found


SOURCE_FILES = _source_files()
IDS = [str(path.relative_to(REPO_ROOT)) for path in SOURCE_FILES]


def test_the_audit_actually_sees_the_repository() -> None:
    """A policy that matches nothing passes quietly and protects nothing."""
    suffixes = {path.suffix for path in SOURCE_FILES}

    assert len(SOURCE_FILES) > 100
    assert suffixes == set(HEADER_MARKERS)


@pytest.mark.parametrize("path", SOURCE_FILES, ids=IDS)
def test_first_party_sources_carry_the_header(path: Path) -> None:
    marker = HEADER_MARKERS[path.suffix]
    lines = path.read_text(encoding="utf-8").splitlines()
    start = 1 if lines and lines[0].startswith("#!") else 0

    assert lines[start:start + 2] == [f"{marker} {HOLDER}", f"{marker} {SPDX}"], (
        f"expected the two-line header at line {start + 1}"
    )


def _notice_lines(path: Path) -> list[str]:
    """Comment lines that read as a copyright or SPDX notice, not code that mentions one."""
    marker = HEADER_MARKERS[path.suffix]
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith(marker) and ("Copyright (c)" in line or SPDX in line)
    ]


@pytest.mark.parametrize("path", SOURCE_FILES, ids=IDS)
def test_headers_appear_exactly_once(path: Path) -> None:
    marker = HEADER_MARKERS[path.suffix]

    assert _notice_lines(path) == [f"{marker} {HOLDER}", f"{marker} {SPDX}"]


def test_interpreter_lines_stay_first() -> None:
    """A header above a shebang is a script that no longer runs."""
    executable = [
        path for path in SOURCE_FILES if "#!" in path.read_text(encoding="utf-8")[:2]
    ]
    assert len(executable) > 20, "expected the script harnesses to be found"

    for path in executable:
        assert path.read_text(encoding="utf-8").startswith("#!/"), path.name


def test_only_this_holder_claims_copyright() -> None:
    """Third-party attribution would need its own terms, not this policy."""
    for path in SOURCE_FILES:
        for notice in _notice_lines(path):
            if "Copyright (c)" not in notice:
                continue
            assert HOLDER in notice, f"{path.name}: unexpected holder in {notice!r}"


def test_comment_free_formats_were_left_alone() -> None:
    """JSON has no comments, so a header there would be a corrupt file."""
    import json

    for tree in SOURCE_TREES + ("configs", "inputs"):
        for path in sorted((REPO_ROOT / tree).rglob("*.json")):
            if SKIP_DIRS.intersection(path.relative_to(REPO_ROOT).parts):
                continue
            json.loads(path.read_text(encoding="utf-8"))


def test_the_license_matches_the_identifier_the_headers_claim() -> None:
    license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert license_text.startswith(HOLDER)
    assert "Apache License" in license_text and "Version 2.0" in license_text
    assert 'license = "Apache-2.0"' in pyproject
