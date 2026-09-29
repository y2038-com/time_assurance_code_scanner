# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests that package and CLI version surfaces stay aligned."""

from __future__ import annotations

import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest

from tacs import __version__ as tacs_version


EXPECTED = "0.2.0rc1"
DIST_NAME = "time-assurance-code-scanner"


def test_package_dunder_version_is_release_candidate() -> None:
    assert tacs_version == EXPECTED


def test_pyproject_version_matches_package() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    text = pyproject.read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
    assert match, "pyproject.toml must declare project.version"
    assert match.group(1) == EXPECTED
    assert match.group(1) == tacs_version


def test_importlib_metadata_matches_package() -> None:
    assert metadata.version(DIST_NAME) == EXPECTED
    assert metadata.version(DIST_NAME) == tacs_version


def test_cli_version_command_matches_package() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "tacs.cli", "version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == f"tacs {EXPECTED}"


def test_click_version_option_matches_package() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "tacs.cli", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    # Click prints "tacs, version X" by default for --version.
    assert EXPECTED in result.stdout
    assert "0.1.0" not in result.stdout


@pytest.mark.parametrize(
    "module_name",
    ["tacs", "report_renderer"],
)
def test_distribution_modules_report_release_candidate(module_name: str) -> None:
    mod = __import__(module_name)
    assert getattr(mod, "__version__") == EXPECTED
