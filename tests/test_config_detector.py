# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Basic unit tests for config_detector Phase 1 functionality."""

from __future__ import annotations

import tempfile
from pathlib import Path

from config_detector.detector import ConfigDetector
from config_detector.build_parsers import MakefileParser, CMakeParser
from config_detector.analyzers import ArchitectureDetector, TimeTConfigDetector


def test_makefile_parser():
    """Test Makefile parser."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        makefile = tmp_path / "Makefile"
        makefile.write_text(
            """
CC = arm-none-eabi-gcc
CFLAGS = -m32 -D_TIME_BITS=64 -Os
ARCH = arm
"""
        )

        parser = MakefileParser(tmp_path)
        result = parser.extract_all()

        assert result["build_files_found"] == 1
        assert "-m32" in result["cflags"]
        assert "TIME_BITS=64" in result["defines"] or any(
            "TIME_BITS" in d for d in result["defines"]
        )
        assert result["toolchain"] == "arm-none-eabi"


def test_cmake_parser():
    """Test CMake parser."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        cmake_file = tmp_path / "CMakeLists.txt"
        cmake_file.write_text(
            """
set(CMAKE_SYSTEM_PROCESSOR "arm")
set(CMAKE_C_FLAGS "-m32 -D_TIME_BITS=64")
add_definitions(-DFOO -DBAR=value)
"""
        )

        parser = CMakeParser(tmp_path)
        result = parser.extract_all()

        assert result["build_files_found"] == 1
        assert result["variables"]["CMAKE_SYSTEM_PROCESSOR"] == "arm"
        assert "-m32" in result["cflags"]


def test_architecture_detector():
    """Test architecture detection."""
    detector = ArchitectureDetector()

    extracted = {
        "cflags": ["-m32", "-Os"],
        "defines": [],
        "variables": {},
        "toolchain": "",
    }
    arch, conf, _evidence = detector.detect(extracted)
    assert arch == "ILP32"
    assert conf > 0.9

    extracted = {
        "cflags": ["-m64"],
        "defines": [],
        "variables": {},
        "toolchain": "",
    }
    arch, conf, _evidence = detector.detect(extracted)
    assert arch == "LP64"
    assert conf > 0.9


def test_time_t_detector():
    """Test time_t size detection (API returns size + signedness)."""
    detector = TimeTConfigDetector()

    extracted = {
        "cflags": ["-D_TIME_BITS=64"],
        "defines": [],
        "variables": {},
    }
    size, size_conf, _signed, _signed_conf, _evidence = detector.detect(extracted)
    assert size == 64
    assert size_conf > 0.9

    extracted = {
        "cflags": [],
        "defines": [],
        "variables": {},
    }
    size, size_conf, _signed, _signed_conf, _evidence = detector.detect(
        extracted, architecture="LP64"
    )
    assert size == 64
    assert size_conf > 0.6


def test_full_detection():
    """Test full detection pipeline across all eight configs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        makefile = tmp_path / "Makefile"
        makefile.write_text(
            """
CC = arm-none-eabi-gcc
CFLAGS = -m32 -D_TIME_BITS=32
"""
        )

        detector = ConfigDetector(tmp_path)
        results = detector.detect()

        assert results["architecture"] == "ILP32"
        assert results["time_t_size"] == 32
        assert len(results["likelihoods"]) == 8

        lp64_configs = [l for l in results["likelihoods"] if l.name.startswith("lp64")]
        assert lp64_configs
        assert all(l.ruled_out for l in lp64_configs)

        # With signed default + 32-bit time_t, unsigned/64-bit ILP32 variants are ruled out.
        active = [l for l in results["likelihoods"] if not l.ruled_out]
        assert active
        assert all(l.name.startswith("ilp32") for l in active)
        assert any(l.name == "ilp32_signed_32bit" for l in active)
