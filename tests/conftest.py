# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Pytest collection tweaks for script-style helpers under tests/."""

collect_ignore = [
    "patterns/test_io_quick.py",
    "test_wizard_fix.py",
    "debug_pass2.py",
    "debug_id_mismatch.py",
    "debug_i3c_matches.py",
    "quick_test_constants.py",
    "patterns/analyze_io_missing.py",
    "patterns/debug_io_candidates.py",
    "patterns/inspect_io_results.py",
    "patterns/show_abstains.py",
]
