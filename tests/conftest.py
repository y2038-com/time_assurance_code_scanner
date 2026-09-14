# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Pytest collection defaults for this package."""

# Manual / historical harnesses live under tests/manual/ and are not collected
# (they are not named test_*.py). Keep this list empty unless a stray module
# must be ignored without relocating it.
collect_ignore: list[str] = []
