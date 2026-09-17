#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Manual smoke for environment wizard imports.
Run: python3 tests/manual/manual_wizard_fix.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# The sample config moved under src/ with the rest of the packages. Anchoring on
# __file__ keeps this working from any directory.
REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_CONFIG = REPO_ROOT / "src" / "envui" / "examples" / "env_config.sample.json"


def main() -> int:
    try:
        from envui.cli.env_wizard import EnvironmentWizard

        print("Import successful!")

        wizard = EnvironmentWizard()
        print("Wizard instance created successfully!")

        print("\nTesting non-interactive mode...")
        # The written config is scratch, so it goes to a temp directory.
        with tempfile.TemporaryDirectory(prefix="y2038_wizard_") as out_dir:
            wizard.run_non_interactive(
                str(SAMPLE_CONFIG),
                str(Path(out_dir) / "test_env_config.json"),
                print_summary=True,
                log_cli=False,
            )
        print("Non-interactive mode test passed!")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
