#!/usr/bin/env python3
"""
Manual smoke for environment wizard imports.
Run: python3 tests/test_wizard_fix.py
"""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from envui.cli.env_wizard import EnvironmentWizard

        print("Import successful!")

        wizard = EnvironmentWizard()
        print("Wizard instance created successfully!")

        print("\nTesting non-interactive mode...")
        wizard.run_non_interactive(
            "envui/examples/env_config.sample.json",
            "results/test_env_config.json",
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
