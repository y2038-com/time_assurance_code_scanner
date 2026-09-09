#!/usr/bin/env python3
"""
Test the fixed environment wizard imports.
"""

import sys
from pathlib import Path

# Test the import fix
try:
    # This should work now
    from envui.cli.env_wizard import EnvironmentWizard
    print("✓ Import successful!")
    
    # Test creating wizard instance
    wizard = EnvironmentWizard()
    print("✓ Wizard instance created successfully!")
    
    # Test non-interactive mode with sample config
    print("\nTesting non-interactive mode...")
    wizard.run_non_interactive(
        'envui/examples/env_config.sample.json',
        'results/test_env_config.json',
        print_summary=True,
        log_cli=False
    )
    print("✓ Non-interactive mode test passed!")
    
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
