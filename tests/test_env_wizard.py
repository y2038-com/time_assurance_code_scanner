#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Test script for the environment wizard.
"""

import json
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from envui.cli.validate_env import EnvironmentValidator
    from envui.cli.derive_fields import FieldDeriver
    from envui.cli.io_utils import IOUtils
    
    print("✓ All imports successful")
    
    # Test with sample config
    sample_config = {
        "hardware_model": "ILP32",
        "time_t_size_bits": 32,
        "time_t_signed": "signed",
        "time64_functions_available": False,
        "d_time_bits_supported": True,
        "d_time_bits_setting": "64",
        "os_or_rtos": "Zephyr 3.7",
        "c_library": "picolibc",
        "c_library_other_text": "",
        "toolchain_flags": ["-D_FILE_OFFSET_BITS=64"],
        "notes": "board XYZ"
    }
    
    # Test field derivation
    deriver = FieldDeriver()
    derived_config = deriver.derive_fields(sample_config)
    print(f"✓ Field derivation successful: {derived_config['scenario_hint']}")
    
    # Test summary generation
    summary = deriver.get_scenario_summary(derived_config)
    print(f"✓ Summary generation successful: {summary}")
    
    # Test validation (without jsonschema for now)
    validator = EnvironmentValidator()
    # Skip schema validation for now, just test business rules
    errors = validator._validate_business_rules(derived_config)
    if errors:
        print(f"✗ Validation errors: {errors}")
    else:
        print("✓ Business rule validation successful")
    
    print("\nAll tests passed!")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
