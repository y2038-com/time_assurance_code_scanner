#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Simplified test version of the environment wizard (without jsonschema dependency).
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from envui.cli.derive_fields import FieldDeriver
from envui.cli.io_utils import IOUtils


def validate_business_rules(config):
    """Validate business rules without jsonschema."""
    errors = []
    
    # Rule 1: d_time_bits_supported vs d_time_bits_setting
    d_time_bits_supported = config.get('d_time_bits_supported', False)
    d_time_bits_setting = config.get('d_time_bits_setting', '')
    
    if not d_time_bits_supported and d_time_bits_setting != 'not_available':
        errors.append("If d_time_bits_supported=false, d_time_bits_setting must be 'not_available'")
    
    if d_time_bits_supported and d_time_bits_setting == 'not_available':
        errors.append("If d_time_bits_supported=true, d_time_bits_setting cannot be 'not_available'")
    
    # Rule 2: c_library="other" requires c_library_other_text
    c_library = config.get('c_library', '')
    c_library_other_text = config.get('c_library_other_text', '')
    
    if c_library == 'other' and not c_library_other_text.strip():
        errors.append("If c_library='other', c_library_other_text must be non-empty")
    
    # Rule 3: scenario_hint="ILP32-32bit-signed-time64_no" requires mitigation_path
    scenario_hint = config.get('scenario_hint', '')
    mitigation_path = config.get('mitigation_path')
    
    if scenario_hint == 'ILP32-32bit-signed-time64_no' and mitigation_path is None:
        errors.append("If scenario_hint='ILP32-32bit-signed-time64_no', mitigation_path is required")
    
    return errors


def main():
    """Test the environment wizard functionality."""
    print("Y2038 Environment Configuration Wizard - Test Mode")
    print("=" * 60)
    
    # Read sample config
    try:
        with open('envui/examples/env_config.sample.json', 'r') as f:
            config = json.load(f)
        print("✓ Loaded sample configuration")
    except Exception as e:
        print(f"✗ Failed to load sample config: {e}")
        return 1
    
    # Derive fields
    deriver = FieldDeriver()
    config = deriver.derive_fields(config)
    print(f"✓ Derived scenario_hint: {config['scenario_hint']}")
    print(f"✓ Derived mitigation_path: {config['mitigation_path']}")
    
    # Validate business rules
    errors = validate_business_rules(config)
    if errors:
        print("✗ Validation errors:")
        for error in errors:
            print(f"  - {error}")
        return 1
    else:
        print("✓ Business rule validation passed")
    
    # Generate summary
    summary = deriver.get_scenario_summary(config)
    print(f"✓ Summary: {summary}")
    
    # Write output
    try:
        IOUtils.write_json_file('results/env_config.json', config)
        print("✓ Wrote configuration to results/env_config.json")
    except Exception as e:
        print(f"✗ Failed to write output: {e}")
        return 1
    
    # Test logging
    try:
        log_dir = Path("results/env_logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        month_dir = log_dir / datetime.utcnow().strftime("%Y-%m")
        month_dir.mkdir(exist_ok=True)
        
        log_file = month_dir / f"env_wizard_{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"
        
        log_entry = {
            "utc_timestamp": datetime.utcnow().isoformat() + "Z",
            "out_path": "results/env_config.json",
            "summary_text": summary,
            "validation_ok": True,
            "errors": [],
            "scenario_hint": config.get('scenario_hint', ''),
            "mitigation_path": config.get('mitigation_path'),
            "flags": {
                "print_summary": True,
                "log_cli": True
            }
        }
        
        IOUtils.append_jsonl_line(str(log_file), log_entry)
        print(f"✓ Logged operation to {log_file}")
        
    except Exception as e:
        print(f"✗ Failed to log operation: {e}")
        return 1
    
    print("\n🎉 All tests passed! Environment wizard is working correctly.")
    return 0


if __name__ == '__main__':
    exit(main())
