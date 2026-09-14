#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Y2038 Environment Configuration Wizard

A CLI tool for collecting and validating environment details for Y2038 vulnerability scanning.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    # Try relative imports first (when run as module)
    from .validate_env import EnvironmentValidator
    from .derive_fields import FieldDeriver
    from .io_utils import IOUtils
except ImportError:
    # Fall back to absolute imports (when run as script)
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from envui.cli.validate_env import EnvironmentValidator
    from envui.cli.derive_fields import FieldDeriver
    from envui.cli.io_utils import IOUtils


class EnvironmentWizard:
    """Main environment configuration wizard."""
    
    def __init__(self):
        """Initialize the wizard."""
        self.validator = EnvironmentValidator()
        self.deriver = FieldDeriver()
        self.io_utils = IOUtils()
    
    def run_interactive(self, output_path: str, print_summary: bool = False, log_cli: bool = False) -> None:
        """
        Run interactive mode to collect environment configuration.
        
        Args:
            output_path: Path to write the configuration
            print_summary: Whether to print a summary
            log_cli: Whether to enable CLI logging
        """
        print("Y2038 Environment Configuration Wizard")
        print("=" * 50)
        
        config = self._collect_interactive_input()
        
        # Derive fields
        config = self.deriver.derive_fields(config)
        
        # Validate
        is_valid, errors = self.validator.validate(config)
        if not is_valid:
            print("\nValidation errors:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)
        
        # Normalize
        config = self.validator.normalize_config(config)
        
        # Write output
        self.io_utils.write_json_file(output_path, config)
        
        # Print summary if requested
        if print_summary:
            summary = self.deriver.get_scenario_summary(config)
            print(f"\nSummary: {summary}")
        
        # Log if requested
        if log_cli:
            self._log_cli_operation(output_path, config, is_valid, errors, print_summary)
    
    def run_non_interactive(self, input_path: str, output_path: str, print_summary: bool = False, log_cli: bool = False) -> None:
        """
        Run non-interactive mode to validate and normalize existing configuration.
        
        Args:
            input_path: Path to read the configuration from
            output_path: Path to write the normalized configuration
            print_summary: Whether to print a summary
            log_cli: Whether to enable CLI logging
        """
        # Read input
        try:
            config = self.io_utils.read_json_file(input_path)
        except Exception as e:
            print(f"Error reading input file: {e}")
            sys.exit(1)
        
        # Derive fields
        config = self.deriver.derive_fields(config)
        
        # Validate
        is_valid, errors = self.validator.validate(config)
        if not is_valid:
            print("Validation errors:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)
        
        # Normalize
        config = self.validator.normalize_config(config)
        
        # Write output
        self.io_utils.write_json_file(output_path, config)
        
        # Print summary if requested
        if print_summary:
            summary = self.deriver.get_scenario_summary(config)
            print(f"Summary: {summary}")
        
        # Log if requested
        if log_cli:
            self._log_cli_operation(output_path, config, is_valid, errors, print_summary)
    
    def _collect_interactive_input(self) -> Dict[str, Any]:
        """Collect input interactively from user."""
        config = {}
        
        # Hardware model
        print("\n1. Hardware Architecture:")
        print("   Options: ILP32, LP64")
        print("   Example: ILP32 (32-bit int, long, pointer)")
        while True:
            hardware_model = input("   Hardware model: ").strip()
            if hardware_model in ['ILP32', 'LP64']:
                config['hardware_model'] = hardware_model
                break
            print("   Invalid option. Please choose ILP32 or LP64.")
        
        # time_t size
        print("\n2. time_t Size:")
        print("   Options: 32, 64")
        print("   Example: 32 (32-bit time_t)")
        while True:
            try:
                time_t_size = int(input("   time_t size (bits): ").strip())
                if time_t_size in [32, 64]:
                    config['time_t_size_bits'] = time_t_size
                    break
                print("   Invalid option. Please choose 32 or 64.")
            except ValueError:
                print("   Invalid input. Please enter a number.")
        
        # time_t signedness
        print("\n3. time_t Signedness:")
        print("   Options: signed, unsigned")
        print("   Example: signed (most common)")
        while True:
            time_t_signed = input("   time_t signedness: ").strip()
            if time_t_signed in ['signed', 'unsigned']:
                config['time_t_signed'] = time_t_signed
                break
            print("   Invalid option. Please choose signed or unsigned.")
        
        # time64 functions availability
        print("\n4. time64 Functions:")
        print("   Options: true, false")
        print("   Example: false (no time64 functions available)")
        while True:
            time64_input = input("   time64 functions available (true/false): ").strip().lower()
            if time64_input in ['true', 'false']:
                config['time64_functions_available'] = time64_input == 'true'
                break
            print("   Invalid option. Please choose true or false.")
        
        # _TIME_BITS support
        print("\n5. _TIME_BITS Support:")
        print("   Options: true, false")
        print("   Example: true (glibc supports _TIME_BITS)")
        while True:
            d_time_bits_supported_input = input("   _TIME_BITS supported (true/false): ").strip().lower()
            if d_time_bits_supported_input in ['true', 'false']:
                config['d_time_bits_supported'] = d_time_bits_supported_input == 'true'
                break
            print("   Invalid option. Please choose true or false.")
        
        # _TIME_BITS setting
        print("\n6. _TIME_BITS Setting:")
        if config['d_time_bits_supported']:
            print("   Options: not_set, 32, 64")
            print("   Example: 64 (use 64-bit time_t)")
            while True:
                d_time_bits_setting = input("   _TIME_BITS setting: ").strip()
                if d_time_bits_setting in ['not_set', '32', '64']:
                    config['d_time_bits_setting'] = d_time_bits_setting
                    break
                print("   Invalid option. Please choose not_set, 32, or 64.")
        else:
            config['d_time_bits_setting'] = 'not_available'
            print("   Set to 'not_available' (not supported)")
        
        # OS/RTOS
        print("\n7. Operating System/RTOS (optional):")
        print("   Example: Zephyr 3.7, Linux 5.4, FreeRTOS 10.0")
        os_or_rtos = input("   OS/RTOS: ").strip()
        if os_or_rtos:
            config['os_or_rtos'] = os_or_rtos
        
        # C library
        print("\n8. C Library:")
        print("   Options: glibc, newlib, picolibc, musl, minimal, libstdc++, other")
        print("   Example: picolibc (common in embedded systems)")
        while True:
            c_library = input("   C library: ").strip()
            if c_library in ['glibc', 'newlib', 'picolibc', 'musl', 'minimal', 'libstdc++', 'other']:
                config['c_library'] = c_library
                break
            print("   Invalid option. Please choose from the list.")
        
        # C library other text
        if c_library == 'other':
            print("\n8a. C Library Description:")
            print("   Example: Custom embedded C library")
            c_library_other_text = input("   Description: ").strip()
            if c_library_other_text:
                config['c_library_other_text'] = c_library_other_text
        
        # Toolchain flags
        print("\n9. Toolchain Flags (optional):")
        print("   Example: -D_FILE_OFFSET_BITS=64, -D_TIME_BITS=64")
        print("   Enter flags separated by commas, or press Enter to skip:")
        toolchain_flags_input = input("   Toolchain flags: ").strip()
        if toolchain_flags_input:
            flags = [flag.strip() for flag in toolchain_flags_input.split(',')]
            config['toolchain_flags'] = flags
        
        # Notes
        print("\n10. Additional Notes (optional):")
        print("   Example: board XYZ, specific configuration notes")
        notes = input("   Notes: ").strip()
        if notes:
            config['notes'] = notes
        
        return config
    
    def _log_cli_operation(self, output_path: str, config: Dict[str, Any], is_valid: bool, errors: List[str], print_summary: bool) -> None:
        """Log CLI operation to JSONL file."""
        try:
            # Create log directory
            log_dir = Path("results/env_logs")
            log_dir.mkdir(parents=True, exist_ok=True)
            
            # Create monthly subdirectory
            now = datetime.utcnow()
            month_dir = log_dir / now.strftime("%Y-%m")
            month_dir.mkdir(exist_ok=True)
            
            # Log file path
            log_file = month_dir / f"env_wizard_{now.strftime('%Y-%m-%d')}.jsonl"
            
            # Prepare log entry
            log_entry = {
                "utc_timestamp": now.isoformat() + "Z",
                "out_path": output_path,
                "summary_text": self.deriver.get_scenario_summary(config),
                "validation_ok": is_valid,
                "errors": errors,
                "scenario_hint": config.get('scenario_hint', ''),
                "mitigation_path": config.get('mitigation_path'),
                "flags": {
                    "print_summary": print_summary,
                    "log_cli": True
                }
            }
            
            # Append to log file
            self.io_utils.append_jsonl_line(str(log_file), log_entry)
            
        except Exception as e:
            print(f"Warning: Failed to log CLI operation: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Y2038 Environment Configuration Wizard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python envui/cli/env_wizard.py --out results/env_config.json --print-summary
  
  # Non-interactive mode
  python envui/cli/env_wizard.py --non-interactive envui/examples/env_config.sample.json --out results/env_config.json --print-summary --log-cli
        """
    )
    
    parser.add_argument(
        '--out',
        default='results/env_config.json',
        help='Output path for configuration file (default: results/env_config.json)'
    )
    
    parser.add_argument(
        '--non-interactive',
        metavar='PATH_TO_JSON',
        help='Non-interactive mode: read, validate, and normalize existing JSON file'
    )
    
    parser.add_argument(
        '--print-summary',
        action='store_true',
        help='Print one-line summary of the configuration'
    )
    
    parser.add_argument(
        '--log-cli',
        action='store_true',
        help='Enable CLI operation logging to results/env_logs'
    )
    
    parser.add_argument(
        '--log-retention-days',
        type=int,
        default=30,
        help='Log retention period in days (default: 30)'
    )
    
    args = parser.parse_args()
    
    # Create wizard
    wizard = EnvironmentWizard()
    
    try:
        if args.non_interactive:
            wizard.run_non_interactive(
                args.non_interactive,
                args.out,
                args.print_summary,
                args.log_cli
            )
        else:
            wizard.run_interactive(
                args.out,
                args.print_summary,
                args.log_cli
            )
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    # Handle import issues when running as script
    if len(sys.path) == 0 or sys.path[0] == '':
        # Add project root to path
        project_root = Path(__file__).parent.parent.parent
        sys.path.insert(0, str(project_root))
    
    main()
