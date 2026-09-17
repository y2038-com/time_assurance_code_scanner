#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Environment configuration fixtures for testing different ABI and time_t configurations.

This module provides pre-configured environment configs for:
- 32-bit ABI with signed 32-bit time_t
- 32-bit ABI with unsigned 32-bit time_t
- 64-bit ABI with signed time_t
- 64-bit ABI with unsigned time_t
"""

import json
from pathlib import Path
from typing import Dict, Any


def create_env_config(
    hardware_model: str,
    time_t_size_bits: int,
    time_t_signed: str,
    time64_functions_available: bool = False,
    d_time_bits_supported: bool = False,
    d_time_bits_setting: str = "not_available",
    c_library: str = "glibc",
    os_or_rtos: str = None,
    toolchain_flags: list = None,
    notes: str = None
) -> Dict[str, Any]:
    """Create an environment configuration dictionary."""
    config = {
        "hardware_model": hardware_model,
        "time_t_size_bits": time_t_size_bits,
        "time_t_signed": time_t_signed,
        "time64_functions_available": time64_functions_available,
        "d_time_bits_supported": d_time_bits_supported,
        "d_time_bits_setting": d_time_bits_setting,
        "c_library": c_library,
    }
    
    if os_or_rtos:
        config["os_or_rtos"] = os_or_rtos
    if toolchain_flags:
        config["toolchain_flags"] = toolchain_flags
    if notes:
        config["notes"] = notes
    
    # Derive scenario_hint and mitigation_path
    scenario_hint = f"{hardware_model}-{time_t_size_bits}bit-{time_t_signed}"
    if time64_functions_available:
        scenario_hint += "-time64_yes"
    else:
        scenario_hint += "-time64_no"
    
    if d_time_bits_supported and d_time_bits_setting != "not_available":
        scenario_hint += f"-_TIME_BITS_{d_time_bits_setting}"
    else:
        scenario_hint += "-N/A"
    
    config["scenario_hint"] = scenario_hint
    
    # Set mitigation_path for risky scenarios
    if (hardware_model == "ILP32" and 
        time_t_size_bits == 32 and 
        time_t_signed == "signed" and 
        not time64_functions_available):
        config["mitigation_path"] = "upgrade_env"
    else:
        config["mitigation_path"] = None
    
    return config


# Pre-configured environment configs for testing - ALL 8 COMBINATIONS

def get_ilp32_signed_32bit_config() -> Dict[str, Any]:
    """32-bit ABI (ILP32) with signed 32-bit time_t - Most risky for Y2038."""
    return create_env_config(
        hardware_model="ILP32",
        time_t_size_bits=32,
        time_t_signed="signed",
        time64_functions_available=False,
        d_time_bits_supported=False,
        d_time_bits_setting="not_available",
        c_library="picolibc",
        os_or_rtos="Zephyr 3.7",
        notes="32-bit embedded system with signed time_t - highest Y2038 risk"
    )


def get_ilp32_unsigned_32bit_config() -> Dict[str, Any]:
    """32-bit ABI (ILP32) with unsigned 32-bit time_t - Y2106 risk, not Y2038."""
    return create_env_config(
        hardware_model="ILP32",
        time_t_size_bits=32,
        time_t_signed="unsigned",
        time64_functions_available=False,
        d_time_bits_supported=False,
        d_time_bits_setting="not_available",
        c_library="picolibc",
        os_or_rtos="Zephyr 3.7",
        notes="32-bit embedded system with unsigned time_t - Y2106 risk, not Y2038"
    )


def get_lp64_signed_64bit_config() -> Dict[str, Any]:
    """64-bit ABI (LP64) with signed 64-bit time_t - Y2038 safe."""
    return create_env_config(
        hardware_model="LP64",
        time_t_size_bits=64,
        time_t_signed="signed",
        time64_functions_available=True,
        d_time_bits_supported=True,
        d_time_bits_setting="64",
        c_library="glibc",
        os_or_rtos="Linux 5.4",
        toolchain_flags=["-D_TIME_BITS=64"],
        notes="64-bit system with 64-bit time_t - Y2038 safe"
    )


def get_lp64_unsigned_64bit_config() -> Dict[str, Any]:
    """64-bit ABI (LP64) with unsigned 64-bit time_t - Very rare, but possible."""
    return create_env_config(
        hardware_model="LP64",
        time_t_size_bits=64,
        time_t_signed="unsigned",
        time64_functions_available=True,
        d_time_bits_supported=True,
        d_time_bits_setting="64",
        c_library="glibc",
        os_or_rtos="Linux 5.4",
        toolchain_flags=["-D_TIME_BITS=64"],
        notes="64-bit system with unsigned 64-bit time_t - very rare configuration"
    )


def get_ilp32_signed_64bit_config() -> Dict[str, Any]:
    """32-bit ABI (ILP32) with signed 64-bit time_t - Narrowing pattern risks only."""
    return create_env_config(
        hardware_model="ILP32",
        time_t_size_bits=64,
        time_t_signed="signed",
        time64_functions_available=True,
        d_time_bits_supported=True,
        d_time_bits_setting="64",
        c_library="glibc",
        os_or_rtos="Linux 5.4",
        toolchain_flags=["-D_TIME_BITS=64"],
        notes="32-bit ABI with 64-bit time_t - narrowing pattern risks only"
    )


def get_ilp32_unsigned_64bit_config() -> Dict[str, Any]:
    """32-bit ABI (ILP32) with unsigned 64-bit time_t - Narrowing pattern risks only."""
    return create_env_config(
        hardware_model="ILP32",
        time_t_size_bits=64,
        time_t_signed="unsigned",
        time64_functions_available=True,
        d_time_bits_supported=True,
        d_time_bits_setting="64",
        c_library="glibc",
        os_or_rtos="Linux 5.4",
        toolchain_flags=["-D_TIME_BITS=64"],
        notes="32-bit ABI with unsigned 64-bit time_t - narrowing pattern risks only"
    )


def get_lp64_signed_32bit_config() -> Dict[str, Any]:
    """64-bit ABI (LP64) with signed 32-bit time_t - Rare, Y2038 risk."""
    return create_env_config(
        hardware_model="LP64",
        time_t_size_bits=32,
        time_t_signed="signed",
        time64_functions_available=False,
        d_time_bits_supported=False,
        d_time_bits_setting="not_available",
        c_library="glibc",
        os_or_rtos="Linux 5.4",
        notes="64-bit ABI with 32-bit signed time_t - rare configuration, Y2038 risk"
    )


def get_lp64_unsigned_32bit_config() -> Dict[str, Any]:
    """64-bit ABI (LP64) with unsigned 32-bit time_t - Rare, Y2106 risk."""
    return create_env_config(
        hardware_model="LP64",
        time_t_size_bits=32,
        time_t_signed="unsigned",
        time64_functions_available=False,
        d_time_bits_supported=False,
        d_time_bits_setting="not_available",
        c_library="glibc",
        os_or_rtos="Linux 5.4",
        notes="64-bit ABI with 32-bit unsigned time_t - rare configuration, Y2106 risk"
    )


def get_all_test_configs() -> Dict[str, Dict[str, Any]]:
    """Get all 8 test configurations as a dictionary."""
    return {
        "ilp32_signed_32bit": get_ilp32_signed_32bit_config(),
        "ilp32_unsigned_32bit": get_ilp32_unsigned_32bit_config(),
        "ilp32_signed_64bit": get_ilp32_signed_64bit_config(),
        "ilp32_unsigned_64bit": get_ilp32_unsigned_64bit_config(),
        "lp64_signed_32bit": get_lp64_signed_32bit_config(),
        "lp64_unsigned_32bit": get_lp64_unsigned_32bit_config(),
        "lp64_signed_64bit": get_lp64_signed_64bit_config(),
        "lp64_unsigned_64bit": get_lp64_unsigned_64bit_config(),
    }


def save_config_to_file(config: Dict[str, Any], file_path: Path) -> None:
    """Save an environment configuration to a JSON file."""
    with open(file_path, 'w') as f:
        json.dump(config, f, indent=2)


def load_config_from_file(file_path: Path) -> Dict[str, Any]:
    """Load an environment configuration from a JSON file."""
    with open(file_path, 'r') as f:
        return json.load(f)


if __name__ == "__main__":
    # Generate all config files for testing
    configs_dir = Path(__file__).parent / "env_configs"
    configs_dir.mkdir(exist_ok=True)
    
    all_configs = get_all_test_configs()
    for name, config in all_configs.items():
        config_file = configs_dir / f"{name}.json"
        save_config_to_file(config, config_file)
        print(f"Created: {config_file}")
        print(f"  Scenario: {config['scenario_hint']}")
        print(f"  Mitigation: {config.get('mitigation_path', 'None')}")
        print()
