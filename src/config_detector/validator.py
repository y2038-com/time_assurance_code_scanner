# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Validation for LLM configuration responses."""

import json
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import jsonschema

from tacs.core.env_capabilities import (
    CAPABILITY_FIELDS,
    capability,
    capability_of,
    setting,
)


class ConfigValidator:
    """Validator for configuration detection results."""
    
    def __init__(self):
        """Initialize the validator with the environment schema."""
        # Load the environment schema
        # Try multiple possible paths
        possible_paths = [
            Path(__file__).parent.parent / "envui" / "schemas" / "environment.schema.json",
            Path(__file__).parent.parent.parent / "envui" / "schemas" / "environment.schema.json",
        ]
        
        schema_path = None
        for path in possible_paths:
            if path.exists():
                schema_path = path
                break
        
        if schema_path is None:
            raise FileNotFoundError(f"Could not find environment.schema.json in: {possible_paths}")
        
        with open(schema_path, 'r', encoding='utf-8') as f:
            self.schema = json.load(f)
    
    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate configuration against schema and business rules.
        
        Args:
            config: Configuration dictionary to validate
        
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Schema validation
        try:
            jsonschema.validate(instance=config, schema=self.schema)
        except jsonschema.ValidationError as e:
            errors.append(f"Schema validation error: {e.message}")
        except jsonschema.SchemaError as e:
            errors.append(f"Schema error: {e.message}")
        
        # Business rule validation
        errors.extend(self._validate_business_rules(config))
        
        return len(errors) == 0, errors
    
    def _validate_business_rules(self, config: Dict[str, Any]) -> List[str]:
        """Validate business rules that aren't in the schema."""
        errors = []
        
        # The setting says more than the support flag, so the two can contradict
        # each other. Unknown support contradicts only "not_available", which
        # asserts the feature is absent.
        support = capability_of(config, "d_time_bits_supported")
        current = config.get("d_time_bits_setting")

        # Rule 1: If d_time_bits_supported is false, d_time_bits_setting must be "not_available"
        if support is False and current != "not_available":
            errors.append(
                "d_time_bits_setting must be 'not_available' when "
                "d_time_bits_supported is false"
            )
        
        # Rule 2: If d_time_bits_supported is true, d_time_bits_setting cannot be "not_available"
        if support is True and current == "not_available":
            errors.append(
                "d_time_bits_setting cannot be 'not_available' when "
                "d_time_bits_supported is true"
            )

        # Rule 2b: unknown support cannot claim the feature is unavailable
        if support is None and current == "not_available":
            errors.append(
                "d_time_bits_setting cannot be 'not_available' when "
                "d_time_bits_supported is unknown; use 'unknown'"
            )
        
        # Rule 3: If c_library is "other", c_library_other_text should be provided (optional but recommended)
        # This is handled by the schema, but we can add a warning
        
        # Rule 4: toolchain_flags should be a list
        if "toolchain_flags" in config:
            if not isinstance(config["toolchain_flags"], list):
                errors.append("toolchain_flags must be a list")
        
        return errors
    
    def normalize(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize configuration values (e.g., convert strings to proper types).
        
        Args:
            config: Configuration dictionary to normalize
        
        Returns:
            Normalized configuration dictionary
        """
        normalized = config.copy()
        
        # Ensure time_t_size_bits is an integer
        if "time_t_size_bits" in normalized:
            try:
                normalized["time_t_size_bits"] = int(normalized["time_t_size_bits"])
            except (ValueError, TypeError):
                pass
        
        # Capability fields are tri-state. Reading them as plain booleans turned
        # "unknown" into False, which is the assertion they exist to avoid.
        for field in CAPABILITY_FIELDS:
            if field in normalized:
                normalized[field] = capability(normalized[field])

        if "d_time_bits_setting" in normalized:
            normalized["d_time_bits_setting"] = setting(normalized["d_time_bits_setting"])
        
        # Ensure toolchain_flags is a list
        if "toolchain_flags" in normalized:
            if not isinstance(normalized["toolchain_flags"], list):
                normalized["toolchain_flags"] = []
        
        # Normalize os_or_rtos (can be null)
        if "os_or_rtos" in normalized:
            if normalized["os_or_rtos"] == "" or normalized["os_or_rtos"] is None:
                normalized["os_or_rtos"] = None
        
        return normalized
