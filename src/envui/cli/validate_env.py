# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional

from envui.cli.derive_fields import requires_mitigation_path
from tacs.core.env_capabilities import capability_of

try:
    import jsonschema
except ImportError:
    jsonschema = None


class EnvironmentValidator:
    """Validates environment configuration against JSON schema and business rules."""
    
    def __init__(self, schema_path: str | None = None):
        """
        Initialize the validator.

        Args:
            schema_path: Path to the JSON schema file (defaults to package schema)
        """
        if schema_path is None:
            pkg_schema = Path(__file__).resolve().parent.parent / "schemas" / "environment.schema.json"
            schema_path = str(
                pkg_schema if pkg_schema.exists() else Path("envui/schemas/environment.schema.json")
            )
        self.schema_path = Path(schema_path)
        self.schema = self._load_schema()
    
    def _load_schema(self) -> Dict[str, Any]:
        """Load the JSON schema."""
        with open(self.schema_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def validate(self, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate configuration against schema and business rules.
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # JSON Schema validation (if jsonschema is available)
        if jsonschema is not None:
            try:
                jsonschema.validate(config, self.schema)
            except jsonschema.ValidationError as e:
                errors.append(f"Schema validation error: {e.message}")
            except Exception as e:
                errors.append(f"Schema validation failed: {e}")
        else:
            # Fallback: basic required field validation
            required_fields = [
                'hardware_model', 'time_t_size_bits', 'time_t_signed',
                'time64_functions_available', 'd_time_bits_supported', 
                'd_time_bits_setting', 'c_library'
            ]
            for field in required_fields:
                if field not in config:
                    errors.append(f"Missing required field: {field}")
        
        # Additional business rule validations
        errors.extend(self._validate_business_rules(config))
        
        return len(errors) == 0, errors
    
    def _validate_business_rules(self, config: Dict[str, Any]) -> List[str]:
        """Validate additional business rules not covered by JSON schema."""
        errors = []
        
        # Rule 1: d_time_bits_supported vs d_time_bits_setting. Read as a tri-state:
        # a truth test would hold an unknown config to the rule for a known-absent
        # one, and demand it say 'not_available'.
        d_time_bits_supported = capability_of(config, 'd_time_bits_supported')
        d_time_bits_setting = config.get('d_time_bits_setting', '')
        
        if d_time_bits_supported is False and d_time_bits_setting != 'not_available':
            errors.append("If d_time_bits_supported=false, d_time_bits_setting must be 'not_available'")
        
        if d_time_bits_supported is True and d_time_bits_setting == 'not_available':
            errors.append("If d_time_bits_supported=true, d_time_bits_setting cannot be 'not_available'")
        
        if d_time_bits_supported is None and d_time_bits_setting == 'not_available':
            errors.append("If d_time_bits_supported is unknown, d_time_bits_setting cannot be 'not_available'; use 'unknown'")
        
        # Rule 2: c_library="other" requires c_library_other_text
        c_library = config.get('c_library', '')
        c_library_other_text = config.get('c_library_other_text', '')
        
        if c_library == 'other' and not c_library_other_text.strip():
            errors.append("If c_library='other', c_library_other_text must be non-empty")
        
        # Rule 3: the risky ILP32-32bit-signed scenarios require mitigation_path
        scenario_hint = config.get('scenario_hint', '')
        mitigation_path = config.get('mitigation_path')
        
        if requires_mitigation_path(scenario_hint) and mitigation_path is None:
            errors.append(f"If scenario_hint='{scenario_hint}', mitigation_path is required")
        
        # Rule 4: toolchain_flags pattern validation. Malformed input is what this
        # method exists to report, so a non-list value or a non-string entry
        # becomes an error rather than a TypeError out of iteration or re.match.
        toolchain_flags = config.get('toolchain_flags', [])
        flag_pattern = r'^(-{1,2}[A-Za-z0-9_][A-Za-z0-9_-]*(=.+)?|-[DU][A-Za-z0-9_]+(=.+)?)$'
        
        import re
        if not isinstance(toolchain_flags, list):
            errors.append(
                f"toolchain_flags must be a list, found {type(toolchain_flags).__name__}"
            )
        else:
            for flag in toolchain_flags:
                if not isinstance(flag, str):
                    errors.append(
                        f"Invalid toolchain flag {flag!r}: must be a string, "
                        f"found {type(flag).__name__}"
                    )
                elif not re.match(flag_pattern, flag):
                    errors.append(f"Invalid toolchain flag format: '{flag}'. Must match pattern: {flag_pattern}")
        
        return errors
    
    def normalize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize configuration by removing empty optional fields.
        
        Args:
            config: Configuration dictionary to normalize
            
        Returns:
            Normalized configuration dictionary
        """
        normalized = config.copy()
        
        # Remove empty optional string fields
        optional_string_fields = ['os_or_rtos', 'c_library_other_text', 'notes']
        for field in optional_string_fields:
            if field in normalized and not normalized[field].strip():
                del normalized[field]
        
        # Remove empty toolchain_flags array
        if 'toolchain_flags' in normalized and not normalized['toolchain_flags']:
            del normalized['toolchain_flags']
        
        return normalized
