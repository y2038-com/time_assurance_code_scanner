from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional

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
        
        # Rule 4: toolchain_flags pattern validation
        toolchain_flags = config.get('toolchain_flags', [])
        flag_pattern = r'^(-{1,2}[A-Za-z0-9_][A-Za-z0-9_-]*(=.+)?|-[DU][A-Za-z0-9_]+(=.+)?)$'
        
        import re
        for flag in toolchain_flags:
            if not re.match(flag_pattern, flag):
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
