# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Configuration validator for all 8 config combinations."""

from typing import Dict, Optional, Tuple
from enum import Enum


class ConfigID(str, Enum):
    """All 8 valid configuration combinations."""
    ILP32_SIGNED_32BIT = "ilp32_signed_32bit"
    ILP32_UNSIGNED_32BIT = "ilp32_unsigned_32bit"
    ILP32_SIGNED_64BIT = "ilp32_signed_64bit"
    ILP32_UNSIGNED_64BIT = "ilp32_unsigned_64bit"
    LP64_SIGNED_32BIT = "lp64_signed_32bit"
    LP64_UNSIGNED_32BIT = "lp64_unsigned_32bit"
    LP64_SIGNED_64BIT = "lp64_signed_64bit"
    LP64_UNSIGNED_64BIT = "lp64_unsigned_64bit"


class ConfigValidator:
    """Validate and normalize environment configurations."""
    
    # All 8 valid configuration combinations
    VALID_CONFIGS: Dict[str, Dict[str, any]] = {
        ConfigID.ILP32_SIGNED_32BIT.value: {
            'hardware_model': 'ILP32',
            'time_t_size_bits': 32,
            'time_t_signed': 'signed',
            'description': 'ILP32 with signed 32-bit time_t (classic Y2038 scenario)'
        },
        ConfigID.ILP32_UNSIGNED_32BIT.value: {
            'hardware_model': 'ILP32',
            'time_t_size_bits': 32,
            'time_t_signed': 'unsigned',
            'description': 'ILP32 with unsigned 32-bit time_t (Y2106 scenario)'
        },
        ConfigID.ILP32_SIGNED_64BIT.value: {
            'hardware_model': 'ILP32',
            'time_t_size_bits': 64,
            'time_t_signed': 'signed',
            'description': 'ILP32 with signed 64-bit time_t (narrowing pattern risks)'
        },
        ConfigID.ILP32_UNSIGNED_64BIT.value: {
            'hardware_model': 'ILP32',
            'time_t_size_bits': 64,
            'time_t_signed': 'unsigned',
            'description': 'ILP32 with unsigned 64-bit time_t (narrowing pattern risks)'
        },
        ConfigID.LP64_SIGNED_32BIT.value: {
            'hardware_model': 'LP64',
            'time_t_size_bits': 32,
            'time_t_signed': 'signed',
            'description': 'LP64 with signed 32-bit time_t (rare, Y2038 scenario)'
        },
        ConfigID.LP64_UNSIGNED_32BIT.value: {
            'hardware_model': 'LP64',
            'time_t_size_bits': 32,
            'time_t_signed': 'unsigned',
            'description': 'LP64 with unsigned 32-bit time_t (rare, Y2106 scenario)'
        },
        ConfigID.LP64_SIGNED_64BIT.value: {
            'hardware_model': 'LP64',
            'time_t_size_bits': 64,
            'time_t_signed': 'signed',
            'description': 'LP64 with signed 64-bit time_t (modern safe, narrowing pattern risks)'
        },
        ConfigID.LP64_UNSIGNED_64BIT.value: {
            'hardware_model': 'LP64',
            'time_t_size_bits': 64,
            'time_t_signed': 'unsigned',
            'description': 'LP64 with unsigned 64-bit time_t (rare, narrowing pattern risks)'
        },
    }
    
    @classmethod
    def get_config_id(cls, config: Dict) -> Optional[str]:
        """
        Get config_id from config dict.
        
        Args:
            config: Environment configuration dict
        
        Returns:
            Config ID string or None if invalid
        """
        hardware_model = config.get('hardware_model', '').upper()
        time_t_size = config.get('time_t_size_bits')
        time_t_signed = config.get('time_t_signed', '').lower()
        
        # Normalize
        if hardware_model not in ['ILP32', 'LP64']:
            return None
        if time_t_size not in [32, 64]:
            return None
        if time_t_signed not in ['signed', 'unsigned']:
            return None
        
        # Generate config_id
        config_id = f"{hardware_model.lower()}_{time_t_signed}_{time_t_size}bit"
        
        # Validate it's one of the 8 valid configs
        if config_id in cls.VALID_CONFIGS:
            return config_id
        
        return None
    
    @classmethod
    def validate_config(cls, config: Dict) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validate config and return (is_valid, config_id, error_message).
        
        Args:
            config: Environment configuration dict
        
        Returns:
            Tuple of (is_valid, config_id, error_message)
        """
        # Check required fields
        required_fields = ['hardware_model', 'time_t_size_bits', 'time_t_signed']
        missing_fields = [f for f in required_fields if f not in config]
        if missing_fields:
            return False, None, f"Missing required fields: {', '.join(missing_fields)}"
        
        # Get config_id
        config_id = cls.get_config_id(config)
        if not config_id:
            return False, None, f"Invalid configuration combination: {config.get('hardware_model')}/{config.get('time_t_size_bits')}bit/{config.get('time_t_signed')}"
        
        # Validate against known configs
        expected = cls.VALID_CONFIGS[config_id]
        if (config.get('hardware_model').upper() != expected['hardware_model'] or
            config.get('time_t_size_bits') != expected['time_t_size_bits'] or
            config.get('time_t_signed').lower() != expected['time_t_signed']):
            return False, config_id, "Config values don't match expected config_id"
        
        return True, config_id, None
    
    @classmethod
    def normalize_config(cls, config: Dict) -> Dict:
        """
        Normalize config to standard format.
        
        Args:
            config: Environment configuration dict
        
        Returns:
            Normalized config dict
        """
        normalized = config.copy()
        
        # Normalize hardware_model
        if 'hardware_model' in normalized:
            normalized['hardware_model'] = normalized['hardware_model'].upper()
            if normalized['hardware_model'] not in ['ILP32', 'LP64']:
                raise ValueError(f"Invalid hardware_model: {normalized['hardware_model']}")
        
        # Normalize time_t_signed
        if 'time_t_signed' in normalized:
            normalized['time_t_signed'] = normalized['time_t_signed'].lower()
            if normalized['time_t_signed'] not in ['signed', 'unsigned']:
                raise ValueError(f"Invalid time_t_signed: {normalized['time_t_signed']}")
        
        # Ensure time_t_size_bits is int
        if 'time_t_size_bits' in normalized:
            normalized['time_t_size_bits'] = int(normalized['time_t_size_bits'])
            if normalized['time_t_size_bits'] not in [32, 64]:
                raise ValueError(f"Invalid time_t_size_bits: {normalized['time_t_size_bits']}")
        
        return normalized
    
    @classmethod
    def get_config_info(cls, config_id: str) -> Optional[Dict]:
        """
        Get information about a config_id.
        
        Args:
            config_id: Configuration ID
        
        Returns:
            Config info dict or None if invalid
        """
        return cls.VALID_CONFIGS.get(config_id)
    
    @classmethod
    def is_overflow_risk(cls, config_id: str) -> bool:
        """
        Check if config has direct overflow risk (32-bit time_t).
        
        Args:
            config_id: Configuration ID
        
        Returns:
            True if config has overflow risk
        """
        config_info = cls.VALID_CONFIGS.get(config_id)
        if not config_info:
            return False
        return config_info['time_t_size_bits'] == 32
    
    @classmethod
    def is_narrowing_risk_only(cls, config_id: str) -> bool:
        """
        Check if config only has narrowing pattern risks (64-bit time_t).
        
        Args:
            config_id: Configuration ID
        
        Returns:
            True if config only has narrowing risks
        """
        config_info = cls.VALID_CONFIGS.get(config_id)
        if not config_info:
            return False
        return config_info['time_t_size_bits'] == 64
