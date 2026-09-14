# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Dict, Any, Optional


class FieldDeriver:
    """Derives computed fields from environment configuration."""
    
    def derive_fields(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Derive scenario_hint and mitigation_path from configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Configuration with derived fields added
        """
        derived_config = config.copy()
        
        # Derive scenario_hint
        scenario_hint = self._derive_scenario_hint(config)
        derived_config['scenario_hint'] = scenario_hint
        
        # Derive mitigation_path
        mitigation_path = self._derive_mitigation_path(config, scenario_hint)
        derived_config['mitigation_path'] = mitigation_path
        
        return derived_config
    
    def _derive_scenario_hint(self, config: Dict[str, Any]) -> str:
        """
        Derive scenario_hint from hardware_model, time_t_size_bits, time_t_signed, and time64_functions_available.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            Scenario hint string
        """
        hardware_model = config.get('hardware_model', '')
        time_t_size_bits = config.get('time_t_size_bits', 0)
        time_t_signed = config.get('time_t_signed', '')
        time64_functions_available = config.get('time64_functions_available', False)
        
        # LP64 cases
        if hardware_model == 'LP64':
            return 'LP64-64bit-N/A'
        
        # ILP32 cases
        if hardware_model == 'ILP32':
            if time_t_size_bits == 64:
                return 'ILP32-64bit-N/A'
            elif time_t_size_bits == 32:
                if time_t_signed == 'unsigned':
                    time64_suffix = 'yes' if time64_functions_available else 'no'
                    return f'ILP32-32bit-unsigned-time64_{time64_suffix}'
                elif time_t_signed == 'signed':
                    time64_suffix = 'yes' if time64_functions_available else 'no'
                    return f'ILP32-32bit-signed-time64_{time64_suffix}'
        
        # Fallback for invalid combinations
        return 'LP64-64bit-N/A'
    
    def _derive_mitigation_path(self, config: Dict[str, Any], scenario_hint: str) -> Optional[str]:
        """
        Derive mitigation_path based on scenario_hint.
        
        Args:
            config: Configuration dictionary
            scenario_hint: Derived scenario hint
            
        Returns:
            Mitigation path string or None
        """
        # Only required for the risky ILP32-32bit-signed-time64_no scenario
        if scenario_hint == 'ILP32-32bit-signed-time64_no':
            # For now, default to 'upgrade_env' - this could be made configurable
            return 'upgrade_env'
        
        return None
    
    def get_scenario_summary(self, config: Dict[str, Any]) -> str:
        """
        Generate a one-line summary of the scenario.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            One-line summary string
        """
        hardware_model = config.get('hardware_model', 'unknown')
        time_t_size_bits = config.get('time_t_size_bits', 0)
        time_t_signed = config.get('time_t_signed', 'unknown')
        time64_functions_available = config.get('time64_functions_available', False)
        d_time_bits_supported = config.get('d_time_bits_supported', False)
        d_time_bits_setting = config.get('d_time_bits_setting', 'unknown')
        c_library = config.get('c_library', 'unknown')
        
        # Format time64 availability
        time64_str = 'yes' if time64_functions_available else 'no'
        
        # Format _TIME_BITS support
        if d_time_bits_supported:
            d_time_str = f"supported:{d_time_bits_setting}"
        else:
            d_time_str = "not_supported"
        
        # Format C library
        c_lib_str = c_library
        if c_library == 'other':
            c_lib_other = config.get('c_library_other_text', '')
            if c_lib_other:
                c_lib_str = f"{c_library}({c_lib_other})"
        
        return f"{hardware_model}, time_t={time_t_size_bits} {time_t_signed}, time64={time64_str}, _TIME_BITS={d_time_str}, c_lib={c_lib_str}"
