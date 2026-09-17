# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Dict, Any, Optional

from tacs.core.env_capabilities import describe_capability, setting_of, time64_suffix

#: Scenario hints that oblige the config to name a mitigation path. Unknown time64
#: availability is included: the risk it would mitigate has not been ruled out.
MITIGATION_REQUIRED_HINTS = (
    'ILP32-32bit-signed-time64_no',
    'ILP32-32bit-signed-time64_unknown',
)


def requires_mitigation_path(scenario_hint: str) -> bool:
    """Whether a hint describes a scenario that must name a mitigation path.

    Hints are composed left to right, so the risky scenario can carry a trailing
    segment such as ``-N/A``. Matching the leading segments keeps this in step
    with the schema, which asks the same question as a pattern. This is a
    validation-layer reading of a derived label; scan logic reads the structured
    ABI fields instead.
    """
    hint = scenario_hint or ''
    return any(
        hint == required or hint.startswith(f'{required}-')
        for required in MITIGATION_REQUIRED_HINTS
    )


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
        # The hint carries the capability's three states through, so a config that
        # never established time64 availability is not labelled as lacking it.
        suffix = time64_suffix(config.get('time64_functions_available'))
        
        # LP64 cases
        if hardware_model == 'LP64':
            return 'LP64-64bit-N/A'
        
        # ILP32 cases
        if hardware_model == 'ILP32':
            if time_t_size_bits == 64:
                return 'ILP32-64bit-N/A'
            elif time_t_size_bits == 32:
                if time_t_signed == 'unsigned':
                    return f'ILP32-32bit-unsigned-time64_{suffix}'
                elif time_t_signed == 'signed':
                    return f'ILP32-32bit-signed-time64_{suffix}'
        
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
        # Required for the risky ILP32-32bit-signed scenarios. Unknown time64
        # availability counts here: a mitigation path is a decision about risk that
        # has not been ruled out, not a claim that the entry points are missing.
        if requires_mitigation_path(scenario_hint):
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
        c_library = config.get('c_library', 'unknown')
        d_time_bits_setting = setting_of(config)
        
        # Format time64 availability
        time64_str = time64_suffix(config.get('time64_functions_available'))
        
        # Format _TIME_BITS support, keeping unknown apart from unsupported
        d_time_str = describe_capability(
            config.get('d_time_bits_supported'),
            yes=f"supported:{d_time_bits_setting}",
            no="not_supported",
            unknown=f"support_unknown:{d_time_bits_setting}",
        )
        
        # Format C library
        c_lib_str = c_library
        if c_library == 'other':
            c_lib_other = config.get('c_library_other_text', '')
            if c_lib_other:
                c_lib_str = f"{c_library}({c_lib_other})"
        
        return f"{hardware_model}, time_t={time_t_size_bits} {time_t_signed}, time64={time64_str}, _TIME_BITS={d_time_str}, c_lib={c_lib_str}"
