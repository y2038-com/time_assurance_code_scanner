# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Format string parser for printf/scanf with ABI-aware width mapping."""

import re
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass


@dataclass
class FormatSpec:
    """A format specifier from a format string."""
    specifier: str  # e.g., "%d", "%ld", "%lld"
    position: int  # Position in argument list (0-based, accounting for format string)
    width_bits: Optional[int]  # Expected width in bits under current ABI
    is_signed: bool  # True for signed specifiers (%d, %ld), False for unsigned (%u, %lu)
    is_hex: bool  # True for hex specifiers (%x, %lx)


class FormatSpecifierParser:
    """Parses printf/scanf format strings with ABI-aware width mapping."""
    
    def __init__(self, abi_config: Optional[Dict[str, Any]] = None):
        """
        Initialize parser with ABI configuration.
        
        Args:
            abi_config: Environment configuration with hardware_model, time_t_size_bits, etc.
        """
        self.abi_config = abi_config or {}
        self.abi = self.abi_config.get('hardware_model', 'LP64')
        self.time_t_size = self.abi_config.get('time_t_size_bits', 64)
        self.time_t_signed = self.abi_config.get('time_t_signed', 'signed')
        
        # ABI-aware format specifier width mapping
        if self.abi == 'ILP32':
            self.spec_widths = {
                '%d': 32, '%i': 32, '%u': 32,
                '%ld': 32, '%li': 32, '%lu': 32,
                '%lld': 64, '%lli': 64, '%llu': 64,
                '%x': 32, '%lx': 32, '%llx': 64,
                '%jd': 64, '%ju': 64, '%jx': 64,  # intmax_t (typically 64-bit)
            }
        else:  # LP64
            self.spec_widths = {
                '%d': 32, '%i': 32, '%u': 32,
                '%ld': 64, '%li': 64, '%lu': 64,
                '%lld': 64, '%lli': 64, '%llu': 64,
                '%x': 32, '%lx': 64, '%llx': 64,
                '%jd': 64, '%ju': 64, '%jx': 64,  # intmax_t (typically 64-bit)
            }
        
        # Signed/unsigned mapping
        self.signed_specs = {'%d', '%i', '%ld', '%li', '%lld', '%lli', '%jd'}
        self.unsigned_specs = {'%u', '%lu', '%llu', '%ju'}
        self.hex_specs = {'%x', '%lx', '%llx', '%jx'}
    
    def parse_format_string(self, format_str: str) -> List[FormatSpec]:
        """
        Parse format string into specifiers.
        
        Handles:
        - Literal strings: "printf("%d", t)"
        - Concatenated strings: "printf("%" "d", t)"
        
        Args:
            format_str: Format string (may be literal or need preprocessing)
        
        Returns:
            List of FormatSpec objects
        """
        if not format_str:
            return []
        
        # Remove string literal concatenation (C feature: "a" "b" -> "ab")
        format_str = re.sub(r'"\s*"', '', format_str)
        
        # Remove outer quotes if present
        format_str = format_str.strip('"\'')
        
        specs = []
        position = 0
        
        # Pattern to match format specifiers: %[flags][width][.precision][length]specifier
        # For MVP, focus on common integer specifiers
        pattern = r'%[-+0 #]*\d*\.?\d*([hl]*)([diuoxX])'
        
        for match in re.finditer(pattern, format_str):
            length_modifier = match.group(1)  # h, l, ll, etc.
            spec_char = match.group(2).lower()  # d, i, u, o, x
            
            # Build specifier string
            if length_modifier == 'll':
                specifier = f'%ll{spec_char}'
            elif length_modifier == 'l':
                specifier = f'%l{spec_char}'
            elif length_modifier == 'h':
                specifier = f'%h{spec_char}'
            else:
                specifier = f'%{spec_char}'
            
            # Check for intmax_t (j modifier)
            if 'j' in length_modifier:
                specifier = f'%j{spec_char}'
            
            width_bits = self.spec_widths.get(specifier)
            is_signed = specifier in self.signed_specs
            is_hex = specifier in self.hex_specs
            
            specs.append(FormatSpec(
                specifier=specifier,
                position=position,
                width_bits=width_bits,
                is_signed=is_signed,
                is_hex=is_hex
            ))
            
            position += 1
        
        return specs
    
    def check_specifier_match(
        self,
        spec: FormatSpec,
        time_t_size: int,
        time_t_signed: str
    ) -> Tuple[bool, str]:
        """
        Check if format specifier matches time_t under ABI.
        
        Args:
            spec: FormatSpec to check
            time_t_size: Size of time_t in bits (32 or 64)
            time_t_signed: "signed" or "unsigned"
        
        Returns:
            (is_match, reason)
        """
        if spec.width_bits is None:
            return True, "Unknown specifier width"
        
        # Check width mismatch
        width_mismatch = spec.width_bits != time_t_size
        
        # Check sign mismatch
        sign_mismatch = False
        if time_t_signed == "signed" and not spec.is_signed:
            sign_mismatch = True
        elif time_t_signed == "unsigned" and spec.is_signed:
            sign_mismatch = True
        
        if width_mismatch and sign_mismatch:
            return False, f"Width mismatch ({spec.width_bits}-bit specifier vs {time_t_size}-bit time_t) and sign mismatch"
        elif width_mismatch:
            return False, f"Width mismatch ({spec.width_bits}-bit specifier vs {time_t_size}-bit time_t)"
        elif sign_mismatch:
            return False, f"Sign mismatch ({'signed' if spec.is_signed else 'unsigned'} specifier vs {time_t_signed} time_t)"
        
        return True, "Match"
    
    def check_mismatch(self, spec: str, time_t_size: int) -> bool:
        """
        Check if format specifier width mismatches time_t size.
        
        Args:
            spec: Format specifier (e.g., "%d", "%ld")
            time_t_size: Size of time_t in bits (32 or 64)
        
        Returns:
            True if width mismatch detected
        """
        expected_width = self.spec_widths.get(spec)
        if expected_width is None:
            return False  # Unknown specifier
        return expected_width != time_t_size
