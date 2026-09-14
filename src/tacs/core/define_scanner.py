# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass


@dataclass
class DefineMatch:
    """Represents a #define match with context."""
    macro_name: str
    macro_value: str
    file_path: str
    line_number: int
    full_line: str
    subcheck_type: str
    confidence: float
    needs_followup_scan: bool


class DefineScanner:
    """Smart scanner for #define statements with Y2038-specific subchecks."""
    
    def __init__(self):
        """Initialize the define scanner with smart patterns."""
        
        # Time type patterns (word boundaries to avoid false matches)
        self.time_type_patterns = [
            r'\btime_t\b',
            r'\bclock_t\b', 
            r'\btimer_t\b',
            r'\bsuseconds_t\b',
            r'\buseconds_t\b',
            r'\btimespec_t\b',
            r'\btimeval_t\b'
        ]
        
        # Time function patterns (more specific to avoid hardware clocks)
        self.time_function_patterns = [
            r'\btime\s*\(',           # time() function calls
            r'\bclock_gettime\b',     # clock_gettime function
            r'\bgettimeofday\b',      # gettimeofday function
            r'\blocaltime\b',         # localtime function
            r'\bgmtime\b',            # gmtime function
            r'\bmktime\b',            # mktime function
            r'\btimespec_get\b',      # timespec_get function
            r'\btimespec_getres\b',   # timespec_getres function
            r'\bclock\s*\(',          # clock() function calls (not hardware)
            r'\bsleep\s*\(',          # sleep function calls
            r'\busleep\s*\(',         # usleep function calls
            r'\bnanosleep\s*\(',      # nanosleep function calls
        ]
        
        # Time struct patterns
        self.time_struct_patterns = [
            r'\bstruct\s+timespec\b',
            r'\bstruct\s+timeval\b',
            r'\bstruct\s+tm\b',
            r'\bstruct\s+itimerspec\b',
            r'\bstruct\s+itimerval\b'
        ]
        
        # Time constant patterns (only specific time-related constants)
        self.time_constant_patterns = [
            r'\b60\b',           # seconds per minute
            r'\b3600\b',         # seconds per hour  
            r'\b86400\b',        # seconds per day
            r'\b604800\b',       # seconds per week
            r'\b2592000\b',      # seconds per month (30 days)
            r'\b31536000\b',     # seconds per year (365 days)
            r'\b31557600\b'      # seconds per year (365.25 days)
        ]
        
        # Compile patterns for efficiency
        self.time_type_regex = re.compile('|'.join(self.time_type_patterns))
        self.time_function_regex = re.compile('|'.join(self.time_function_patterns))
        self.time_struct_regex = re.compile('|'.join(self.time_struct_patterns))
        self.time_constant_regex = re.compile('|'.join(self.time_constant_patterns))
        
        # Pattern for #define statements
        self.define_pattern = re.compile(
            r'#define\s+(\w+)\s+(.*?)(?:\n|$)',
            re.MULTILINE
        )
    
    def scan_line_for_defines(self, line: str, file_path: str, line_number: int) -> List[DefineMatch]:
        """
        Scan a single line for #define statements and apply subchecks.
        
        Args:
            line: Line content to scan
            file_path: Path to the file
            line_number: Line number in the file
            
        Returns:
            List of DefineMatch objects for matches that pass subchecks
        """
        matches = []
        
        # Find #define statements in the line
        for match in self.define_pattern.finditer(line):
            macro_name = match.group(1)
            macro_value = match.group(2).strip()
            
            if not macro_value:
                continue
            
            # Apply subchecks
            subcheck_result = self._apply_subchecks(macro_name, macro_value, line)
            
            if subcheck_result:
                define_match = DefineMatch(
                    macro_name=macro_name,
                    macro_value=macro_value,
                    file_path=file_path,
                    line_number=line_number,
                    full_line=line.strip(),
                    subcheck_type=subcheck_result['type'],
                    confidence=subcheck_result['confidence'],
                    needs_followup_scan=subcheck_result['needs_followup']
                )
                matches.append(define_match)
        
        return matches
    
    def _apply_subchecks(self, macro_name: str, macro_value: str, full_line: str) -> Optional[Dict]:
        """
        Apply smart subchecks to determine if a #define is Y2038-relevant.
        
        Args:
            macro_name: Name of the macro
            macro_value: Value of the macro
            full_line: Complete line for context
            
        Returns:
            Dict with subcheck results, or None if no subcheck matches
        """
        macro_value_lower = macro_value.lower()
        full_line_lower = full_line.lower()
        
        # Skip hardware-related definitions
        if self._is_hardware_related(macro_name, macro_value, full_line):
            return None
        
        # Subcheck 1: Time Type Alias
        if self.time_type_regex.search(macro_value_lower):
            return {
                'type': 'time_type_alias',
                'confidence': 0.95,
                'needs_followup': True
            }
        
        # Subcheck 2: Time Function Alias  
        if self.time_function_regex.search(macro_value_lower):
            return {
                'type': 'time_function_alias', 
                'confidence': 0.9,
                'needs_followup': True
            }
        
        # Subcheck 3: Time Struct Alias
        if self.time_struct_regex.search(macro_value_lower):
            return {
                'type': 'time_struct_alias',
                'confidence': 0.95,
                'needs_followup': True
            }
        
        # Subcheck 4: Time Constants (only in time-related context)
        if self.time_constant_regex.search(macro_value_lower):
            # Additional context check - only flag if the macro name suggests time usage
            time_context_patterns = [
                r'time', r'clock', r'timer', r'delay', r'sleep', r'wait',
                r'timeout', r'interval', r'period', r'frequency', r'rate',
                r'sec', r'min', r'hour', r'day', r'week', r'month', r'year',
                r'seconds', r'minutes', r'hours', r'days', r'weeks', r'months', r'years',
                r'per', r'each', r'every', r'between', r'duration', r'length'
            ]
            
            macro_name_lower = macro_name.lower()
            for pattern in time_context_patterns:
                if re.search(r'\b' + pattern + r'\b', macro_name_lower):
                    return {
                        'type': 'time_constant',
                        'confidence': 0.8,
                        'needs_followup': False
                    }
        
        return None
    
    def _is_hardware_related(self, macro_name: str, macro_value: str, full_line: str) -> bool:
        """
        Check if a #define is hardware-related and should be excluded.
        
        Args:
            macro_name: Name of the macro
            macro_value: Value of the macro
            full_line: Complete line for context
            
        Returns:
            True if hardware-related (should be excluded)
        """
        macro_name_lower = macro_name.lower()
        macro_value_lower = macro_value.lower()
        full_line_lower = full_line.lower()
        
        # Hardware-related patterns to exclude
        hardware_patterns = [
            # Hardware registers
            r'reg', r'ctl', r'ctrl', r'cr', r'dr', r'sr', r'status',
            r'addr', r'base', r'offset', r'bit', r'mask', r'flag',
            r'freq', r'speed', r'rate', r'hz', r'mhz', r'khz',
            r'div', r'divider', r'prescaler', r'counter',
            r'pin', r'gpio', r'port', r'bus', r'i2c', r'i3c', r'spi', r'uart',
            r'dma', r'interrupt', r'irq', r'isr',
            r'power', r'voltage', r'current', r'temp',
            r'chip', r'device', r'peripheral', r'controller',
            r'rcar', r'npcx', r'sdmmc', r'xuartps', r'renesas',  # Specific hardware
            r'rising', r'falling', r'high', r'low', r'ns', r'us', r'ms',  # Timing specs
        ]
        
        # Check macro name for hardware patterns
        for pattern in hardware_patterns:
            if re.search(r'\b' + pattern + r'\b', macro_name_lower):
                return True
        
        # Check macro value for hardware patterns
        for pattern in hardware_patterns:
            if re.search(r'\b' + pattern + r'\b', macro_value_lower):
                return True
        
        # Check for hex values (common in hardware)
        if re.search(r'0x[0-9a-fA-F]+', macro_value):
            return True
        
        # Check for specific hardware keywords in comments
        hardware_comment_patterns = [
            r'register', r'control', r'status', r'address', r'frequency',
            r'speed', r'rate', r'divider', r'prescaler', r'counter',
            r'pin', r'port', r'bus', r'interrupt', r'power', r'voltage',
            r'chip', r'device', r'peripheral', r'controller',
            r'rising', r'falling', r'high', r'low', r'timing', r'delay',
            r'nanoseconds', r'microseconds', r'milliseconds', r'ns', r'us', r'ms'
        ]
        
        for pattern in hardware_comment_patterns:
            if re.search(r'\b' + pattern + r'\b', full_line_lower):
                return True
        
        return False
    
    def generate_followup_rules(self, define_matches: List[DefineMatch]) -> List[Dict]:
        """
        Generate new rules for macros that need follow-up scanning.
        
        Args:
            define_matches: List of DefineMatch objects
            
        Returns:
            List of new rule dictionaries
        """
        new_rules = []
        
        for match in define_matches:
            if not match.needs_followup_scan:
                continue
            
            # Create a rule for the macro name itself
            rule = {
                "symbol": match.macro_name,
                "risk": "high" if match.subcheck_type in ['time_type_alias', 'time_struct_alias'] else "medium",
                "category": "macro",
                "description": f"Discovered {match.subcheck_type} macro: {match.macro_name} -> {match.macro_value}",
                "discovered": True,
                "discovery_type": "define",
                "source_file": match.file_path,
                "source_line": match.line_number,
                "confidence": match.confidence
            }
            new_rules.append(rule)
        
        return new_rules
    
    def print_discovered_defines(self, define_matches: List[DefineMatch]):
        """Print discovered #define matches."""
        from tacs.core.status_logger import StatusLogger
        
        if not define_matches:
            StatusLogger.timestamped_print("No Y2038-relevant #define statements discovered")
            return
        
        StatusLogger.timestamped_print(f"Discovered {len(define_matches)} Y2038-relevant #define statements:")
        
        # Group by subcheck type, then by unique macro_name -> macro_value pairs
        by_type = {}
        for match in define_matches:
            if match.subcheck_type not in by_type:
                by_type[match.subcheck_type] = {}
            # Use (macro_name, macro_value) as key for uniqueness
            key = (match.macro_name, match.macro_value)
            if key not in by_type[match.subcheck_type]:
                by_type[match.subcheck_type][key] = 0
            by_type[match.subcheck_type][key] += 1
        
        for subcheck_type, unique_matches in by_type.items():
            total_count = sum(unique_matches.values())
            print(f"  {subcheck_type}: {total_count} matches")
            # Sort by count (descending) then by macro name
            sorted_matches = sorted(unique_matches.items(), key=lambda x: (-x[1], x[0][0]))
            for (macro_name, macro_value), count in sorted_matches:
                if count > 1:
                    print(f"    {macro_name} -> {macro_value} ({count} occurrences)")
                else:
                    print(f"    {macro_name} -> {macro_value}")
