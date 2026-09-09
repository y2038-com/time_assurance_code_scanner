from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass


@dataclass
class ArithmeticMatch:
    """Represents an arithmetic operation match on time_t."""
    operation: str  # '+', '-', '*', '/', etc.
    file_path: str
    line_number: int
    full_line: str
    time_t_var: str  # The time_t variable name
    operand: str  # The operand (constant, variable, or expression)
    confidence: float
    risk_level: str  # 'high', 'medium', 'low'


class ArithmeticScanner:
    """Scanner for arithmetic operations on time_t variables."""
    
    def __init__(self, time_t_aliases: Optional[Dict[str, List[str]]] = None):
        """
        Initialize the arithmetic scanner.
        
        Args:
            time_t_aliases: Dictionary of time_t alias names to their definitions
        """
        # Build set of all time_t type names (base + aliases)
        self.time_t_names = {'time_t', 'clock_t', 'timer_t', 'suseconds_t', 'useconds_t'}
        
        if time_t_aliases:
            for alias_name in time_t_aliases.keys():
                self.time_t_names.add(alias_name)
        
        # Pattern to match time_t variable declarations
        # Matches: time_t var, my_time_t var, etc.
        time_t_pattern = '|'.join(re.escape(name) for name in self.time_t_names)
        self.time_t_decl_pattern = re.compile(
            rf'\b({time_t_pattern})\s+(\w+)\s*[=;,]',
            re.IGNORECASE
        )
        
        # Pattern to match arithmetic operations on variables
        # Matches: var + constant, var - constant, var * constant, var / constant
        # Also matches: var +=, var -=, var *=, var /=
        self.arithmetic_pattern = re.compile(
            r'\b(\w+)\s*([+\-*/])\s*([=]?)\s*([^;,\[\](){}]+?)(?=[;,\[\](){}]|$)',
            re.IGNORECASE
        )
        
        # Pattern to match large constants that could cause overflow
        # 2^31 = 2147483648, 2^30 = 1073741824, etc.
        self.large_constant_pattern = re.compile(
            r'\b(214748364[0-8]|107374182[4-9]|53687091[2-9]|26843545[6-9]|13421772[8-9]|6710886[4-9]|3355443[2-9]|1677721[6-9]|838860[8-9]|419430[4-9]|209715[2-9]|104857[6-9]|52428[8-9]|26214[4-9]|13107[2-9]|6553[6-9]|3276[8-9]|1638[4-9]|819[2-9]|409[6-9]|204[8-9]|102[4-9]|51[2-9]|25[6-9]|12[8-9]|6[4-9]|3[2-9]|1[6-9])\b'
        )
        
        # Pattern to match negative constants
        self.negative_constant_pattern = re.compile(r'-\s*\d+')
        
        # Track declared time_t variables in current scope
        self.declared_vars: Set[str] = set()
    
    def scan_line_for_arithmetic(self, line: str, file_path: str, line_number: int, 
                                 declared_time_t_vars: Set[str]) -> List[ArithmeticMatch]:
        """
        Scan a single line for arithmetic operations on time_t variables.
        
        Args:
            line: Line content to scan
            file_path: Path to the file
            line_number: Line number in the file
            declared_time_t_vars: Set of time_t variable names declared in current scope
            
        Returns:
            List of ArithmeticMatch objects for matches
        """
        matches = []
        
        # Strip comments and strings for cleaner matching
        cleaned_line = self._strip_comments_and_strings(line)
        
        # First, check for time_t variable declarations
        decl_matches = self.time_t_decl_pattern.finditer(cleaned_line)
        for decl_match in decl_matches:
            var_name = decl_match.group(2)
            declared_time_t_vars.add(var_name)
        
        # Now check for arithmetic operations
        arithmetic_matches = self.arithmetic_pattern.finditer(cleaned_line)
        
        for arith_match in arithmetic_matches:
            var_name = arith_match.group(1)
            operator = arith_match.group(2)
            is_compound = arith_match.group(3) == '='
            operand = arith_match.group(4).strip()
            
            # Check if this is an arithmetic operation on a time_t variable
            if var_name in declared_time_t_vars or self._is_time_t_var(var_name, cleaned_line):
                # Determine risk level based on operand
                risk_level, confidence = self._assess_risk(operator, operand, is_compound)
                
                if risk_level in ('high', 'medium'):
                    match = ArithmeticMatch(
                        operation=operator + ('=' if is_compound else ''),
                        file_path=file_path,
                        line_number=line_number,
                        full_line=line.strip(),
                        time_t_var=var_name,
                        operand=operand,
                        confidence=confidence,
                        risk_level=risk_level
                    )
                    matches.append(match)
        
        return matches
    
    def _strip_comments_and_strings(self, line: str) -> str:
        """Strip comments and string literals from a line."""
        # Remove line comments
        line = re.sub(r'//.*$', '', line)
        
        # Remove string literals (simple approach)
        line = re.sub(r'"[^"]*"', '""', line)
        line = re.sub(r"'[^']*'", "''", line)
        
        return line
    
    def _is_time_t_var(self, var_name: str, line: str) -> bool:
        """Check if a variable is likely a time_t type based on context."""
        # Look for time_t declaration patterns before the variable
        # This is a heuristic - may not catch all cases
        time_t_pattern = '|'.join(re.escape(name) for name in self.time_t_names)
        pattern = rf'\b({time_t_pattern})\s+{re.escape(var_name)}\b'
        return re.search(pattern, line, re.IGNORECASE) is not None
    
    def _assess_risk(self, operator: str, operand: str, is_compound: bool) -> Tuple[str, float]:
        """
        Assess the risk level of an arithmetic operation.
        
        Returns:
            Tuple of (risk_level, confidence)
        """
        operand_clean = operand.strip()
        
        # Check for large constants (potential overflow)
        if self.large_constant_pattern.search(operand_clean):
            if operator in ('+', '*'):
                return ('high', 0.9)
            else:
                return ('medium', 0.7)
        
        # Check for negative constants (potential underflow for signed)
        if self.negative_constant_pattern.search(operand_clean):
            if operator == '-' or (operator == '+' and '-' in operand_clean):
                return ('medium', 0.7)
        
        # Check for very large numeric constants
        try:
            # Try to extract numeric value
            numeric_match = re.search(r'-?\d+', operand_clean)
            if numeric_match:
                value = int(numeric_match.group())
                abs_value = abs(value)
                
                # Constants >= 2^30 are high risk for 32-bit signed
                if abs_value >= 1073741824:  # 2^30
                    if operator in ('+', '*'):
                        return ('high', 0.9)
                    else:
                        return ('medium', 0.7)
                
                # Constants >= 2^20 are medium risk
                if abs_value >= 1048576:  # 2^20
                    return ('medium', 0.7)
        except (ValueError, AttributeError):
            pass
        
        # Default: low risk for small constants, but still worth flagging
        # Small constants (like +60, -3600) are usually safe but could accumulate
        if operator in ('+', '-') and re.match(r'^-?\d+$', operand_clean):
            return ('low', 0.5)
        
        # Unknown operand (variable, expression) - medium risk
        return ('medium', 0.6)
    
    def print_discovered_arithmetic(self, matches: List[ArithmeticMatch]):
        """Print summary of discovered arithmetic operations."""
        if not matches:
            return
        
        high_risk = [m for m in matches if m.risk_level == 'high']
        medium_risk = [m for m in matches if m.risk_level == 'medium']
        low_risk = [m for m in matches if m.risk_level == 'low']
        
        if high_risk or medium_risk:
            print(f"Discovered {len(matches)} arithmetic operations on time_t:")
            if high_risk:
                print(f"  High risk: {len(high_risk)} operations")
            if medium_risk:
                print(f"  Medium risk: {len(medium_risk)} operations")
            if low_risk:
                print(f"  Low risk: {len(low_risk)} operations")
