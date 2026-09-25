# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from tacs.core.schema import Candidate
from tacs.core.status_logger import StatusLogger
from tacs.core.define_scanner import DefineScanner, DefineMatch
from tacs.core.arithmetic_scanner import ArithmeticScanner, ArithmeticMatch
from tacs.core.path_utils import canonical_source_path
from tacs.core.candidate_utils import prepare_candidates
from tacs.core.candidate_evidence import normalize_discovery_method


def _ir_symbols_methods_and_rule_ids(
    item: Dict[str, Any],
) -> List[tuple[str, Optional[str], Optional[str]]]:
    """Pair each IR symbol with discovery_method and rule_id.

    Propagates producer-emitted values only. Does not classify from symbol,
    risk, or description text. Missing methods become ``unknown`` via
    :func:`normalize_discovery_method`. Missing rule_ids stay None.
    """
    if "symbols" in item:
        symbols = item.get("symbols") or []
        if isinstance(symbols, str):
            symbols = [symbols]
        methods = item.get("discovery_methods")
        if not isinstance(methods, list):
            methods = []
        rule_ids = item.get("rule_ids")
        if not isinstance(rule_ids, list):
            rule_ids = []
        paired: List[tuple[str, Optional[str], Optional[str]]] = []
        for i, symbol in enumerate(symbols):
            method = methods[i] if i < len(methods) else None
            rule_id = rule_ids[i] if i < len(rule_ids) else None
            paired.append((str(symbol or ""), method, rule_id))
        return paired

    symbol = str(item.get("symbol") or "")
    return [(symbol, item.get("discovery_method"), item.get("rule_id"))]


# Backward-compatible alias used by older tests.
def _ir_symbols_and_methods(item: Dict[str, Any]) -> List[tuple[str, Optional[str]]]:
    return [(sym, method) for sym, method, _rid in _ir_symbols_methods_and_rule_ids(item)]


class IRAdapter:
    """Adapter for the fast token inverted index scanner."""
    
    def __init__(self, scanner_path: str, max_file_size: Optional[int] = None):
        """
        Initialize the IR adapter.
        
        Args:
            scanner_path: Path to the y2038scan_fast_json_group.py script
            max_file_size: Optional per-file byte limit; larger files are not read,
                and the limit is handed to the scanner subprocess as well
        """
        self.max_file_size = max_file_size
        self.scanner_path = Path(scanner_path)
        if not self.scanner_path.exists():
            raise FileNotFoundError(f"Scanner script not found: {scanner_path}")
        
        # Initialize define scanner for integrated #define detection
        self.define_scanner = DefineScanner()
        # Arithmetic scanner will be initialized with time_t aliases when needed
    
    def discover_candidates(
        self,
        root_path: str,
        rules_path: str,
        min_risk: str = "medium",
        include_patterns: List[str] = None,
        exclude_patterns: List[str] = None,
        time_t_aliases: Dict[str, List[str]] = None,
        time_functions: List[str] = None
    ) -> List[Candidate]:
        """
        Discover candidates using the fast scanner.
        
        Args:
            root_path: Root directory to scan
            rules_path: Path to rules JSON file
            min_risk: Minimum risk level (low, medium, high)
            include_patterns: List of glob patterns to include
            exclude_patterns: List of glob patterns to exclude
            time_t_aliases: Dict of discovered time_t typedef aliases for cast detection
            time_functions: List of time-related function names for cast detection
            
        Returns:
            List of Candidate objects
        """
        # Create temporary file for JSON output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
            tmp_path = tmp_file.name
        
        # Create temporary files for time_t aliases and functions if provided
        time_t_aliases_path = None
        time_functions_path = None
        
        try:
            # Write time_t aliases to temp file if provided
            if time_t_aliases:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as aliases_file:
                    # Write as list of alias names
                    aliases_list = list(time_t_aliases.keys())
                    json.dump(aliases_list, aliases_file)
                    time_t_aliases_path = aliases_file.name
            
            # Write time functions to temp file if provided
            if time_functions:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as funcs_file:
                    json.dump(time_functions, funcs_file)
                    time_functions_path = funcs_file.name
            
            # Build command
            cmd = [
                sys.executable,
                str(self.scanner_path),
                root_path,
                rules_path,
                '--min-risk', min_risk,
                '--verbosity', '0',
                '--group-by-line',
                '--json-out', tmp_path
            ]
            
            # Add include/exclude patterns if provided
            if include_patterns:
                for pattern in include_patterns:
                    cmd.extend(['--include', pattern])
            if exclude_patterns:
                for pattern in exclude_patterns:
                    cmd.extend(['--exclude', pattern])
            if self.max_file_size is not None:
                cmd.extend(['--max-file-size', str(self.max_file_size)])
            
            # Add time_t cast detection arguments if available
            if time_t_aliases_path:
                cmd.extend(['--time-t-aliases', time_t_aliases_path])
            if time_functions_path:
                cmd.extend(['--time-functions', time_functions_path])
            
            # Run the scanner with real-time stderr streaming for progress updates
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Read stderr in real-time to show progress updates as they happen
            stderr_lines = []
            while True:
                line = process.stderr.readline()
                if not line:
                    break
                stderr_lines.append(line)
                # Print progress messages immediately with timestamp
                if line.strip().startswith('Progress:'):
                    StatusLogger.timestamped_debug(line.strip())
            
            # Wait for process to complete
            stdout, remaining_stderr = process.communicate()
            stderr_lines.extend(remaining_stderr.split('\n') if remaining_stderr else [])
            result_stderr = '\n'.join(stderr_lines)
            
            result = type('obj', (object,), {
                'returncode': process.returncode,
                'stdout': stdout,
                'stderr': result_stderr
            })()
            
            if result.returncode != 0:
                # Print any error messages from stderr
                if result.stderr:
                    for line in result.stderr.split('\n'):
                        if line.strip() and not line.strip().startswith('Progress:'):
                            StatusLogger.timestamped_error(line.strip())
                raise RuntimeError(f"Scanner failed: {result.stderr}")
            
            # Read results
            with open(tmp_path, 'r', encoding='utf-8') as f:
                raw_results = json.load(f)
            
            # Convert to Candidate objects
            candidates = []
            for item in raw_results:
                file_path = canonical_source_path(item['file'])
                for symbol, method, rule_id in _ir_symbols_methods_and_rule_ids(item):
                    candidate = Candidate(
                        file=file_path,
                        line=item['line'],
                        symbol=symbol,
                        one_line_snippet=item['lineText'],
                        risk=item['risk'],
                        description=item.get('description', ''),
                        discovery_method=normalize_discovery_method(method),
                        rule_id=rule_id if isinstance(rule_id, str) and rule_id.strip() else None,
                    )
                    candidates.append(candidate)
            
            # Also scan for #define statements if #define rule is present
            define_candidates = self._scan_for_defines(root_path, rules_path, include_patterns, exclude_patterns)
            candidates.extend(define_candidates)
            
            # Scan for arithmetic operations on time_t
            arithmetic_candidates = self._scan_for_arithmetic(root_path, include_patterns, exclude_patterns, time_t_aliases)
            candidates.extend(arithmetic_candidates)

            # Symlink aliases and overlapping detectors can emit the same hit more
            # than once; collapse exact duplicates and stabilize order here so
            # functionization and candidates.jsonl see one logical population.
            return prepare_candidates(candidates)
            
        finally:
            # Clean up temporary files
            try:
                Path(tmp_path).unlink()
            except Exception:
                pass
            try:
                if time_t_aliases_path:
                    Path(time_t_aliases_path).unlink()
            except Exception:
                pass
            try:
                if time_functions_path:
                    Path(time_functions_path).unlink()
            except Exception:
                pass
    
    def _scan_for_defines(self, root_path: str, rules_path: str, include_patterns: List[str] = None, exclude_patterns: List[str] = None) -> List[Candidate]:
        """Scan for #define statements using the integrated define scanner."""
        # Check if #define rule exists in rules file
        try:
            from tacs.core.rule_catalog import load_rules_document

            rules, _retired = load_rules_document(rules_path)
            has_define_rule = any(rule.get('symbol') == '#define' for rule in rules)
            if not has_define_rule:
                return []
        except Exception:
            return []
        
        # Get files to scan
        StatusLogger.timestamped_debug("Scanning for #define statements...")
        files = self._get_files(
            root_path,
            include_patterns or ['**/*.c', '**/*.h'],
            exclude_patterns or [],
            self.max_file_size,
        )
        define_matches = []
        
        # Scan each file for #define statements
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                for line_num, line in enumerate(lines, 1):
                    matches = self.define_scanner.scan_line_for_defines(line, str(file_path), line_num)
                    define_matches.extend(matches)
            except Exception as e:
                StatusLogger.timestamped_warning(f"Could not read {file_path}: {e}")
                continue
        
        # Print discovered defines
        self.define_scanner.print_discovered_defines(define_matches)
        
        # Convert DefineMatch objects to Candidate objects
        # Subchecks are detector metadata, not independent catalog rules; rule_id stays null.
        candidates = []
        for match in define_matches:
            candidate = Candidate(
                file=canonical_source_path(match.file_path),
                line=match.line_number,
                symbol=match.macro_name,
                one_line_snippet=match.full_line,
                risk="high" if match.subcheck_type in ['time_type_alias', 'time_struct_alias'] else "medium",
                description=f"{match.subcheck_type}: {match.macro_name} -> {match.macro_value}",
                discovery_method="define_scanner",
                rule_id=None,
            )
            candidates.append(candidate)
        
        return candidates
    
    def _get_files(
        self,
        root_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str],
        max_file_size: Optional[int] = None,
    ) -> List[Path]:
        """Get unique in-repo source files matching include/exclude patterns."""
        from tacs.core.source_files import enumerate_source_files

        enumeration = enumerate_source_files(
            root_path,
            include_patterns,
            exclude_patterns=exclude_patterns,
            max_file_size=max_file_size,
        )
        for display in enumeration.skipped_external:
            StatusLogger.timestamped_debug(
                f"Ignoring source symlink outside repository root: {display}"
            )
        return enumeration.files    
    def _scan_for_arithmetic(self, root_path: str, include_patterns: List[str] = None, 
                             exclude_patterns: List[str] = None, 
                             time_t_aliases: Dict[str, List[str]] = None) -> List[Candidate]:
        """Scan for arithmetic operations on time_t variables."""
        # Initialize arithmetic scanner with time_t aliases
        arithmetic_scanner = ArithmeticScanner(time_t_aliases or {})
        
        # Get files to scan
        StatusLogger.timestamped_debug("Scanning for arithmetic operations on time_t...")
        files = self._get_files(
            root_path,
            include_patterns or ['**/*.c', '**/*.h'],
            exclude_patterns or [],
            self.max_file_size,
        )
        arithmetic_matches = []
        
        # Track declared time_t variables per file
        for file_path in files:
            declared_vars: Set[str] = set()
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                # First pass: collect all time_t variable declarations
                for line_num, line in enumerate(lines, 1):
                    # Check for time_t declarations
                    time_t_pattern = '|'.join(re.escape(name) for name in arithmetic_scanner.time_t_names)
                    decl_pattern = re.compile(
                        rf'\b({time_t_pattern})\s+(\w+)\s*[=;,\[\]()]',
                        re.IGNORECASE
                    )
                    for match in decl_pattern.finditer(line):
                        var_name = match.group(2)
                        declared_vars.add(var_name)
                
                # Second pass: scan for arithmetic operations
                for line_num, line in enumerate(lines, 1):
                    matches = arithmetic_scanner.scan_line_for_arithmetic(
                        line, str(file_path), line_num, declared_vars
                    )
                    arithmetic_matches.extend(matches)
            except Exception as e:
                StatusLogger.timestamped_warning(f"Could not read {file_path}: {e}")
                continue
        
        # Print discovered arithmetic operations
        arithmetic_scanner.print_discovered_arithmetic(arithmetic_matches)
        
        # Convert ArithmeticMatch objects to Candidate objects
        candidates = []
        for match in arithmetic_matches:
            # Only include high and medium risk operations
            if match.risk_level in ('high', 'medium'):
                candidate = Candidate(
                    file=canonical_source_path(match.file_path),
                    line=match.line_number,
                    symbol=f"arithmetic_{match.operation}",
                    one_line_snippet=match.full_line,
                    risk=match.risk_level,
                    description=f"Arithmetic operation on time_t: {match.time_t_var} {match.operation} {match.operand}",
                    discovery_method="arithmetic_scanner",
                    rule_id=None,
                )
                candidates.append(candidate)
        
        return candidates