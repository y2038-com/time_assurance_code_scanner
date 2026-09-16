# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""
Function analyzer using tree-sitter for function extraction.
"""

import os
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from tacs.core.function_schemas import FunctionBody, FunctionAnalysis, ContextNeed
from tacs.core.path_utils import repo_relative_path
from tacs.core.schema import Candidate
from tacs.core.status_logger import StatusLogger


class FunctionAnalyzer:
    """Analyzes source code to extract functions containing Y2038 candidates."""
    
    def __init__(
        self,
        max_function_lines: int = 10000,
        max_function_chars: int = 20000,
        root_path: Optional[str] = None,
    ):
        """
        Initialize the function analyzer.
        
        Args:
            max_function_lines: Maximum function lines before splitting (default: 10000)
            max_function_chars: Maximum function characters before splitting (default: 20000)
            root_path: Scan root that function IDs are named relative to. Without it,
                       IDs fall back to being relative to the current directory.
        """
        self.max_function_lines = max_function_lines
        self.max_function_chars = max_function_chars
        self.root_path = root_path
        self.tree_sitter_available = self._check_tree_sitter()
        if not self.tree_sitter_available:
            # Tree-sitter is optional - this is just informational, not an error
            # The scanner will use a fallback function extraction method
            pass  # Removed warning - it's expected if tree-sitter isn't installed
    
    def _identifier_path(self, file_path: str) -> str:
        """Name a source file the way function IDs and diagnostics should show it."""
        if self.root_path:
            return repo_relative_path(file_path, self.root_path)
        return os.path.relpath(file_path)

    def _check_tree_sitter(self) -> bool:
        """Check if tree-sitter is available."""
        try:
            import tree_sitter
            return True
        except ImportError:
            return False
    
    def extract_functions_with_candidates(self, candidates: List[Candidate]) -> List[FunctionBody]:
        """
        Extract unique function bodies that contain at least one candidate line.
        
        Args:
            candidates: List of Y2038 candidates
            
        Returns:
            List of function bodies containing candidates
        """
        # Group candidates by file
        file_candidates = {}
        for candidate in candidates:
            file_path = candidate.file
            if file_path not in file_candidates:
                file_candidates[file_path] = []
            file_candidates[file_path].append(candidate)
        
        functions = []
        for file_path, file_candidates_list in file_candidates.items():
            try:
                file_functions = self._extract_functions_from_file(file_path, file_candidates_list)
                # Split large functions if needed
                split_functions = []
                for func in file_functions:
                    split_functions.extend(self._split_large_function_if_needed(func))
                functions.extend(split_functions)
            except Exception as e:
                StatusLogger.timestamped_warning(f"Failed to extract functions from {file_path}: {e}")
                # Fallback to simple function extraction
                file_functions = self._fallback_extract_functions(file_path, file_candidates_list)
                # Split large functions if needed
                split_functions = []
                for func in file_functions:
                    split_functions.extend(self._split_large_function_if_needed(func))
                functions.extend(split_functions)
        
        return functions
    
    def _extract_functions_from_file(self, file_path: str, candidates: List[Candidate]) -> List[FunctionBody]:
        """Extract functions from a file using tree-sitter."""
        if not self.tree_sitter_available:
            return self._fallback_extract_functions(file_path, candidates)
        
        try:
            import tree_sitter
            from tree_sitter import Language, Parser
            
            # For now, use fallback since we don't have C/C++ language bindings set up
            return self._fallback_extract_functions(file_path, candidates)
            
        except Exception as e:
            StatusLogger.timestamped_warning(f"Tree-sitter extraction failed for {file_path}: {e}")
            return self._fallback_extract_functions(file_path, candidates)
    
    def _fallback_extract_functions(self, file_path: str, candidates: List[Candidate]) -> List[FunctionBody]:
        """Fallback function extraction using simple parsing."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            StatusLogger.timestamped_warning(f"Failed to read file {file_path}: {e}")
            return []
        
        functions = []
        candidate_lines = {c.line for c in candidates}
        
        # Find function boundaries
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Look for function signature
            if self._is_function_signature(line):
                function_start = i
                function_name = self._extract_function_name(line)
                
                # Find function end
                function_end = self._find_function_end(lines, i)
                
                # Check if this function contains any candidates
                function_candidate_lines = []
                for line_num in range(function_start + 1, function_end + 1):
                    if line_num in candidate_lines:
                        function_candidate_lines.append(line_num)
                
                if function_candidate_lines:
                    # Extract function body
                    function_body_lines = lines[function_start:function_end + 1]
                    function_body = ''.join(function_body_lines)
                    
                    # Create function ID
                    rel_path = self._identifier_path(file_path)
                    function_id = f"{rel_path}@{function_name}:{function_start + 1}-{function_end + 1}"
                    
                    function_body_obj = FunctionBody(
                        function_id=function_id,
                        file_path=file_path,
                        symbol=function_name,
                        start_line=function_start + 1,
                        end_line=function_end + 1,
                        body=function_body,
                        candidate_lines=function_candidate_lines
                    )
                    functions.append(function_body_obj)
                
                i = function_end + 1
            else:
                i += 1
        
        return functions
    
    def _split_large_function_if_needed(self, func: FunctionBody) -> List[FunctionBody]:
        """
        Split a large function into smaller parts if it exceeds size limits.
        
        Args:
            func: Function body to potentially split
            
        Returns:
            List of function bodies (original if not split, or multiple parts if split)
        """
        # Check if function needs splitting
        function_lines = func.end_line - func.start_line + 1
        function_chars = len(func.body)
        
        if function_lines <= self.max_function_lines and function_chars <= self.max_function_chars:
            # Function is within limits, return as-is
            return [func]
        
        # Function exceeds limits, split it
        StatusLogger.timestamped_warning(
            f"Function {func.symbol} ({func.function_id}) exceeds size limits "
            f"({function_lines} lines, {function_chars} chars). Splitting into parts..."
        )
        
        # Read the file to get line-by-line content
        try:
            with open(func.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
        except Exception as e:
            StatusLogger.timestamped_warning(f"Failed to read file {func.file_path} for splitting: {e}")
            # Return original function if we can't read the file
            return [func]
        
        # Extract function lines (convert to 0-based indexing)
        function_start_idx = func.start_line - 1
        function_end_idx = func.end_line - 1
        function_lines_list = all_lines[function_start_idx:function_end_idx + 1]
        
        # Split into chunks
        parts = []
        part_number = 1
        current_start = function_start_idx
        current_lines = []
        current_chars = 0
        
        for i, line in enumerate(function_lines_list):
            line_num = function_start_idx + i
            line_chars = len(line)
            
            # Check if adding this line would exceed limits
            would_exceed_lines = (len(current_lines) + 1) > self.max_function_lines
            would_exceed_chars = (current_chars + line_chars) > self.max_function_chars
            
            if (would_exceed_lines or would_exceed_chars) and current_lines:
                # Create a part from current_lines
                part_body = ''.join(current_lines)
                part_end = line_num - 1
                
                # Find candidate lines in this part
                part_candidate_lines = [
                    cl for cl in func.candidate_lines
                    if current_start + 1 <= cl <= part_end + 1
                ]
                
                # Create part function ID
                rel_path = self._identifier_path(func.file_path)
                part_function_id = f"{rel_path}@{func.symbol}:{current_start + 1}-{part_end + 1}:part{part_number}"
                
                part_func = FunctionBody(
                    function_id=part_function_id,
                    file_path=func.file_path,
                    symbol=func.symbol,
                    start_line=current_start + 1,
                    end_line=part_end + 1,
                    body=part_body,
                    candidate_lines=part_candidate_lines,
                    is_partial=True,
                    original_function_id=func.function_id,
                    part_number=part_number
                )
                parts.append(part_func)
                
                # Start new part
                part_number += 1
                current_start = line_num
                current_lines = [line]
                current_chars = line_chars
            else:
                # Add line to current part
                current_lines.append(line)
                current_chars += line_chars
        
        # Add final part if there are remaining lines
        if current_lines:
            part_body = ''.join(current_lines)
            part_end = function_end_idx
            
            # Find candidate lines in this part
            part_candidate_lines = [
                cl for cl in func.candidate_lines
                if current_start + 1 <= cl <= part_end + 1
            ]
            
            # Create part function ID
            rel_path = self._identifier_path(func.file_path)
            part_function_id = f"{rel_path}@{func.symbol}:{current_start + 1}-{part_end + 1}:part{part_number}"
            
            part_func = FunctionBody(
                function_id=part_function_id,
                file_path=func.file_path,
                symbol=func.symbol,
                start_line=current_start + 1,
                end_line=part_end + 1,
                body=part_body,
                candidate_lines=part_candidate_lines,
                is_partial=True,
                original_function_id=func.function_id,
                part_number=part_number
            )
            parts.append(part_func)
        
        StatusLogger.timestamped_print(f"Split function {func.symbol} into {len(parts)} parts")
        return parts
    
    def _is_function_signature(self, line: str) -> bool:
        """Check if a line is a function signature."""
        # Skip comment lines
        stripped = line.strip()
        if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
            return False
        
        # Look for common function patterns
        function_patterns = [
            'static ',
            'extern ',
            'int ',
            'void ',
            'char ',
            'struct ',
            'enum ',
            'float ',
            'double ',
            'long ',
            'short ',
            'unsigned ',
            'signed '
        ]
        
        # Check if line contains function-like patterns and parentheses
        has_pattern = any(pattern in line for pattern in function_patterns)
        has_parens = '(' in line and ')' in line
        
        # Also check for lines that end with ')' (function signature with brace on next line)
        ends_with_paren = line.strip().endswith(')')
        
        return has_pattern and has_parens and (line.endswith('{') or ends_with_paren)
    
    def _extract_function_name(self, line: str) -> str:
        """Extract function name from signature."""
        import re
        
        # Remove leading/trailing whitespace
        line = line.strip()
        
        # Pattern: optional modifiers (static, extern, inline) + return type + function name + (
        # Matches: "void function_name(", "static int func(", "unsigned long test_narrowing_cast_long(", etc.
        pattern = r'(?:static\s+|extern\s+|inline\s+)?'  # Optional modifiers
        pattern += r'(?:\w+(?:\s+\w+)*\s+)*'  # Return type (may have multiple words like "unsigned long")
        pattern += r'(\w+(?:_\w+)*)\s*\('  # Function name before opening paren (handles underscores)
        
        match = re.search(pattern, line)
        if match:
            return match.group(1)
        
        # Fallback: original logic
        parts = line.split('(')
        if len(parts) > 1:
            before_paren = parts[0].strip()
            words = before_paren.split()
            if words:
                return words[-1]
        
        return "unknown_function"
    
    def _find_function_end(self, lines: List[str], start_idx: int) -> int:
        """Find the end of a function using brace matching."""
        # Start brace counting from the opening brace
        brace_count = 0
        i = start_idx
        
        # If the current line doesn't end with '{', look for the opening brace on the next line
        if not lines[start_idx].strip().endswith('{'):
            i = start_idx + 1
            while i < len(lines) and not lines[i].strip().endswith('{'):
                i += 1
            if i >= len(lines):
                return start_idx  # No opening brace found
        
        # Now count braces starting from the opening brace
        brace_count = 1  # We found the opening brace
        i += 1
        
        while i < len(lines) and brace_count > 0:
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            i += 1
        
        return i - 1
    
    def compute_function_hash(self, function_body: FunctionBody, scenario_hint: str, rules_version: str) -> str:
        """Compute hash for function caching."""
        content = f"{function_body.body}|{scenario_hint}|{rules_version}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def extract_context_items(self, function_body: FunctionBody, needs: List[ContextNeed]) -> Dict[str, Any]:
        """
        Extract requested context items for iterative analysis.
        
        Args:
            function_body: The function being analyzed
            needs: List of context types needed
            
        Returns:
            Dictionary of extracted context items
        """
        context_additions = {}
        
        try:
            with open(function_body.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            StatusLogger.timestamped_warning(f"Failed to read file for context extraction: {e}")
            return context_additions
        
        for need in needs:
            if need == ContextNeed.TYPEDEF:
                context_additions['typedefs'] = self._extract_typedefs(lines)
            elif need == ContextNeed.STRUCT:
                context_additions['structs'] = self._extract_structs(lines)
            elif need == ContextNeed.MACRO:
                context_additions['macros'] = self._extract_macros(lines)
            elif need == ContextNeed.CALLEE:
                context_additions['callees'] = self._extract_callees(lines, function_body)
            elif need == ContextNeed.HEADER:
                context_additions['headers'] = self._extract_headers(lines)
        
        return context_additions
    
    def _extract_typedefs(self, lines: List[str]) -> List[str]:
        """Extract typedef declarations, handling multi-line typedefs."""
        typedefs = []
        
        # Primary method: line-by-line check (most reliable)
        # Look for lines that start with 'typedef' and end with ';'
        # and don't contain function-like syntax (parentheses before semicolon)
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Skip empty lines and comments
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            
            # Check if line starts with 'typedef'
            if stripped.startswith('typedef '):
                # Check if it's a single-line typedef (ends with ';')
                if ';' in stripped:
                    # Extract the part before the semicolon
                    before_semicolon = stripped.split(';')[0]
                    # If there are no parentheses before the semicolon, it's likely a typedef
                    # (function definitions have parentheses)
                    if '(' not in before_semicolon:
                        typedefs.append(stripped)
                else:
                    # Multi-line typedef: look ahead for the closing semicolon
                    typedef_lines = [stripped]
                    for j in range(i + 1, min(i + 10, len(lines))):  # Look ahead up to 10 lines
                        next_line = lines[j].strip()
                        typedef_lines.append(next_line)
                        if ';' in next_line:
                            # Found the end, check if it's a valid typedef
                            full_typedef = ' '.join(typedef_lines)
                            before_semicolon = full_typedef.split(';')[0]
                            # Check for function-like syntax
                            if '(' not in before_semicolon:
                                typedefs.append(full_typedef)
                            break
        
        # Remove duplicates while preserving order
        seen = set()
        unique_typedefs = []
        for typedef in typedefs:
            # Normalize whitespace for comparison
            normalized = ' '.join(typedef.split())
            if normalized not in seen:
                unique_typedefs.append(normalized)
                seen.add(normalized)
        
        return unique_typedefs
    
    def _extract_structs(self, lines: List[str]) -> List[str]:
        """Extract struct declarations, handling multi-line structs."""
        structs = []
        content = ''.join(lines)
        
        # Use regex to find struct definitions
        import re
        # Pattern for struct: struct name { ... };
        struct_pattern = re.compile(
            r'struct\s+(\w+)\s*\{[^}]*\}\s*;',
            re.MULTILINE | re.DOTALL
        )
        
        for match in struct_pattern.finditer(content):
            struct_stmt = match.group(0).strip()
            # Clean up whitespace
            struct_stmt = ' '.join(struct_stmt.split())
            if struct_stmt not in structs:
                structs.append(struct_stmt)
        
        # Also check for forward declarations and single-line structs
        for line in lines:
            stripped = line.strip()
            if 'struct ' in stripped and '{' in stripped and '}' in stripped:
                if stripped not in structs:
                    structs.append(stripped)
        
        return structs
    
    def _extract_macros(self, lines: List[str]) -> List[str]:
        """Extract macro definitions."""
        macros = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#define '):
                macros.append(stripped)
        return macros
    
    def _extract_callees(self, lines: List[str], function_body: FunctionBody) -> List[str]:
        """Extract function calls within the function."""
        callees = []
        function_lines = lines[function_body.start_line - 1:function_body.end_line]
        
        for line in function_lines:
            # Simple heuristic: look for function calls
            if '(' in line and ')' in line:
                # Extract potential function names
                parts = line.split('(')
                for part in parts[:-1]:  # All parts except the last
                    words = part.split()
                    if words:
                        callees.append(words[-1])
        
        return list(set(callees))  # Remove duplicates
    
    def _extract_headers(self, lines: List[str]) -> List[str]:
        """Extract header includes."""
        headers = []
        for line in lines:
            if line.strip().startswith('#include '):
                headers.append(line.strip())
        return headers
