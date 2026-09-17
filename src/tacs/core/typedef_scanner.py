# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


class TypedefScanner:
    """Scanner for typedef statements that create time_t aliases."""
    
    def __init__(
        self,
        max_hops: int = 5,
        max_aliases: int = 64,
        max_file_size: Optional[int] = None,
    ):
        """
        Initialize the typedef scanner.
        
        Args:
            max_hops: Maximum number of hops to follow typedef chains
            max_aliases: Maximum number of aliases to discover
            max_file_size: Optional per-file byte limit; larger files are not read
        """
        self.max_hops = max_hops
        self.max_aliases = max_aliases
        self.max_file_size = max_file_size
        
        # Patterns for typedef parsing
        self.typedef_pattern = re.compile(
            r'typedef\s+.*?\s+(\w+)\s*;',
            re.MULTILINE | re.DOTALL
        )
        
        # Pattern for typedef with parentheses (function pointers, etc.)
        self.typedef_func_pattern = re.compile(
            r'typedef\s+.*?\(\s*\*\s*(\w+)\s*\)\s*\([^)]*\)\s*;',
            re.MULTILINE | re.DOTALL
        )
    
    def scan_directory(self, root_path: str, include_patterns: List[str], exclude_patterns: List[str]) -> Dict[str, List[str]]:
        """
        Scan directory for typedef statements.
        
        Args:
            root_path: Root directory to scan
            include_patterns: List of glob patterns to include
            exclude_patterns: List of glob patterns to exclude
            
        Returns:
            Dictionary mapping typedef names to their definitions
        """
        typedef_map = defaultdict(list)
        
        # Get all files matching include patterns
        files = self._get_files(root_path, include_patterns, exclude_patterns)
        
        for file_path in files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Find typedefs in this file
                file_typedefs = self._find_typedefs(content, str(file_path))
                typedef_map.update(file_typedefs)
                
            except Exception as e:
                from tacs.core.status_logger import StatusLogger

                StatusLogger.timestamped_warning(f"Could not read {file_path}: {e}")

                continue
        
        return dict(typedef_map)
    
    def _get_files(self, root_path: str, include_patterns: List[str], exclude_patterns: List[str]) -> List[Path]:
        """Get unique in-repo source files matching include/exclude patterns."""
        from tacs.core.source_files import enumerate_source_files
        from tacs.core.status_logger import StatusLogger

        enumeration = enumerate_source_files(
            root_path,
            include_patterns,
            exclude_patterns=exclude_patterns,
            max_file_size=self.max_file_size,
        )
        for display in enumeration.skipped_external:
            StatusLogger.timestamped_debug(
                f"Ignoring source symlink outside repository root: {display}"
            )
        return enumeration.files
    
    def _find_typedefs(self, content: str, file_path: str) -> Dict[str, List[str]]:
        """Find typedef statements in file content."""
        typedefs = defaultdict(list)
        
        # Remove comments to avoid false matches
        cleaned_content = self._remove_comments(content)
        
        # First, try to find typedefs across the entire content (for multi-line typedefs)
        # This handles cases like:
        #   typedef struct {
        #       int x;
        #   } my_type_t;
        all_matches = list(self.typedef_pattern.finditer(cleaned_content))
        all_func_matches = list(self.typedef_func_pattern.finditer(cleaned_content))
        
        # Get line numbers for matches
        lines = cleaned_content.split('\n')
        line_starts = [0]
        for line in lines:
            line_starts.append(line_starts[-1] + len(line) + 1)  # +1 for newline
        
        def get_line_num(pos: int) -> int:
            """Get line number (1-indexed) for a character position."""
            for i, start in enumerate(line_starts):
                if start > pos:
                    return i
            return len(lines)
        
        # Process all matches
        for match in all_matches:
            typedef_name = match.group(1)
            full_match = match.group(0)
            line_num = get_line_num(match.start())
            typedefs[typedef_name].append(f"{file_path}:{line_num}: {full_match.strip()}")
        
        for match in all_func_matches:
            typedef_name = match.group(1)
            full_match = match.group(0)
            line_num = get_line_num(match.start())
            typedefs[typedef_name].append(f"{file_path}:{line_num}: {full_match.strip()}")
        
        return dict(typedefs)
    
    def _remove_comments(self, content: str) -> str:
        """Remove C/C++ comments from content."""
        # Remove single-line comments
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        return content
    
    def find_time_t_aliases(self, typedef_map: Dict[str, List[str]], seed_types: Set[str] = None) -> Dict[str, List[str]]:
        """
        Find typedefs that are aliases for time_t or other time-related types.
        
        Args:
            typedef_map: Dictionary of all typedefs found
            seed_types: Initial set of time-related types to search from
            
        Returns:
            Dictionary of time-related typedef aliases
        """
        if seed_types is None:
            seed_types = {'time_t', 'clock_t', 'timer_t', 'suseconds_t', 'useconds_t'}
        
        time_aliases = {}
        visited = set()
        current_level = seed_types.copy()
        
        for hop in range(self.max_hops):
            if not current_level:
                break
            
            next_level = set()
            
            for typedef_name in current_level:
                if typedef_name in visited:
                    continue
                
                visited.add(typedef_name)
                
                # Look for typedefs that reference this type
                for alias_name, definitions in typedef_map.items():
                    if alias_name in visited:
                        continue
                    
                    for definition in definitions:
                        # Check if this typedef references our current type
                        if self._references_type(definition, typedef_name):
                            time_aliases[alias_name] = definitions
                            next_level.add(alias_name)
            
            current_level = next_level
            
            # Check if we've exceeded the alias limit
            if len(time_aliases) >= self.max_aliases:
                from tacs.core.status_logger import StatusLogger

                StatusLogger.timestamped_warning(
                    f"Reached maximum alias limit ({self.max_aliases})"
                )
                break
        
        return time_aliases
    
    def _references_type(self, definition: str, type_name: str) -> bool:
        """Check if a typedef definition references a specific type."""
        # More precise check: look for the type name as a whole word
        # This avoids false positives like "time_timestamp" matching "time_t"
        # Use word boundaries to match the type name exactly
        import re
        # Pattern matches the type name as a whole word (not part of another identifier)
        # Extract just the typedef part (after the colon and line number)
        # Format is: "file:line: typedef ..."
        if ':' in definition:
            # Get the typedef part (everything after the second colon)
            parts = definition.split(':', 2)
            if len(parts) >= 3:
                typedef_part = parts[2].strip()
            else:
                typedef_part = definition
        else:
            typedef_part = definition
        
        # Pattern matches the type name as a whole word (not part of another identifier)
        pattern = r'\b' + re.escape(type_name) + r'\b'
        return bool(re.search(pattern, typedef_part))
    
    def print_discovered_aliases(self, aliases: Dict[str, List[str]]):
        """Log discovered time_t aliases (DEBUG)."""
        from tacs.core.status_logger import StatusLogger

        if not aliases:
            StatusLogger.timestamped_debug("No time_t aliases discovered")
            return
        
        StatusLogger.timestamped_debug(f"Discovered {len(aliases)} time_t aliases:")
        for alias_name, definitions in aliases.items():
            StatusLogger.timestamped_debug(f"  {alias_name}:")
            for definition in definitions:
                StatusLogger.timestamped_debug(f"    {definition}")
