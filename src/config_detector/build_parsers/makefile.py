# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Makefile parser for extracting compiler flags and configuration."""

import re
from pathlib import Path
from typing import Dict, List, Set
from .base import BaseParser


class MakefileParser(BaseParser):
    """Parser for Makefile build systems."""
    
    # Common Makefile names
    MAKEFILE_NAMES = ['Makefile', 'makefile', 'GNUmakefile', 'Makefile.in']
    
    def find_build_files(self) -> List[Path]:
        """Find Makefiles in the project."""
        build_files = []
        
        # Check root directory first
        for name in self.MAKEFILE_NAMES:
            makefile = self.root_path / name
            if makefile.exists():
                build_files.append(makefile)
        
        # Search for Makefiles in subdirectories (limit depth to avoid too many)
        for makefile in self.root_path.rglob('Makefile'):
            if makefile.is_file() and makefile.parent != self.root_path:
                # Limit to common locations
                rel_path = makefile.relative_to(self.root_path)
                if any(part in ['src', 'lib', 'drivers', 'kernel', 'arch'] for part in rel_path.parts[:3]):
                    build_files.append(makefile)
        
        return build_files[:10]  # Limit to first 10 to avoid performance issues
    
    def extract_flags(self, build_file: Path) -> Dict[str, any]:
        """
        Extract compiler flags from a Makefile.
        
        Looks for:
        - CFLAGS, CPPFLAGS, LDFLAGS
        - CC (compiler/toolchain)
        -D defines
        - ARCH, TARGET, BOARD variables
        """
        try:
            content = build_file.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return {'cflags': [], 'defines': [], 'variables': {}, 'toolchain': ''}
        
        cflags: Set[str] = set()
        defines: Set[str] = set()
        variables: Dict[str, str] = {}
        toolchain = ""
        
        # Pattern for variable assignments: VAR = value or VAR := value or VAR += value
        var_pattern = re.compile(r'^(\w+)\s*[+:]?=\s*(.+)$', re.MULTILINE)
        
        # Pattern for -D defines
        define_pattern = re.compile(r'-D(\w+(?:=\w+)?)')
        
        # Extract variable assignments
        for match in var_pattern.finditer(content):
            var_name = match.group(1).upper()
            var_value = match.group(2).strip()
            
            # Remove comments
            var_value = re.sub(r'#.*$', '', var_value).strip()
            
            variables[var_name] = var_value
            
            # Extract flags from common flag variables
            if var_name in ['CFLAGS', 'CPPFLAGS', 'LDFLAGS', 'EXTRA_CFLAGS']:
                # Extract individual flags
                flags = var_value.split()
                for flag in flags:
                    flag = flag.strip()
                    if flag:
                        cflags.add(flag)
                        
                        # Extract -D defines
                        define_match = define_pattern.search(flag)
                        if define_match:
                            defines.add(define_match.group(1))
            
            # Extract toolchain from CC
            if var_name == 'CC' and not toolchain:
                # Extract toolchain prefix (e.g., "arm-none-eabi-gcc" -> "arm-none-eabi")
                toolchain_match = re.match(r'^([\w-]+)-gcc', var_value)
                if toolchain_match:
                    toolchain = toolchain_match.group(1)
                else:
                    toolchain = var_value
        
        # Also look for inline flags in rules
        inline_flag_pattern = re.compile(r'\$\((?:CFLAGS|CPPFLAGS)\)|(-[mD]\w+(?:=\w+)?)')
        for match in inline_flag_pattern.finditer(content):
            flag = match.group(0) if match.group(0) else match.group(1)
            if flag and flag.startswith('-'):
                cflags.add(flag)
                define_match = define_pattern.search(flag)
                if define_match:
                    defines.add(define_match.group(1))
        
        return {
            'cflags': list(cflags),
            'defines': list(defines),
            'variables': variables,
            'toolchain': toolchain
        }
