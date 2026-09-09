"""CMake parser for extracting compiler flags and configuration."""

import re
from pathlib import Path
from typing import Dict, List, Set
from .base import BaseParser


class CMakeParser(BaseParser):
    """Parser for CMake build systems."""
    
    def find_build_files(self) -> List[Path]:
        """Find CMakeLists.txt files in the project."""
        build_files = []
        seen_files = set()
        
        # Check root directory first
        cmake_file = self.root_path / 'CMakeLists.txt'
        if cmake_file.exists():
            build_files.append(cmake_file)
            seen_files.add(cmake_file)
        
        # Search for CMakeLists.txt in subdirectories (limit depth)
        for cmake_file in self.root_path.rglob('CMakeLists.txt'):
            if cmake_file.is_file() and cmake_file not in seen_files:
                # Limit to reasonable depth and common locations
                rel_path = cmake_file.relative_to(self.root_path)
                if len(rel_path.parts) <= 4:  # Max 4 levels deep
                    build_files.append(cmake_file)
                    seen_files.add(cmake_file)
        
        return build_files[:10]  # Limit to first 10
    
    def extract_flags(self, build_file: Path) -> Dict[str, any]:
        """
        Extract compiler flags from a CMakeLists.txt file.
        
        Looks for:
        - add_definitions(), add_compile_definitions()
        - set(CMAKE_C_FLAGS ...)
        - set(CMAKE_SYSTEM_PROCESSOR ...)
        - find_package() calls
        """
        try:
            content = build_file.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return {'cflags': [], 'defines': [], 'variables': {}, 'toolchain': ''}
        
        cflags: Set[str] = set()
        defines: Set[str] = set()
        variables: Dict[str, str] = {}
        toolchain = ""
        
        # Pattern for set() commands: set(VAR value) or set(VAR "value")
        set_pattern = re.compile(r'set\s*\(\s*(\w+)\s+(.+?)\s*\)', re.IGNORECASE | re.DOTALL)
        
        # Pattern for add_definitions: add_definitions(-DFOO -DBAR=value)
        def_pattern = re.compile(r'add_(?:compile_)?definitions\s*\((.+?)\)', re.IGNORECASE | re.DOTALL)
        
        # Pattern for CMAKE_SYSTEM_PROCESSOR
        processor_pattern = re.compile(r'CMAKE_SYSTEM_PROCESSOR', re.IGNORECASE)
        
        # Extract set() variables
        for match in set_pattern.finditer(content):
            var_name = match.group(1).upper()
            var_value = match.group(2).strip()
            
            # Remove quotes
            var_value = re.sub(r'^["\']|["\']$', '', var_value)
            # Remove comments
            var_value = re.sub(r'#.*$', '', var_value).strip()
            
            variables[var_name] = var_value
            
            # Extract flags from CMAKE_C_FLAGS, etc.
            if 'CMAKE_C_FLAGS' in var_name or 'CMAKE_CXX_FLAGS' in var_name:
                flags = var_value.split()
                for flag in flags:
                    flag = flag.strip()
                    if flag:
                        cflags.add(flag)
            
            # Extract CMAKE_SYSTEM_PROCESSOR
            if var_name == 'CMAKE_SYSTEM_PROCESSOR':
                variables['CMAKE_SYSTEM_PROCESSOR'] = var_value
            
            # Extract toolchain from CMAKE_C_COMPILER
            if var_name == 'CMAKE_C_COMPILER' and not toolchain:
                toolchain_match = re.match(r'^([\w-]+)-gcc', var_value)
                if toolchain_match:
                    toolchain = toolchain_match.group(1)
        
        # Extract add_definitions
        for match in def_pattern.finditer(content):
            defs_str = match.group(1)
            # Extract -D defines
            define_matches = re.finditer(r'-D(\w+(?:=\w+)?)', defs_str)
            for def_match in define_matches:
                defines.add(def_match.group(1))
        
        # Look for find_package(Zephyr) or similar
        if re.search(r'find_package\s*\(\s*Zephyr', content, re.IGNORECASE):
            variables['ZEPHYR'] = 'true'
        
        return {
            'cflags': list(cflags),
            'defines': list(defines),
            'variables': variables,
            'toolchain': toolchain
        }
