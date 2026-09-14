# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Base parser interface for build system files."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Set


class BaseParser(ABC):
    """Base class for build system parsers."""
    
    def __init__(self, root_path: Path):
        """
        Initialize parser.
        
        Args:
            root_path: Root directory of the project
        """
        self.root_path = root_path
    
    @abstractmethod
    def find_build_files(self) -> List[Path]:
        """
        Find relevant build system files.
        
        Returns:
            List of paths to build files
        """
        pass
    
    @abstractmethod
    def extract_flags(self, build_file: Path) -> Dict[str, any]:
        """
        Extract compiler flags and configuration from a build file.
        
        Args:
            build_file: Path to the build file
            
        Returns:
            Dictionary with extracted information:
            - 'cflags': List of C compiler flags
            - 'defines': List of -D defines
            - 'variables': Dictionary of variable assignments
            - 'toolchain': Toolchain information if found
        """
        pass
    
    def extract_all(self) -> Dict[str, any]:
        """
        Extract all information from all build files.
        
        Returns:
            Combined dictionary with all extracted information
        """
        build_files = self.find_build_files()
        
        all_cflags: Set[str] = set()
        all_defines: Set[str] = set()
        all_variables: Dict[str, str] = {}
        toolchain: str = ""
        
        for build_file in build_files:
            try:
                extracted = self.extract_flags(build_file)
                all_cflags.update(extracted.get('cflags', []))
                all_defines.update(extracted.get('defines', []))
                all_variables.update(extracted.get('variables', {}))
                if extracted.get('toolchain') and not toolchain:
                    toolchain = extracted.get('toolchain')
            except Exception as e:
                # Continue if one file fails
                continue
        
        return {
            'cflags': list(all_cflags),
            'defines': list(all_defines),
            'variables': all_variables,
            'toolchain': toolchain,
            'build_files_found': len(build_files)
        }
