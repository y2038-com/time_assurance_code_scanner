from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional


class IOUtils:
    """Utilities for safe file I/O operations."""
    
    @staticmethod
    def read_json_file(file_path: str) -> Dict[str, Any]:
        """
        Safely read a JSON file.
        
        Args:
            file_path: Path to the JSON file
            
        Returns:
            Parsed JSON data
            
        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If file contains invalid JSON
            IOError: If file cannot be read
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not path.is_file():
            raise IOError(f"Path is not a file: {file_path}")
        
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Invalid JSON in {file_path}: {e.msg}", e.doc, e.pos)
        except Exception as e:
            raise IOError(f"Failed to read {file_path}: {e}")
    
    @staticmethod
    def write_json_file(file_path: str, data: Dict[str, Any], create_dirs: bool = True) -> None:
        """
        Safely write data to a JSON file.
        
        Args:
            file_path: Path to write the JSON file
            data: Data to write
            create_dirs: Whether to create parent directories
            
        Raises:
            IOError: If file cannot be written
        """
        path = Path(file_path)
        
        if create_dirs:
            path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise IOError(f"Failed to write {file_path}: {e}")
    
    @staticmethod
    def ensure_directory_exists(dir_path: str) -> None:
        """
        Ensure a directory exists, creating it if necessary.
        
        Args:
            dir_path: Path to the directory
        """
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    @staticmethod
    def get_safe_path(base_path: str, *path_parts: str) -> str:
        """
        Safely join path components.
        
        Args:
            base_path: Base path
            *path_parts: Additional path components
            
        Returns:
            Joined path string
        """
        return str(Path(base_path).joinpath(*path_parts))
    
    @staticmethod
    def is_safe_path(path: str, base_dir: Optional[str] = None) -> bool:
        """
        Check if a path is safe (doesn't escape base directory).
        
        Args:
            path: Path to check
            base_dir: Base directory to check against (optional)
            
        Returns:
            True if path is safe
        """
        try:
            resolved_path = Path(path).resolve()
            if base_dir:
                base_resolved = Path(base_dir).resolve()
                return base_resolved in resolved_path.parents or resolved_path == base_resolved
            return True
        except Exception:
            return False
    
    @staticmethod
    def append_jsonl_line(file_path: str, data: Dict[str, Any], create_dirs: bool = True) -> None:
        """
        Append a JSON object as a line to a JSONL file.
        
        Args:
            file_path: Path to the JSONL file
            data: Data to append
            create_dirs: Whether to create parent directories
            
        Raises:
            IOError: If file cannot be written
        """
        path = Path(file_path)
        
        if create_dirs:
            path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(path, 'a', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False)
                f.write('\n')
        except Exception as e:
            raise IOError(f"Failed to append to {file_path}: {e}")
