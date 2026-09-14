# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import glob
from pathlib import Path
from typing import Dict, List, Tuple
from tacs.core.schema import Metrics


def calculate_metrics(root_path: str, include_patterns: List[str], exclude_patterns: List[str]) -> Metrics:
    """
    Calculate code metrics for the given root path with include/exclude patterns.
    
    Args:
        root_path: Root directory to scan
        include_patterns: List of glob patterns to include
        exclude_patterns: List of glob patterns to exclude
        
    Returns:
        Metrics object with calculated values
    """
    total_files = 0
    total_lines = 0
    total_chars = 0
    total_words = 0
    max_line_length = 0
    max_file_length = 0
    file_lengths = []
    
    # Convert patterns to absolute paths
    root = Path(root_path).resolve()
    
    # Collect all files matching include patterns
    all_files = set()
    for pattern in include_patterns:
        # Convert relative pattern to absolute
        if not pattern.startswith('/'):
            pattern = str(root / pattern)
        else:
            pattern = str(root / pattern.lstrip('/'))
        
        # Use glob to find matching files
        matches = glob.glob(pattern, recursive=True)
        all_files.update(matches)
    
    # Apply exclude patterns
    excluded_files = set()
    for pattern in exclude_patterns:
        if not pattern.startswith('/'):
            pattern = str(root / pattern)
        else:
            pattern = str(root / pattern.lstrip('/'))
        
        matches = glob.glob(pattern, recursive=True)
        excluded_files.update(matches)
    
    # Process files
    for file_path in all_files:
        if file_path in excluded_files:
            continue
            
        if not os.path.isfile(file_path):
            continue
            
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_lines = 0
                file_chars = 0
                file_words = 0
                
                for line in f:
                    line = line.rstrip('\n\r')
                    file_lines += 1
                    file_chars += len(line)
                    file_words += len(line.split())
                    
                    # Track max line length
                    max_line_length = max(max_line_length, len(line))
                
                total_files += 1
                total_lines += file_lines
                total_chars += file_chars
                total_words += file_words
                file_lengths.append(file_lines)
                max_file_length = max(max_file_length, file_lines)
                
        except Exception:
            # Skip files that can't be read
            continue
    
    # Calculate averages
    avg_line_length = total_chars / total_lines if total_lines > 0 else 0.0
    avg_file_length = sum(file_lengths) / len(file_lengths) if file_lengths else 0.0
    
    return Metrics(
        total_files=total_files,
        total_lines=total_lines,
        total_chars=total_chars,
        total_words=total_words,
        max_line_length=max_line_length,
        avg_line_length=avg_line_length,
        max_file_length=max_file_length,
        avg_file_length=avg_file_length
    )
