# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from tacs.core.typedef_scanner import TypedefScanner
from tacs.core.status_logger import StatusLogger


class DiscoveryManager:
    """Manages the discovery of typedefs and macros for time_t aliases."""
    
    def __init__(self, max_typedef_hops: int = 5, max_aliases: int = 64):
        """
        Initialize the discovery manager.
        
        Args:
            max_typedef_hops: Maximum number of hops to follow typedef chains
            max_aliases: Maximum number of typedef aliases to discover
        """
        self.typedef_scanner = TypedefScanner(max_typedef_hops, max_aliases)
        
        # Seed types for typedef discovery
        self.seed_types = {
            'time_t', 'clock_t', 'timer_t', 'suseconds_t', 'useconds_t',
            'struct_timespec', 'struct_timeval', 'struct_tm'
        }
    
    def discover_time_aliases(
        self,
        root_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str]
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """
        Discover time_t aliases and time-related macros.
        
        Args:
            root_path: Root directory to scan
            include_patterns: List of glob patterns to include
            exclude_patterns: List of glob patterns to exclude
            
        Returns:
            Tuple of (typedef_aliases, time_macros)
        """
        StatusLogger.timestamped_print("Stage 2: Discovering typedefs and macros...")
        
        # Scan for typedefs
        StatusLogger.timestamped_debug("  Scanning for typedefs...")
        all_typedefs = self.typedef_scanner.scan_directory(
            root_path, include_patterns, exclude_patterns
        )
        
        # Find time_t aliases
        StatusLogger.timestamped_debug("  Finding time_t aliases...")
        typedef_aliases = self.typedef_scanner.find_time_t_aliases(
            all_typedefs, self.seed_types
        )
        
        # Return empty macros dict since we now use integrated #define scanning
        time_macros = {}
        
        # Print results
        StatusLogger.timestamped_print(f"  Found {len(typedef_aliases)} typedef aliases")
        
        if typedef_aliases:
            StatusLogger.timestamped_debug("  Typedef aliases:")
            for alias_name in list(typedef_aliases.keys())[:5]:  # Show first 5
                StatusLogger.timestamped_debug(f"    {alias_name}")
            if len(typedef_aliases) > 5:
                StatusLogger.timestamped_debug(f"    ... and {len(typedef_aliases) - 5} more")
        
        return typedef_aliases, time_macros

    @staticmethod
    def _relativize_definition(definition: str, root_path: Optional[str]) -> str:
        """Prefer paths relative to the scan root in discovery artifacts."""
        if not root_path or ":" not in definition:
            return definition
        parts = definition.split(":", 2)
        if len(parts) < 3:
            return definition
        file_part, line_part, rest = parts[0], parts[1], parts[2]
        try:
            file_path = Path(file_part)
            root = Path(root_path).resolve()
            if file_path.is_absolute():
                try:
                    rel = file_path.resolve().relative_to(root)
                    return f"{rel.as_posix()}:{line_part}:{rest}"
                except ValueError:
                    return definition
        except OSError:
            return definition
        return definition

    def _relativize_alias_map(
        self,
        aliases: Dict[str, List[str]],
        root_path: Optional[str],
    ) -> Dict[str, List[str]]:
        return {
            name: [self._relativize_definition(d, root_path) for d in defs]
            for name, defs in aliases.items()
        }
    
    def update_rules_with_discoveries(
        self,
        rules_path: str,
        typedef_aliases: Dict[str, List[str]],
        time_macros: Dict[str, List[str]],
        *,
        output_dir: str,
        root_path: Optional[str] = None,
    ) -> str:
        """
        Build an updated rules file with discovered aliases/macros.

        Writes only under ``output_dir`` (typically the scan session ``prescan/``
        folder). Never modifies packaged or user-supplied rules paths.
        
        Args:
            rules_path: Path to original rules file (read-only)
            typedef_aliases: Discovered typedef aliases
            time_macros: Discovered time-related macros
            output_dir: Directory for discovery artifacts
            root_path: Scan root used to relativize definition paths
            
        Returns:
            Path to updated rules file under ``output_dir``
        """
        StatusLogger.timestamped_print("  Updating rules with discoveries...")

        typedef_aliases = self._relativize_alias_map(typedef_aliases, root_path)
        time_macros = self._relativize_alias_map(time_macros, root_path)
        
        # Load original rules
        with open(rules_path, 'r', encoding='utf-8') as f:
            original_rules = json.load(f)
        
        # Create new rules for discovered items
        new_rules = []
        
        # Add typedef aliases as type rules
        for alias_name, definitions in typedef_aliases.items():
            rule = {
                "symbol": alias_name,
                "risk": "high",
                "category": "type",
                "description": f"Typedef alias for time_t (discovered: {len(definitions)} definitions)",
                "discovered": True,
                "discovery_type": "typedef",
                "definitions": definitions
            }
            new_rules.append(rule)
        
        # Add time-related macros
        for macro_name, definitions in time_macros.items():
            rule = {
                "symbol": macro_name,
                "risk": "medium",
                "category": "macro",
                "description": f"Time-related macro (discovered: {len(definitions)} definitions)",
                "discovered": True,
                "discovery_type": "macro",
                "definitions": definitions
            }
            new_rules.append(rule)
        
        # Combine original and new rules
        updated_rules = original_rules + new_rules
        
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        updated_rules_path = out_dir / "rules_with_discoveries.json"
        
        with open(updated_rules_path, 'w', encoding='utf-8') as f:
            json.dump(updated_rules, f, indent=2)
        
        StatusLogger.timestamped_debug(f"  Updated rules saved to: {updated_rules_path}")
        StatusLogger.timestamped_print(
            f"  Added {len(new_rules)} new rules "
            f"({len(typedef_aliases)} typedefs, {len(time_macros)} macros)"
        )
        
        return str(updated_rules_path)
    
    def save_discovery_report(
        self,
        typedef_aliases: Dict[str, List[str]],
        time_macros: Dict[str, List[str]],
        output_path: str,
        *,
        root_path: Optional[str] = None,
    ):
        """
        Save discovery report to ``output_path`` (session/prescan preferred).
        """
        typedef_aliases = self._relativize_alias_map(typedef_aliases, root_path)
        time_macros = self._relativize_alias_map(time_macros, root_path)

        report = {
            "discovery_summary": {
                "typedef_aliases_count": len(typedef_aliases),
                "time_macros_count": len(time_macros),
                "total_discovered": len(typedef_aliases) + len(time_macros)
            },
            "typedef_aliases": typedef_aliases,
            "time_macros": time_macros
        }
        
        # Ensure output directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        StatusLogger.timestamped_debug(f"  Discovery report saved to: {output_path}")
