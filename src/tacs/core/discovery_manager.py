# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from tacs.core.alias_scope import (
    build_include_adjacency,
    compute_scoped_time_aliases,
    flatten_scoped_aliases,
    relativize_scoped_aliases,
)
from tacs.core.status_logger import StatusLogger
from tacs.core.typedef_scanner import TypedefScanner


class DiscoveryManager:
    """Manages the discovery of typedefs and macros for time_t aliases."""

    def __init__(
        self,
        max_typedef_hops: int = 5,
        max_aliases: int = 64,
        max_file_size: Optional[int] = None,
    ):
        """
        Initialize the discovery manager.

        Args:
            max_typedef_hops: Maximum number of hops to follow typedef chains
            max_aliases: Maximum number of typedef aliases to discover
            max_file_size: Optional per-file byte limit; larger files are not read
        """
        self.max_file_size = max_file_size
        self.typedef_scanner = TypedefScanner(
            max_typedef_hops, max_aliases, max_file_size=max_file_size
        )

        # Seed types for typedef discovery
        self.seed_types = {
            "time_t",
            "clock_t",
            "timer_t",
            "suseconds_t",
            "useconds_t",
            "struct_timespec",
            "struct_timeval",
            "struct_tm",
        }

    def discover_time_aliases(
        self,
        root_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str],
    ) -> Tuple[Dict[str, Dict[str, List[str]]], Dict[str, List[str]]]:
        """
        Discover time_t aliases scoped per translation unit.

        Args:
            root_path: Root directory to scan
            include_patterns: List of glob patterns to include
            exclude_patterns: List of glob patterns to exclude

        Returns:
            Tuple of ``(scoped_aliases, time_macros)`` where ``scoped_aliases``
            maps absolute file path → alias name → definition strings in scope
            for that file. ``time_macros`` is empty (defines use the integrated
            per-site scanner).
        """
        StatusLogger.timestamped_print("Stage 2: Discovering typedefs and macros...")

        StatusLogger.timestamped_debug("  Scanning for typedefs...")
        per_file_typedefs = self.typedef_scanner.scan_directory(
            root_path, include_patterns, exclude_patterns
        )

        files = [Path(p) for p in per_file_typedefs.keys()]
        StatusLogger.timestamped_debug("  Building project include adjacency...")
        adjacency = build_include_adjacency(files, root_path)

        StatusLogger.timestamped_debug("  Finding time_t aliases per translation unit...")
        scoped_aliases = compute_scoped_time_aliases(
            per_file_typedefs,
            adjacency,
            self.typedef_scanner.find_time_t_aliases,
            self.seed_types,
        )

        # Integrated #define scanning emits candidates at the define site;
        # macros are not promoted into the global symbol table here.
        time_macros: Dict[str, List[str]] = {}

        flat = flatten_scoped_aliases(scoped_aliases)
        StatusLogger.timestamped_debug(
            f"  Found {len(flat)} typedef aliases across {len(scoped_aliases)} files"
        )

        if flat:
            StatusLogger.timestamped_debug("  Typedef aliases:")
            for alias_name in list(flat.keys())[:5]:
                StatusLogger.timestamped_debug(f"    {alias_name}")
            if len(flat) > 5:
                StatusLogger.timestamped_debug(f"    ... and {len(flat) - 5} more")

        return scoped_aliases, time_macros

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
        typedef_aliases: Dict[str, List[str]] | Dict[str, Dict[str, List[str]]],
        time_macros: Dict[str, List[str]],
        *,
        output_dir: str,
        root_path: Optional[str] = None,
        scoped_aliases: Optional[Dict[str, Dict[str, List[str]]]] = None,
    ) -> str:
        """
        Build an updated rules file with discovered aliases/macros.

        Writes only under ``output_dir`` (typically the scan session ``prescan/``
        folder). Never modifies packaged or user-supplied rules paths.

        Catalog symbols may still be promoted as discovered typedef rules when a
        translation unit locally aliases that spelling (for example
        ``typedef time_t time;``). Those rules always carry ``scope_files`` and
        ``type_use_only`` so the IR scanner applies them only to non-call uses
        inside the declaring TU. Catalog function/type rules remain authoritative
        at call sites and in files outside that scope.

        When ``scoped_aliases`` is provided (preferred), each promoted discovered
        rule carries ``scope_files`` listing the repo-relative paths where that
        alias is in scope. The IR scanner must honor that list.
        """
        StatusLogger.timestamped_debug("  Updating rules with discoveries...")

        # Load original rules
        with open(rules_path, "r", encoding="utf-8") as f:
            original_rules = json.load(f)

        catalog_symbols: Set[str] = set()
        for rule in original_rules:
            if isinstance(rule, dict):
                symbol = rule.get("symbol") or rule.get("name")
                if isinstance(symbol, str) and symbol:
                    catalog_symbols.add(symbol)

        # Normalize scoped map to repo-relative keys when available.
        scoped_rel: Dict[str, Dict[str, List[str]]] = {}
        if scoped_aliases is not None and root_path is not None:
            scoped_rel = relativize_scoped_aliases(
                scoped_aliases,
                root_path,
                self._relativize_definition,
            )
        elif scoped_aliases is not None:
            scoped_rel = {
                k: dict(v) for k, v in sorted(scoped_aliases.items(), key=lambda kv: kv[0])
            }
        elif typedef_aliases and _looks_scoped(typedef_aliases):
            # Already a file→aliases map (absolute or relative keys).
            if root_path is not None:
                scoped_rel = relativize_scoped_aliases(
                    typedef_aliases,  # type: ignore[arg-type]
                    root_path,
                    self._relativize_definition,
                )
            else:
                scoped_rel = {
                    k: dict(v)
                    for k, v in sorted(typedef_aliases.items(), key=lambda kv: kv[0])  # type: ignore[union-attr]
                }

        new_rules: List[dict] = []

        if scoped_rel:
            # alias → (scope_files, definitions)
            alias_scopes: Dict[str, Set[str]] = {}
            alias_defs: Dict[str, List[str]] = {}
            for file_rel in sorted(scoped_rel.keys()):
                for alias_name in sorted(scoped_rel[file_rel].keys()):
                    alias_scopes.setdefault(alias_name, set()).add(file_rel)
                    bucket = alias_defs.setdefault(alias_name, [])
                    for definition in scoped_rel[file_rel][alias_name]:
                        if definition not in bucket:
                            bucket.append(definition)

            for alias_name in sorted(alias_scopes.keys()):
                definitions = alias_defs[alias_name]
                rule = {
                    "symbol": alias_name,
                    "risk": "high",
                    "category": "simple type",
                    "description": (
                        f"Typedef alias for time_t "
                        f"(discovered: {len(definitions)} definitions)"
                    ),
                    "discovered": True,
                    "discovery_type": "typedef",
                    "definitions": definitions,
                    "scope_files": sorted(alias_scopes[alias_name]),
                }
                # Spelling collision with a catalog symbol: keep both, but restrict
                # the discovered rule to non-call (type-use) syntax in scope.
                if alias_name in catalog_symbols:
                    rule["type_use_only"] = True
                new_rules.append(rule)
        else:
            # Legacy flat map path (tests / callers without scope).
            flat_aliases = self._relativize_alias_map(
                typedef_aliases if isinstance(typedef_aliases, dict) else {},
                root_path,
            )
            # If values are lists of strings, treat as flat alias→defs.
            if flat_aliases and all(
                isinstance(v, list) and (not v or isinstance(v[0], str))
                for v in flat_aliases.values()
            ):
                for alias_name in sorted(flat_aliases.keys()):
                    definitions = flat_aliases[alias_name]
                    if not isinstance(definitions, list):
                        continue
                    rule = {
                        "symbol": alias_name,
                        "risk": "high",
                        "category": "simple type",
                        "description": (
                            f"Typedef alias for time_t "
                            f"(discovered: {len(definitions)} definitions)"
                        ),
                        "discovered": True,
                        "discovery_type": "typedef",
                        "definitions": definitions,
                    }
                    if alias_name in catalog_symbols:
                        # Without scope_files, a colliding flat promotion would
                        # reintroduce cross-file conflicts; skip in legacy mode.
                        continue
                    new_rules.append(rule)

        time_macros = self._relativize_alias_map(time_macros, root_path)
        for macro_name in sorted(time_macros.keys()):
            if macro_name in catalog_symbols:
                # Macros that collide with catalog spellings stay unpromoted;
                # define_scanner still reports them at the defining site.
                continue
            definitions = time_macros[macro_name]
            rule = {
                "symbol": macro_name,
                "risk": "medium",
                "category": "macro",
                "description": (
                    f"Time-related macro (discovered: {len(definitions)} definitions)"
                ),
                "discovered": True,
                "discovery_type": "macro",
                "definitions": definitions,
            }
            new_rules.append(rule)

        updated_rules = list(original_rules) + new_rules

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        updated_rules_path = out_dir / "rules_with_discoveries.json"

        with open(updated_rules_path, "w", encoding="utf-8") as f:
            json.dump(updated_rules, f, indent=2)

        StatusLogger.timestamped_debug(f"  Updated rules saved to: {updated_rules_path}")
        StatusLogger.timestamped_debug(
            f"  Added {len(new_rules)} new rules "
            f"({sum(1 for r in new_rules if r.get('discovery_type') == 'typedef')} typedefs, "
            f"{sum(1 for r in new_rules if r.get('discovery_type') == 'macro')} macros)"
        )

        return str(updated_rules_path)

    def save_discovery_report(
        self,
        typedef_aliases: Dict[str, List[str]] | Dict[str, Dict[str, List[str]]],
        time_macros: Dict[str, List[str]],
        output_path: str,
        *,
        root_path: Optional[str] = None,
        scoped_aliases: Optional[Dict[str, Dict[str, List[str]]]] = None,
    ):
        """
        Save discovery report to ``output_path`` (session/prescan preferred).
        """
        scoped_rel: Optional[Dict[str, Dict[str, List[str]]]] = None
        if scoped_aliases is not None and root_path is not None:
            scoped_rel = relativize_scoped_aliases(
                scoped_aliases,
                root_path,
                self._relativize_definition,
            )
            flat = flatten_scoped_aliases(scoped_rel)
        elif scoped_aliases is not None:
            scoped_rel = {k: dict(v) for k, v in scoped_aliases.items()}
            flat = flatten_scoped_aliases(scoped_rel)
        elif _looks_scoped(typedef_aliases):
            if root_path is not None:
                scoped_rel = relativize_scoped_aliases(
                    typedef_aliases,  # type: ignore[arg-type]
                    root_path,
                    self._relativize_definition,
                )
            else:
                scoped_rel = {
                    k: dict(v) for k, v in typedef_aliases.items()  # type: ignore[union-attr]
                }
            flat = flatten_scoped_aliases(scoped_rel)
        else:
            flat = self._relativize_alias_map(
                typedef_aliases if isinstance(typedef_aliases, dict) else {},
                root_path,
            )

        time_macros = self._relativize_alias_map(time_macros, root_path)

        report = {
            "discovery_summary": {
                "typedef_aliases_count": len(flat),
                "time_macros_count": len(time_macros),
                "total_discovered": len(flat) + len(time_macros),
                "scoped_files": len(scoped_rel) if scoped_rel is not None else 0,
            },
            "typedef_aliases": flat,
            "time_macros": time_macros,
        }
        if scoped_rel is not None:
            report["scoped_typedef_aliases"] = scoped_rel

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        StatusLogger.timestamped_debug(f"  Discovery report saved to: {output_path}")


def _looks_scoped(aliases: object) -> bool:
    """True when ``aliases`` looks like file → {alias → defs} rather than alias → defs."""
    if not isinstance(aliases, dict) or not aliases:
        return False
    sample = next(iter(aliases.values()))
    if not isinstance(sample, dict):
        return False
    # file→alias→list
    if not sample:
        return True
    inner = next(iter(sample.values()))
    return isinstance(inner, list)
