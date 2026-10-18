# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Translation-unit scope for discovered typedef aliases.

Implementation-file typedefs apply only within that translation unit.
Project headers apply to files that include them (direct or transitive),
not to every scanned source merely because the header was discovered.

Include resolution is intentionally conservative: only ``#include`` specs that
resolve to another file already in the scan set are followed. System headers
and unresolved includes are ignored rather than treated as global.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from tacs.core.path_utils import canonical_source_path, repo_relative_path

# Quoted or angle includes; group 1 is the delimiter, group 2 is the path spec.
_INCLUDE_RE = re.compile(
    r'^\s*#\s*include\s*([<"])([^>"]+)[>"]',
    re.MULTILINE,
)

IMPL_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".C", ".c++"}
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".H", ".h++"}


def is_implementation_file(path: str) -> bool:
    return Path(path).suffix in IMPL_SUFFIXES


def is_header_file(path: str) -> bool:
    return Path(path).suffix in HEADER_SUFFIXES


def parse_include_specs(content: str) -> List[Tuple[str, bool]]:
    """Return ``(include_spec, is_quoted)`` pairs in source order."""
    out: List[Tuple[str, bool]] = []
    for match in _INCLUDE_RE.finditer(content):
        delim, spec = match.group(1), match.group(2).strip()
        if not spec:
            continue
        out.append((spec, delim == '"'))
    return out


def _index_scan_files(
    files: Iterable[Path],
    root: Path,
) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str]]:
    """Build abs→rel, rel→abs, and unique-basename→abs indexes."""
    abs_to_rel: Dict[str, str] = {}
    rel_to_abs: Dict[str, str] = {}
    basename_to_abs: Dict[str, str] = {}
    ambiguous_basenames: Set[str] = set()
    for file_path in files:
        abs_path = canonical_source_path(file_path)
        rel = repo_relative_path(abs_path, root)
        abs_to_rel[abs_path] = rel
        rel_to_abs[rel] = abs_path
        base = Path(rel).name
        if base in ambiguous_basenames:
            continue
        prior = basename_to_abs.get(base)
        if prior is None:
            basename_to_abs[base] = abs_path
        elif prior != abs_path:
            ambiguous_basenames.add(base)
            basename_to_abs.pop(base, None)
    return abs_to_rel, rel_to_abs, basename_to_abs


def resolve_project_include(
    includer_abs: str,
    spec: str,
    *,
    is_quoted: bool,
    root: Path,
    abs_to_rel: Mapping[str, str],
    basename_to_abs: Mapping[str, str],
) -> Optional[str]:
    """Resolve an include to a scanned project file absolute path, or ``None``."""
    root_abs = canonical_source_path(root)
    candidates: List[Path] = []
    if is_quoted:
        candidates.append(Path(includer_abs).parent / spec)
        candidates.append(Path(root_abs) / spec)
    else:
        # Angle brackets: only honor if the header is itself in the scan set.
        candidates.append(Path(root_abs) / spec)

    for candidate in candidates:
        try:
            abs_cand = canonical_source_path(candidate)
        except OSError:
            continue
        if abs_cand in abs_to_rel:
            return abs_cand

    # Quoted basename-only include when the scanned set has a unique match.
    if is_quoted and "/" not in spec.replace("\\", "/"):
        hit = basename_to_abs.get(Path(spec).name)
        if hit is not None:
            return hit
    return None


def build_include_adjacency(
    files: Iterable[Path],
    root_path: str,
) -> Dict[str, Set[str]]:
    """
    Map absolute file path → set of absolute paths it directly includes.

    Only includes that resolve into the scanned file set are recorded.
    """
    root = Path(canonical_source_path(root_path))
    file_list = sorted(files, key=lambda p: repo_relative_path(p, root))
    abs_to_rel, _rel_to_abs, basename_to_abs = _index_scan_files(file_list, root)

    adjacency: Dict[str, Set[str]] = {abs_path: set() for abs_path in abs_to_rel}
    for abs_path in sorted(abs_to_rel.keys()):
        try:
            content = Path(abs_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for spec, is_quoted in parse_include_specs(content):
            resolved = resolve_project_include(
                abs_path,
                spec,
                is_quoted=is_quoted,
                root=root,
                abs_to_rel=abs_to_rel,
                basename_to_abs=basename_to_abs,
            )
            if resolved and resolved != abs_path:
                adjacency[abs_path].add(resolved)
    return adjacency


def include_closure(
    start_abs: str,
    adjacency: Mapping[str, Set[str]],
) -> Set[str]:
    """Transitive include closure of ``start_abs`` (including itself)."""
    seen: Set[str] = set()
    stack = [start_abs]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        for nxt in adjacency.get(current, ()):
            if nxt not in seen:
                stack.append(nxt)
    return seen


def merge_typedef_maps(
    per_file: Mapping[str, Mapping[str, List[str]]],
    files: Iterable[str],
) -> Dict[str, List[str]]:
    """Merge typedef definitions from the given files (deterministic order)."""
    merged: Dict[str, List[str]] = {}
    for file_abs in sorted(files):
        file_map = per_file.get(file_abs) or {}
        for name in sorted(file_map.keys()):
            defs = file_map[name]
            bucket = merged.setdefault(name, [])
            for definition in defs:
                if definition not in bucket:
                    bucket.append(definition)
    return merged


def compute_scoped_time_aliases(
    per_file_typedefs: Mapping[str, Mapping[str, List[str]]],
    adjacency: Mapping[str, Set[str]],
    find_time_t_aliases,
    seed_types: Optional[Set[str]] = None,
) -> Dict[str, Dict[str, List[str]]]:
    """
    Compute time_t alias maps in scope for each scanned file.

    Keys and nested definition paths remain absolute file paths (callers may
    relativize for artifacts). Alias discovery runs on the typedefs visible in
    that file's include closure.
    """
    scoped: Dict[str, Dict[str, List[str]]] = {}
    for file_abs in sorted(per_file_typedefs.keys()):
        closure = include_closure(file_abs, adjacency)
        # Restrict closure to files we actually typedef-scanned.
        visible = [f for f in sorted(closure) if f in per_file_typedefs]
        merged = merge_typedef_maps(per_file_typedefs, visible)
        aliases = find_time_t_aliases(merged, seed_types)
        scoped[file_abs] = aliases
    return scoped


def flatten_scoped_aliases(
    scoped: Mapping[str, Mapping[str, List[str]]],
) -> Dict[str, List[str]]:
    """Union of aliases across scopes (for reports / LLM data plane only)."""
    flat: Dict[str, List[str]] = {}
    for file_abs in sorted(scoped.keys()):
        for alias in sorted(scoped[file_abs].keys()):
            defs = scoped[file_abs][alias]
            bucket = flat.setdefault(alias, [])
            for definition in defs:
                if definition not in bucket:
                    bucket.append(definition)
    return flat


def relativize_scoped_aliases(
    scoped: Mapping[str, Mapping[str, List[str]]],
    root_path: str,
    relativize_definition,
) -> Dict[str, Dict[str, List[str]]]:
    """Rewrite scoped alias maps to repo-relative file keys and definitions."""
    out: Dict[str, Dict[str, List[str]]] = {}
    for file_abs in sorted(scoped.keys()):
        rel_file = repo_relative_path(file_abs, root_path)
        file_aliases: Dict[str, List[str]] = {}
        for alias in sorted(scoped[file_abs].keys()):
            file_aliases[alias] = [
                relativize_definition(d, root_path) for d in scoped[file_abs][alias]
            ]
        out[rel_file] = file_aliases
    return out


def aliases_for_source_file(
    scoped_rel: Mapping[str, Mapping[str, List[str]]],
    file_path: str,
    root_path: Optional[str] = None,
) -> Dict[str, List[str]]:
    """Look up the in-scope alias map for a source file path."""
    if not scoped_rel:
        return {}
    if file_path in scoped_rel:
        return dict(scoped_rel[file_path])
    if root_path:
        rel = repo_relative_path(file_path, root_path)
        if rel in scoped_rel:
            return dict(scoped_rel[rel])
    # Absolute key fallback (pre-relativized maps).
    abs_path = canonical_source_path(file_path)
    if abs_path in scoped_rel:
        return dict(scoped_rel[abs_path])
    return {}
