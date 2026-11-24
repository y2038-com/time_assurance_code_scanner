# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Bounded function definition/declaration index for one-hop callee propagation.

Compilation-independent lexical indexing only. Does not resolve overloads,
templates, or preprocessor configurations beyond recording distinct spans.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from tacs.core.function_scanner import (
    MAX_DECL_LOOKAHEAD_CHARS,
    MAX_DECL_LOOKAHEAD_LINES,
    _CONTROL_KEYWORDS,
    _function_name_from_header,
    _is_transparent_scope,
    _match_braces,
    _param_list_open_index,
    is_function_definition_header,
    mask_non_code,
    scan_functions,
)
from tacs.core.path_utils import canonical_source_path, repo_relative_path

_IDENT = re.compile(r"[A-Za-z_]\w*", re.ASCII)
_STATIC_RE = re.compile(r"\bstatic\b", re.ASCII)
_ELLIPSIS_RE = re.compile(r"\.\.\.")


@dataclass(frozen=True)
class IndexedParameter:
    """One named parameter from a function declarator (zero-based index)."""

    index: int
    name: str
    declared_type: str
    is_pointer: bool
    is_reference: bool
    is_array: bool


@dataclass(frozen=True)
class IndexedFunction:
    """One function definition or declaration in the source index."""

    file_abs: str
    file_rel: str
    symbol: str
    start_line: int
    end_line: int
    is_definition: bool
    is_static: bool
    is_variadic: bool
    parameters: Tuple[IndexedParameter, ...]
    header_text: str
    internal_id: str
    public_function_id: str
    type_fingerprint: str
    simple_symbol: str = ""

    def __post_init__(self) -> None:
        if not self.simple_symbol:
            object.__setattr__(
                self, "simple_symbol", self.symbol.rsplit("::", 1)[-1]
            )

    @property
    def arity(self) -> int:
        return len(self.parameters)


def _line_number(source: str, pos: int) -> int:
    if pos < 0:
        return 1
    if pos >= len(source):
        pos = max(0, len(source) - 1)
    return source.count("\n", 0, pos) + 1


def _split_top_level_commas(text: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(text[start:i].strip())
            start = i + 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def parse_parameter_list(header: str) -> Tuple[Tuple[IndexedParameter, ...], bool, Optional[str]]:
    """Parse parameters from a function header (text before ``{`` or ``;``).

    Returns ``(parameters, is_variadic, stop_reason)``. ``stop_reason`` is set
    when the declarator is unsupported (macros, unnamed-only forms, etc.).
    """
    compact = " ".join(header.split())
    open_idx = _param_list_open_index(compact)
    if open_idx is None:
        return (), False, "unsupported_parameter_form"
    # Find matching close.
    depth = 0
    close_idx = None
    for i in range(open_idx, len(compact)):
        if compact[i] == "(":
            depth += 1
        elif compact[i] == ")":
            depth -= 1
            if depth == 0:
                close_idx = i
                break
    if close_idx is None:
        return (), False, "unsupported_parameter_form"
    inside = compact[open_idx + 1 : close_idx].strip()
    if not inside or inside == "void":
        return (), False, None
    is_variadic = bool(_ELLIPSIS_RE.search(inside))
    pieces = _split_top_level_commas(inside)
    params: List[IndexedParameter] = []
    for piece in pieces:
        piece = piece.strip()
        if not piece or piece == "...":
            continue
        # Reject default arguments and attribute-heavy forms.
        if "=" in piece:
            return (), is_variadic, "unsupported_parameter_form"
        if "(" in piece and ")" in piece and "*" in piece:
            # Function-pointer parameter: unsupported for propagation.
            return (), is_variadic, "unsupported_parameter_form"
        idents = list(_IDENT.finditer(piece))
        if not idents:
            return (), is_variadic, "unsupported_parameter_form"
        name_match = idents[-1]
        name = name_match.group(0)
        if name in _CONTROL_KEYWORDS or name in {
            "void",
            "int",
            "char",
            "long",
            "short",
            "signed",
            "unsigned",
            "const",
            "volatile",
            "struct",
            "union",
            "enum",
            "float",
            "double",
        }:
            # Likely an unnamed parameter (type only).
            return (), is_variadic, "unsupported_parameter_form"
        declared_type = piece[: name_match.start()].strip()
        if not declared_type:
            return (), is_variadic, "unsupported_parameter_form"
        is_pointer = "*" in declared_type or "*" in piece[name_match.end() :]
        is_reference = "&" in declared_type and "*" not in declared_type
        is_array = "[" in piece[name_match.end() :]
        params.append(
            IndexedParameter(
                index=len(params),
                name=name,
                declared_type=declared_type,
                is_pointer=is_pointer,
                is_reference=is_reference,
                is_array=is_array,
            )
        )
    return tuple(params), is_variadic, None


def _type_fingerprint(params: Sequence[IndexedParameter], is_variadic: bool) -> str:
    parts = [f"{p.declared_type}|{int(p.is_pointer)}|{int(p.is_reference)}" for p in params]
    if is_variadic:
        parts.append("...")
    return ";".join(parts)


def _header_is_static(header: str) -> bool:
    # Storage class before the declarator name / param list.
    open_idx = _param_list_open_index(header)
    prefix = header[: open_idx if open_idx is not None else len(header)]
    return bool(_STATIC_RE.search(prefix))


def make_internal_id(
    file_rel: str,
    symbol: str,
    start_line: int,
    end_line: int,
    is_static: bool,
    arity: int,
    type_fingerprint: str,
) -> str:
    """Deterministic internal node identity (not the public function_id)."""
    return (
        f"{file_rel}|{symbol}|{start_line}|{end_line}|"
        f"{int(is_static)}|{arity}|{type_fingerprint}"
    )


def make_public_function_id(file_rel: str, symbol: str, start_line: int, end_line: int) -> str:
    """Existing public function_id shape used by functionization."""
    return f"{file_rel}@{symbol}:{start_line}-{end_line}"


def _index_definitions_from_source(
    source: str,
    file_abs: str,
    file_rel: str,
    *,
    masked: Optional[str] = None,
    scanned_functions: Optional[Sequence] = None,
) -> List[IndexedFunction]:
    out: List[IndexedFunction] = []
    lines = source.splitlines(keepends=True)
    scanned_list = (
        list(scanned_functions)
        if scanned_functions is not None
        else scan_functions(source, masked=masked)
    )
    for scanned in scanned_list:
        start_idx = max(0, scanned.start_line - 1)
        end_idx = min(len(lines), scanned.end_line)
        body = "".join(lines[start_idx:end_idx])
        # Header is text through the opening brace of the definition.
        brace = body.find("{")
        header = body[:brace] if brace >= 0 else body
        header_compact = " ".join(header.split())
        params, is_variadic, stop = parse_parameter_list(header_compact)
        # Still index even if params unsupported — resolution will reject.
        if stop:
            params = ()
            is_variadic = "..." in header_compact
        is_static = _header_is_static(header_compact)
        fingerprint = _type_fingerprint(params, is_variadic)
        internal = make_internal_id(
            file_rel,
            scanned.symbol,
            scanned.start_line,
            scanned.end_line,
            is_static,
            len(params),
            fingerprint,
        )
        public = make_public_function_id(
            file_rel, scanned.symbol, scanned.start_line, scanned.end_line
        )
        simple = scanned.symbol.rsplit("::", 1)[-1]
        out.append(
            IndexedFunction(
                file_abs=file_abs,
                file_rel=file_rel,
                symbol=scanned.symbol,
                start_line=scanned.start_line,
                end_line=scanned.end_line,
                is_definition=True,
                is_static=is_static,
                is_variadic=is_variadic,
                parameters=params,
                header_text=header_compact,
                internal_id=internal,
                public_function_id=public,
                type_fingerprint=fingerprint,
                simple_symbol=simple,
            )
        )
    return out


def _index_declarations_from_source(
    source: str,
    file_abs: str,
    file_rel: str,
    *,
    masked: Optional[str] = None,
) -> List[IndexedFunction]:
    """Index function prototypes (headers ending in ``;``), not definitions."""
    if not source:
        return []
    if masked is None:
        masked = mask_non_code(source)
    n = len(masked)
    out: List[IndexedFunction] = []
    i = 0
    while i < n:
        while i < n and masked[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        if masked[i] == "#":
            while i < n and masked[i] != "\n":
                i += 1
            continue
        if masked[i] == "}":
            i += 1
            continue
        access = re.match(r"(?:public|private|protected)\s*:", masked[i:])
        if access:
            i += access.end()
            continue

        decl_start = i
        paren_depth = 0
        chars_seen = 0
        lines_seen = 0
        found_brace = False
        found_semi = False
        brace_pos: Optional[int] = None
        abandoned = False
        while i < n:
            ch = masked[i]
            chars_seen += 1
            if ch == "\n":
                lines_seen += 1
            if chars_seen > MAX_DECL_LOOKAHEAD_CHARS or lines_seen > MAX_DECL_LOOKAHEAD_LINES:
                abandoned = True
                break
            if ch == "(":
                paren_depth += 1
                i += 1
                continue
            if ch == ")":
                if paren_depth > 0:
                    paren_depth -= 1
                i += 1
                continue
            if paren_depth == 0:
                if ch == ";":
                    found_semi = True
                    i += 1
                    break
                if ch == "{":
                    found_brace = True
                    brace_pos = i
                    break
                if ch == "}":
                    i += 1
                    break
            i += 1
        else:
            break

        if abandoned:
            i = decl_start + 1
            continue
        if found_brace and brace_pos is not None:
            start_pos = decl_start
            while start_pos < brace_pos and masked[start_pos] in " \t\r\n":
                start_pos += 1
            header = masked[start_pos:brace_pos]
            if is_function_definition_header(header):
                end_pos = _match_braces(masked, brace_pos)
                i = end_pos + 1
            elif _is_transparent_scope(header):
                i = brace_pos + 1
            else:
                end_pos = _match_braces(masked, brace_pos)
                i = end_pos + 1
            continue
        if found_semi:
            start_pos = decl_start
            semi_pos = i - 1
            while start_pos < semi_pos and masked[start_pos] in " \t\r\n":
                start_pos += 1
            header = masked[start_pos:semi_pos]
            compact = " ".join(header.split())
            if not compact or "(" not in compact:
                continue
            # Prototypes look like definitions except they end with ';'.
            name = _function_name_from_header(compact)
            if not name:
                # Try treating as prototype: temporarily require name extraction.
                # _function_name_from_header rejects empty return-type prefixes
                # for ctors; ordinary prototypes with a return type should work
                # if we append a fake brace check via is_function_definition_header
                # which rejects '=' after params — prototypes usually match.
                continue
            # Avoid recording control macros / obvious non-functions.
            base = name.split("::")[-1]
            if base in _CONTROL_KEYWORDS:
                continue
            params, is_variadic, stop = parse_parameter_list(compact)
            if stop:
                params = ()
            is_static = _header_is_static(compact)
            start_line = _line_number(source, start_pos)
            end_line = _line_number(source, semi_pos)
            fingerprint = _type_fingerprint(params, is_variadic)
            internal = make_internal_id(
                file_rel, name, start_line, end_line, is_static, len(params), fingerprint
            )
            public = make_public_function_id(file_rel, name, start_line, end_line)
            out.append(
                IndexedFunction(
                    file_abs=file_abs,
                    file_rel=file_rel,
                    symbol=name,
                    start_line=start_line,
                    end_line=end_line,
                    is_definition=False,
                    is_static=is_static,
                    is_variadic=is_variadic,
                    parameters=params,
                    header_text=compact,
                    internal_id=internal,
                    public_function_id=public,
                    type_fingerprint=fingerprint,
                    simple_symbol=base,
                )
            )
    return out


@dataclass
class SourceIndex:
    """Project-scoped index of definitions and declarations."""

    definitions: List[IndexedFunction] = field(default_factory=list)
    declarations: List[IndexedFunction] = field(default_factory=list)
    by_internal_id: Dict[str, IndexedFunction] = field(default_factory=dict)
    definitions_by_name: Dict[str, List[IndexedFunction]] = field(default_factory=dict)
    definitions_by_simple_name: Dict[str, List[IndexedFunction]] = field(
        default_factory=dict
    )
    declarations_by_simple_name: Dict[str, List[IndexedFunction]] = field(
        default_factory=dict
    )
    definitions_by_file: Dict[str, List[IndexedFunction]] = field(default_factory=dict)

    def definitions_named(self, name: str) -> List[IndexedFunction]:
        hit = self.definitions_by_simple_name.get(name)
        if hit is not None:
            return list(hit)
        return list(self.definitions_by_name.get(name, ()))


def build_source_index(
    files: Iterable[Path],
    root_path: str,
    sources_by_abs: Optional[Dict[str, str]] = None,
    *,
    masked_by_abs: Optional[Dict[str, str]] = None,
    scanned_by_abs: Optional[Dict[str, Sequence]] = None,
    include_declarations: bool = True,
) -> SourceIndex:
    """Build a deterministic function index over the scanned file set.

    When ``sources_by_abs`` / ``masked_by_abs`` / ``scanned_by_abs`` are
    provided, they are reused for the scan lifetime (one scan; no cross-repo
    retention). Set ``include_declarations=False`` for a definitions-only
    index when cross-file visibility is not yet needed.
    """
    root = Path(canonical_source_path(root_path))
    file_list = sorted(
        {Path(canonical_source_path(p)) for p in files},
        key=lambda p: repo_relative_path(p, root),
    )
    index = SourceIndex()
    for path in file_list:
        abs_path = str(path)
        rel = repo_relative_path(abs_path, root) or abs_path
        if sources_by_abs is not None and abs_path in sources_by_abs:
            source = sources_by_abs[abs_path]
        else:
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
        masked = None if masked_by_abs is None else masked_by_abs.get(abs_path)
        scanned = None if scanned_by_abs is None else scanned_by_abs.get(abs_path)
        defs = _index_definitions_from_source(
            source, abs_path, rel, masked=masked, scanned_functions=scanned
        )
        decls = (
            _index_declarations_from_source(source, abs_path, rel, masked=masked)
            if include_declarations
            else []
        )
        for fn in defs:
            index.definitions.append(fn)
            index.by_internal_id[fn.internal_id] = fn
            index.definitions_by_name.setdefault(fn.symbol, []).append(fn)
            index.definitions_by_simple_name.setdefault(fn.simple_symbol, []).append(fn)
            index.definitions_by_file.setdefault(fn.file_abs, []).append(fn)
        for decl in decls:
            index.declarations.append(decl)
            index.declarations_by_simple_name.setdefault(
                decl.simple_symbol, []
            ).append(decl)

    # Deterministic ordering of name buckets.
    for name in list(index.definitions_by_name.keys()):
        index.definitions_by_name[name] = sorted(
            index.definitions_by_name[name],
            key=lambda f: (f.file_rel, f.start_line, f.end_line, f.internal_id),
        )
    for name in list(index.definitions_by_simple_name.keys()):
        index.definitions_by_simple_name[name] = sorted(
            index.definitions_by_simple_name[name],
            key=lambda f: (f.file_rel, f.start_line, f.end_line, f.internal_id),
        )
    for name in list(index.declarations_by_simple_name.keys()):
        index.declarations_by_simple_name[name] = sorted(
            index.declarations_by_simple_name[name],
            key=lambda f: (f.file_rel, f.start_line, f.end_line, f.internal_id),
        )
    index.definitions.sort(
        key=lambda f: (f.file_rel, f.start_line, f.end_line, f.internal_id)
    )
    index.declarations.sort(
        key=lambda f: (f.file_rel, f.start_line, f.end_line, f.internal_id)
    )
    return index
