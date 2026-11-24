# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Direct call-site indexing inside function bodies (issue #57).

Bounded lexical recognition of ordinary call expressions. Does not expand
macros, resolve function pointers, or claim compiler-accurate call graphs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from tacs.core.function_scanner import mask_non_code
from tacs.core.source_index import IndexedFunction

#: Maximum characters of a call expression (callee through closing paren).
MAX_CALL_EXPRESSION_CHARS = 512

_CALL_START = re.compile(
    r"(?P<qual>(?:[A-Za-z_]\w*::)*)"
    r"(?P<name>[A-Za-z_]\w*)"
    r"(?P<member>(?:\.(?:[A-Za-z_]\w*)|->(?:[A-Za-z_]\w*))*)"
    r"\s*\(",
    re.ASCII,
)

_CONTROL = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "sizeof",
        "typeof",
        "return",
        "case",
        "alignof",
        "decltype",
        "static_assert",
        "noexcept",
        "new",
        "delete",
        "throw",
    }
)


@dataclass
class CallArgument:
    """One top-level call argument (zero-based index)."""

    index: int
    expression: str


@dataclass
class CallSite:
    """One recognized call-like occurrence inside a caller function."""

    caller: IndexedFunction
    file_rel: str
    line: int
    column: int
    raw_expression: str
    callee_expr: str
    simple_name: str
    call_form: str  # direct_id | qualified | member_dot | member_arrow | macro_like | indirect
    arguments: Tuple[CallArgument, ...]
    argument_count: int
    stop_reasons: Tuple[str, ...] = ()
    truncated: bool = False


def _line_col_at(source: str, offset: int) -> Tuple[int, int]:
    if offset < 0:
        return 1, 1
    if offset > len(source):
        offset = len(source)
    line = source.count("\n", 0, offset) + 1
    last_nl = source.rfind("\n", 0, offset)
    col = offset - last_nl
    return line, col


def _match_parens(masked: str, open_pos: int) -> Optional[int]:
    if open_pos < 0 or open_pos >= len(masked) or masked[open_pos] != "(":
        return None
    depth = 0
    for i in range(open_pos, len(masked)):
        ch = masked[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
    return None


def _split_args(arg_text: str) -> List[str]:
    parts: List[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(arg_text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(arg_text[start:i].strip())
            start = i + 1
    tail = arg_text[start:].strip()
    if tail or (arg_text and not parts):
        if tail:
            parts.append(tail)
    # Empty arg list → no parts; trailing comma alone is ignored.
    return [p for p in parts if p != "" or False]


def _classify_call_form(qual: str, name: str, member: str) -> str:
    if member:
        if "->" in member:
            return "member_arrow"
        return "member_dot"
    if qual:
        return "qualified"
    if name.isupper() and "_" in name:
        return "macro_like"
    if name.isupper() and len(name) > 1:
        return "macro_like"
    return "direct_id"


def _body_span(source: str, caller: IndexedFunction) -> Tuple[str, int]:
    """Return ``(body_text, abs_char_offset)`` for the function body after ``{``.

    The declarator / prototype is excluded so a definition header such as
    ``static void save_value(int64_t value)`` is never treated as a call site.
    """
    lines = source.splitlines(keepends=True)
    start_idx = max(0, caller.start_line - 1)
    end_idx = min(len(lines), caller.end_line)
    if start_idx >= end_idx:
        return "", 0
    abs_start = sum(len(lines[i]) for i in range(start_idx))
    span = "".join(lines[start_idx:end_idx])
    brace = span.find("{")
    if brace < 0:
        # Declaration-only or unparseable: no executable call sites.
        return "", abs_start
    body_abs = abs_start + brace + 1
    return span[brace + 1 :], body_abs


def find_call_sites_in_function(
    source: str,
    caller: IndexedFunction,
    *,
    masked_source: Optional[str] = None,
) -> List[CallSite]:
    """Find call sites inside ``caller``'s body (after the opening ``{``).

    When ``masked_source`` is the full-file ``mask_non_code(source)``, the body
    mask is sliced from it (same offsets) instead of re-masking the body.
    """
    if not source:
        return []
    body, abs_start = _body_span(source, caller)
    if not body:
        return []
    if masked_source is not None and len(masked_source) == len(source):
        # Body starts at abs_start within the full file.
        masked_body = masked_source[abs_start : abs_start + len(body)]
    else:
        masked_body = mask_non_code(body)
    sites: List[CallSite] = []

    for match in _CALL_START.finditer(masked_body):
        name = match.group("name")
        if name in _CONTROL:
            continue
        # Skip C++-style constructor / type-name initializer noise when the
        # identifier is immediately preceded by a cast-open without being a
        # call: handled below via control / form filters.
        qual = match.group("qual") or ""
        member = match.group("member") or ""
        open_rel = match.end() - 1  # position of '('
        if open_rel < 0 or open_rel >= len(masked_body) or masked_body[open_rel] != "(":
            continue
        # Reject when the match is a cast of the form TYPE(expr) used as a
        # C-style cast after an operator — still may be a call; leave to
        # resolution. Reject function-like type declarations: "typedef ... name("
        # appears outside bodies.
        close_rel = _match_parens(masked_body, open_rel)
        if close_rel is None:
            continue
        expr_start = match.start()
        expr_len = close_rel - expr_start + 1
        stop_reasons: List[str] = []
        truncated = False
        if expr_len > MAX_CALL_EXPRESSION_CHARS:
            # Do not truncate and then treat the text as a complete expression.
            stop_reasons.append("argument_expression_too_long")
            truncated = True
            continue

        raw = body[expr_start : close_rel + 1]
        arg_text = body[open_rel + 1 : close_rel]
        arg_strs = _split_args(arg_text)
        arguments: List[CallArgument] = []
        skip = False
        for idx, arg in enumerate(arg_strs):
            if len(arg) > MAX_CALL_EXPRESSION_CHARS:
                stop_reasons.append("argument_expression_too_long")
                truncated = True
                skip = True
                break
            arguments.append(CallArgument(index=idx, expression=arg.strip()))
        if skip:
            continue

        call_form = _classify_call_form(qual, name, member)
        name_rel = match.start("name")
        line, column = _line_col_at(source, abs_start + name_rel)
        # Drop matches that landed on the declarator line itself (defensive).
        if line < caller.start_line or line > caller.end_line:
            continue
        simple = name
        callee_expr = f"{qual}{name}{member}".strip()
        sites.append(
            CallSite(
                caller=caller,
                file_rel=caller.file_rel,
                line=line,
                column=column,
                raw_expression=raw.strip(),
                callee_expr=callee_expr,
                simple_name=simple,
                call_form=call_form,
                arguments=tuple(arguments),
                argument_count=len(arguments),
                stop_reasons=tuple(stop_reasons),
                truncated=truncated,
            )
        )

    sites.sort(key=lambda s: (s.file_rel, s.line, s.column, s.simple_name, s.raw_expression))
    return sites


def find_call_sites_for_index(
    sources_by_abs: dict,
    definitions: Sequence[IndexedFunction],
) -> List[CallSite]:
    """Index call sites for every definition that has readable source."""
    all_sites: List[CallSite] = []
    for fn in definitions:
        source = sources_by_abs.get(fn.file_abs)
        if not source:
            continue
        all_sites.extend(find_call_sites_in_function(source, fn))
    all_sites.sort(
        key=lambda s: (s.file_rel, s.line, s.column, s.caller.internal_id, s.simple_name)
    )
    return all_sites
