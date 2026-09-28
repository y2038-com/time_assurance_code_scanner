# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Bounded lexical scanner for C/C++ function *definitions*.

Used only by functionization: associating already-discovered deterministic
candidates with enclosing functions. This module does not discover candidates
and is not a substitute for tree-sitter-based catalog symbol search.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

# Bound how far a potential declaration may span before we abandon it.
MAX_DECL_LOOKAHEAD_LINES = 16
MAX_DECL_LOOKAHEAD_CHARS = 1024

_CONTROL_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "else",
        "do",
        "try",
        "sizeof",
        "typeof",
        "return",
        "case",
        "default",
        "goto",
        "throw",
        "delete",
        "new",
        "alignof",
        "decltype",
        "static_assert",
    }
)

# File-scope / type scopes we enter so nested free functions and in-class
# method definitions are seen. Nested enum/initializer braces are still skipped
# when they are not function headers.
_TRANSPARENT_SCOPE_RE = re.compile(
    r"^(?:inline\s+)?namespace\b|^extern\b|^(?:class|struct|union)\b",
    re.ASCII,
)

# Name immediately before the parameter list: ns::Class::method or ~Dtor.
_DECLARATOR_NAME_RE = re.compile(
    r"((?:[A-Za-z_]\w*::)*~?[A-Za-z_]\w*)\s*$",
    re.ASCII,
)

# Trailing C++ declarator junk after the closing ')' of the parameter list.
_TRAILING_AFTER_PARAMS_RE = re.compile(
    r"""
    (?:
        \s+const
      | \s+volatile
      | \s+override
      | \s+final
      | \s+noexcept(?:\s*\([^)]*\))?
      | \s+try
      | \s*&&
      | \s*&
      | \s*->\s*[^;{]+
    )*$
    """,
    re.ASCII | re.VERBOSE,
)


@dataclass(frozen=True)
class ScannedFunction:
    """One recognized function definition span (1-based inclusive lines)."""

    start_line: int
    end_line: int
    symbol: str


def mask_non_code(source: str) -> str:
    """Replace comments, strings, and character literals with spaces.

    Newlines are preserved so character offsets stay aligned with ``source``
    for line mapping. Brace/paren matching on the result ignores non-code.
    """
    out: List[str] = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "/":
            out.append(" ")
            out.append(" ")
            i += 2
            while i < n and source[i] != "\n":
                out.append("\r" if source[i] == "\r" else " ")
                i += 1
            continue

        if ch == "/" and nxt == "*":
            out.append(" ")
            out.append(" ")
            i += 2
            while i < n:
                if source[i] == "\n":
                    out.append("\n")
                    i += 1
                elif source[i] == "*" and i + 1 < n and source[i + 1] == "/":
                    out.append(" ")
                    out.append(" ")
                    i += 2
                    break
                else:
                    out.append("\r" if source[i] == "\r" else " ")
                    i += 1
            continue

        if ch == '"':
            out.append(" ")
            i += 1
            while i < n:
                if source[i] == "\\" and i + 1 < n:
                    out.append(" ")
                    out.append(" ")
                    i += 2
                    continue
                if source[i] == '"':
                    out.append(" ")
                    i += 1
                    break
                if source[i] == "\n":
                    out.append("\n")
                    i += 1
                else:
                    out.append("\r" if source[i] == "\r" else " ")
                    i += 1
            continue

        if ch == "'":
            out.append(" ")
            i += 1
            while i < n:
                if source[i] == "\\" and i + 1 < n:
                    out.append(" ")
                    out.append(" ")
                    i += 2
                    continue
                if source[i] == "'":
                    out.append(" ")
                    i += 1
                    break
                if source[i] == "\n":
                    out.append("\n")
                    i += 1
                else:
                    out.append("\r" if source[i] == "\r" else " ")
                    i += 1
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _line_number(source: str, pos: int) -> int:
    """1-based line number for a character offset in ``source``."""
    if pos < 0:
        return 1
    if pos >= len(source):
        pos = max(0, len(source) - 1)
    return source.count("\n", 0, pos) + 1


def _match_braces(masked: str, open_pos: int) -> int:
    """Return index of the closing ``}`` matching ``masked[open_pos]``."""
    depth = 0
    for i in range(open_pos, len(masked)):
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return max(open_pos, len(masked) - 1)


def _strip_trailing_after_params(header: str) -> str:
    """Remove C++ trailing qualifiers after the parameter list's ``)``."""
    h = header.rstrip()
    # Find the last ')' that closes the parameter list (paren depth 0 walk).
    depth = 0
    last_close = -1
    for i, ch in enumerate(h):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                last_close = i
    if last_close < 0:
        return h
    tail = h[last_close + 1 :]
    if not tail.strip():
        return h[: last_close + 1]
    if _TRAILING_AFTER_PARAMS_RE.fullmatch(tail):
        return h[: last_close + 1]
    return h


def _param_list_open_index(header: str) -> Optional[int]:
    """Index of ``(`` that opens the final top-level parameter list."""
    h = _strip_trailing_after_params(header)
    if not h.endswith(")"):
        return None
    depth = 0
    for i in range(len(h) - 1, -1, -1):
        ch = h[i]
        if ch == ")":
            depth += 1
        elif ch == "(":
            depth -= 1
            if depth == 0:
                return i
    return None


def _top_level_equals_after_params(header: str) -> bool:
    """True when ``=`` appears after the parameter list (initializer / defaulted)."""
    open_idx = _param_list_open_index(header)
    if open_idx is None:
        return False
    depth = 0
    close = None
    for i in range(open_idx, len(header)):
        if header[i] == "(":
            depth += 1
        elif header[i] == ")":
            depth -= 1
            if depth == 0:
                close = i
                break
    if close is None:
        return False
    depth = 0
    for ch in header[close + 1 :]:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "=" and depth == 0:
            return True
    return False


def _has_ctor_initializer_clause(header: str) -> bool:
    """True when a C++ ctor-initializer ``) :`` appears at top-level paren depth.

    Distinguishes ``Clock() : member(0)`` from ternary/default args inside
    ``(...)``. In-class constructors with initializer lists are not treated as
    ordinary methods; out-of-line ``Class::Class`` forms remain supported when
    they have no initializer clause before ``{``.
    """
    depth = 0
    for i, ch in enumerate(header):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                j = i + 1
                while j < len(header) and header[j] in " \t\r\n":
                    j += 1
                if j < len(header) and header[j] == ":":
                    return True
    return False


def _function_name_from_header(header: str) -> Optional[str]:
    """Return the declarator name, or None if this is not a definition header."""
    if "template" in header.split("(")[0]:
        return None
    if re.search(r"\boperator\b", header):
        return None
    if _has_ctor_initializer_clause(header):
        return None

    open_idx = _param_list_open_index(header)
    if open_idx is None:
        return None

    before = header[:open_idx].rstrip()
    # Reject function-pointer declarators: name is inside (*name).
    if before.endswith(")"):
        return None
    # Common FP shape: ... (*name) (
    if re.search(r"\(\s*\*+\s*[A-Za-z_]\w*\s*\)\s*$", before):
        return None

    match = _DECLARATOR_NAME_RE.search(before)
    if not match:
        return None

    full_name = match.group(1)
    base = full_name.split("::")[-1]
    bare = base[1:] if base.startswith("~") else base
    if bare in _CONTROL_KEYWORDS:
        return None

    prefix = before[: match.start()].strip()
    # Drop leading access labels absorbed when scanning inside a class body.
    prefix = re.sub(
        r"^(?:public|private|protected)\s*:\s*",
        "",
        prefix,
        count=1,
    )
    if not prefix:
        # Allow out-of-line ctor/dtor: Class::Class / Class::~Class
        parts = full_name.split("::")
        if len(parts) >= 2:
            cls = parts[-2]
            meth = parts[-1]
            if meth == cls or meth == f"~{cls}":
                return full_name
        return None

    # typedef ... name( — not a definition with '{' usually; still reject typedefs.
    if re.match(r"typedef\b", prefix):
        return None

    return full_name


def is_function_definition_header(header: str) -> bool:
    """True if ``header`` (text before ``{``) looks like a function definition."""
    compact = " ".join(header.split())
    if not compact or "(" not in compact or ")" not in compact:
        return False
    if _top_level_equals_after_params(compact):
        return False
    return _function_name_from_header(compact) is not None


def _is_transparent_scope(header: str) -> bool:
    compact = " ".join(header.split())
    # Inheritance / base-clause: "class Clock : public Base"
    return bool(_TRANSPARENT_SCOPE_RE.match(compact))


def scan_functions(source: str) -> List[ScannedFunction]:
    """Scan ``source`` for ordinary C/C++ function definitions.

    Skips prototypes (``;``), control statements, non-function brace blocks
    (enum/initializer), and uses bounded declaration lookahead. Enters
    namespace, extern, class, struct, and union scopes so nested free functions
    and straightforward in-class methods can be found.
    """
    if not source:
        return []

    masked = mask_non_code(source)
    n = len(masked)
    functions: List[ScannedFunction] = []
    i = 0

    while i < n:
        while i < n and masked[i] in " \t\r\n":
            i += 1
        if i >= n:
            break

        if masked[i] == "#":
            # Skip the entire directive line so braces / function-like text in
            # #define / #if lines do not participate in structural matching.
            while i < n and masked[i] != "\n":
                i += 1
            continue

        if masked[i] == "}":
            i += 1
            continue

        # Access labels inside class/struct: public: / private: / protected:
        rest = masked[i:]
        access = re.match(r"(?:public|private|protected)\s*:", rest)
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

        if found_semi:
            continue

        if found_brace and brace_pos is not None:
            # Advance decl_start past leading whitespace for accurate start_line.
            start_pos = decl_start
            while start_pos < brace_pos and masked[start_pos] in " \t\r\n":
                start_pos += 1
            header = masked[start_pos:brace_pos]
            if is_function_definition_header(header):
                name = _function_name_from_header(" ".join(header.split()))
                end_pos = _match_braces(masked, brace_pos)
                if name:
                    functions.append(
                        ScannedFunction(
                            start_line=_line_number(source, start_pos),
                            end_line=_line_number(source, end_pos),
                            symbol=name,
                        )
                    )
                i = end_pos + 1
            elif _is_transparent_scope(header):
                # Enter namespace / extern / class / struct / union.
                i = brace_pos + 1
            else:
                end_pos = _match_braces(masked, brace_pos)
                i = end_pos + 1
            continue

        # Unrecognized fragment: advance to avoid infinite loops.
        if i <= decl_start:
            i = decl_start + 1

    return functions
