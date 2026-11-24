# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Bounded preprocessor-condition stacks for fail-closed call resolution.

Does not solve Boolean expressions. Records the textual ``#if`` / ``#ifdef`` /
``#ifndef`` / ``#elif`` / ``#else`` stack active at a source line so callers and
callees under mutually exclusive or incompatible branches are not linked.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

_IF_RE = re.compile(
    r"^\s*#\s*(?P<kw>if|ifdef|ifndef|elif|else|endif)\b(?P<rest>.*)$",
    re.ASCII,
)


def condition_stack_at_line(source: str, line: int) -> Tuple[str, ...]:
    """Return the active preprocessor condition texts at 1-based ``line``.

    Each stack entry is a normalized directive text such as ``ifdef CONFIG_A``
    or ``else (!ifdef CONFIG_A)``. Empty tuple means no surrounding condition
    was observed (or the line is before any directive).
    """
    if not source or line < 1:
        return ()
    # Prefer the file-level cache when the caller prepared one (same scan).
    return _stack_from_lines(source.splitlines(), line)


def build_condition_stack_cache(source: str) -> List[Tuple[str, ...]]:
    """Return a 0-based list where entry ``i`` is the stack at line ``i+1``.

    Built once per file for a scan; avoids re-walking the file for every call.
    """
    lines = source.splitlines()
    if not lines:
        return []
    out: List[Tuple[str, ...]] = []
    stack: List[str] = []
    opens: List[str] = []
    for raw in lines:
        match = _IF_RE.match(raw.rstrip("\n"))
        if match:
            kw = match.group("kw")
            rest = (match.group("rest") or "").strip()
            if kw in {"if", "ifdef", "ifndef"}:
                text = f"{kw} {rest}".strip()
                stack.append(text)
                opens.append(text)
            elif kw == "elif":
                if stack:
                    stack[-1] = f"elif {rest}".strip()
                else:
                    stack.append(f"elif {rest}".strip())
                    opens.append(stack[-1])
            elif kw == "else":
                if stack:
                    prior = opens[-1] if opens else stack[-1]
                    stack[-1] = f"else (!{prior})"
                else:
                    stack.append("else")
                    opens.append("else")
            elif kw == "endif":
                if stack:
                    stack.pop()
                if opens:
                    opens.pop()
        out.append(tuple(stack))
    return out


def stack_at_cached(cache: List[Tuple[str, ...]], line: int) -> Tuple[str, ...]:
    """Lookup a 1-based line in a ``build_condition_stack_cache`` result."""
    if line < 1 or line > len(cache):
        return ()
    return cache[line - 1]


def _stack_from_lines(lines: List[str], line: int) -> Tuple[str, ...]:
    stack: List[str] = []
    opens: List[str] = []
    for i, raw in enumerate(lines, start=1):
        if i > line:
            break
        match = _IF_RE.match(raw.rstrip("\n"))
        if not match:
            continue
        kw = match.group("kw")
        rest = (match.group("rest") or "").strip()
        if kw in {"if", "ifdef", "ifndef"}:
            text = f"{kw} {rest}".strip()
            stack.append(text)
            opens.append(text)
        elif kw == "elif":
            if stack:
                stack[-1] = f"elif {rest}".strip()
            else:
                stack.append(f"elif {rest}".strip())
                opens.append(stack[-1])
        elif kw == "else":
            if stack:
                prior = opens[-1] if opens else stack[-1]
                stack[-1] = f"else (!{prior})"
            else:
                stack.append("else")
                opens.append("else")
        elif kw == "endif":
            if stack:
                stack.pop()
            if opens:
                opens.pop()
    return tuple(stack)


def conditions_compatible(
    caller_stack: Tuple[str, ...],
    callee_stack: Tuple[str, ...],
) -> bool:
    """True when stacks are identical (including both empty).

    Fail closed: any mismatch, including one side empty and the other not,
    is treated as incompatible. Nested unresolved differences are rejected.
    """
    return caller_stack == callee_stack


def format_condition_stack(stack: Tuple[str, ...]) -> str:
    """Deterministic single-string form for diagnostics."""
    return " && ".join(stack) if stack else ""
