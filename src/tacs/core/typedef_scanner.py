# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Bounded lexical discovery of typedef declarations.

This is not a complete C or C++ parser. Each ``typedef`` is closed at the
first top-level semicolon, with parentheses, brackets, and braces tracked so
struct/union/enum bodies and function-pointer declarators keep their internal
semicolons. Comments, strings, and character literals are masked first. If the
declaration boundary or alias name cannot be determined, the candidate is
omitted (fail closed) rather than taking an identifier from later source.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

from tacs.core.function_scanner import mask_non_code

_TYPEDEF_KEYWORD = re.compile(r"\btypedef\b")
_IDENTIFIER = re.compile(r"[A-Za-z_]\w*")
_FUNC_PTR_NAME = re.compile(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)")

_OPEN_TO_CLOSE = {"(": ")", "[": "]", "{": "}"}
_CLOSE_TO_OPEN = {")": "(", "]": "[", "}": "{"}
_AGGREGATE_TAGS = frozenset({"struct", "union", "enum", "class"})
_TYPE_QUALIFIERS = frozenset(
    {
        "const",
        "volatile",
        "restrict",
        "unsigned",
        "signed",
        "long",
        "short",
        "static",
        "extern",
        "register",
        "inline",
        "_Atomic",
        "constexpr",
        "consteval",
        "constinit",
        "alignas",
        "mutable",
        "typename",
    }
)

# Names that are never a typedef alias. Fail closed rather than promoting them.
_ALIAS_BLOCKLIST = frozenset(
    {
        "alignas",
        "alignof",
        "asm",
        "auto",
        "bool",
        "break",
        "case",
        "catch",
        "char",
        "char8_t",
        "char16_t",
        "char32_t",
        "class",
        "const",
        "consteval",
        "constexpr",
        "constinit",
        "continue",
        "decltype",
        "default",
        "delete",
        "do",
        "double",
        "else",
        "enum",
        "explicit",
        "export",
        "extern",
        "false",
        "float",
        "for",
        "friend",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "mutable",
        "namespace",
        "new",
        "noexcept",
        "nullptr",
        "operator",
        "private",
        "protected",
        "public",
        "register",
        "reinterpret_cast",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "static_assert",
        "static_cast",
        "struct",
        "switch",
        "template",
        "this",
        "thread_local",
        "throw",
        "true",
        "try",
        "typedef",
        "typeid",
        "typename",
        "union",
        "unsigned",
        "using",
        "virtual",
        "void",
        "volatile",
        "wchar_t",
        "while",
        "_Alignas",
        "_Alignof",
        "_Atomic",
        "_Bool",
        "_Complex",
        "_Generic",
        "_Imaginary",
        "_Noreturn",
        "_Static_assert",
        "_Thread_local",
    }
)


def _aggregate_body_allowed(prefix: str) -> bool:
    """True when a depth-0 ``{`` can open a struct/union/enum/class typedef body."""
    tokens = _IDENTIFIER.findall(prefix)
    if not tokens:
        return False
    start = 1 if tokens[0] == "typedef" else 0
    for tok in tokens[start:]:
        if tok in _TYPE_QUALIFIERS:
            continue
        return tok in _AGGREGATE_TAGS
    return False


def _end_of_declaration(masked: str, start: int) -> Optional[int]:
    """Index of the terminating ``;`` for the typedef starting at ``start``.

    Returns ``None`` when the input is incomplete, delimiters are unbalanced,
    or a later declaration begins before a terminating semicolon.
    """
    stack: List[str] = []
    for i in range(start, len(masked)):
        ch = masked[i]
        if not stack:
            if ch == ";":
                return i
            if ch == "{":
                if not _aggregate_body_allowed(masked[start:i]):
                    return None
                stack.append(ch)
                continue
            if (
                not ch.isspace()
                and ch not in "([*;"
                and _complete_func_ptr_prefix(masked[start:i])
            ):
                return None
        if ch in _OPEN_TO_CLOSE:
            stack.append(ch)
        elif ch in _CLOSE_TO_OPEN:
            if not stack or stack[-1] != _CLOSE_TO_OPEN[ch]:
                return None
            stack.pop()
    return None


def _complete_func_ptr_prefix(prefix: str) -> bool:
    """True when ``prefix`` is already a ``(*name)(...)`` typedef without ``;``."""
    handled, name = _function_pointer_alias(prefix)
    return handled and name is not None


def _skip_ws(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _skip_balanced(text: str, index: int) -> Optional[int]:
    """Return the index after a balanced ``(...)`` or ``[...]`` group."""
    if index >= len(text) or text[index] not in ("(", "["):
        return None
    opener = text[index]
    closer = _OPEN_TO_CLOSE[opener]
    depth = 0
    for i in range(index, len(text)):
        ch = text[i]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i + 1
    return None


def _only_params_or_arrays(text: str) -> bool:
    """True when ``text`` is only optional parameter lists and array bounds."""
    i = _skip_ws(text, 0)
    while i < len(text):
        if text[i] in "([":
            nxt = _skip_balanced(text, i)
            if nxt is None:
                return False
            i = _skip_ws(text, nxt)
            continue
        return False
    return True


def _last_identifier(text: str) -> Optional[str]:
    names = _IDENTIFIER.findall(text)
    if not names:
        return None
    name = names[-1]
    if name in _ALIAS_BLOCKLIST:
        return None
    return name


def _strip_trailing_arrays(text: str) -> str:
    body = text.rstrip()
    while body.endswith("]"):
        depth = 0
        cut = None
        for i in range(len(body) - 1, -1, -1):
            ch = body[i]
            if ch == "]":
                depth += 1
            elif ch == "[":
                depth -= 1
                if depth == 0:
                    cut = i
                    break
        if cut is None:
            break
        body = body[:cut].rstrip()
    return body


def _alias_after_braces(body: str) -> Optional[str]:
    depth = 0
    last_close = None
    for i, ch in enumerate(body):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                last_close = i
            elif depth < 0:
                return None
    if last_close is None:
        return None
    suffix = _strip_trailing_arrays(body[last_close + 1 :])
    return _last_identifier(suffix)


def _function_pointer_alias(body: str) -> tuple[bool, Optional[str]]:
    """Return ``(handled, alias)`` for a ``(*name)`` declarator.

    ``handled`` is true when a top-level ``(*name)`` is present. ``alias`` is
    ``None`` when that form is malformed or followed by later declarations.
    """
    depth_paren = 0
    depth_brack = 0
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch == "(":
            if depth_paren == 0 and depth_brack == 0:
                match = _FUNC_PTR_NAME.match(body, i)
                if match:
                    rest = body[match.end() :]
                    if not _only_params_or_arrays(rest):
                        return True, None
                    name = match.group(1)
                    if name in _ALIAS_BLOCKLIST:
                        return True, None
                    return True, name
            depth_paren += 1
        elif ch == ")":
            depth_paren -= 1
            if depth_paren < 0:
                return True, None
        elif ch == "[":
            depth_brack += 1
        elif ch == "]":
            depth_brack -= 1
            if depth_brack < 0:
                return True, None
        i += 1
    return False, None


def alias_from_declaration(masked_decl: str) -> Optional[str]:
    """Extract the typedef name from a bounded, masked declaration.

    Function-pointer names come from ``(*name)``. Otherwise the name is the
    identifier after a struct/union/enum body, or the last identifier after
    trailing array bounds. Returns ``None`` when the name cannot be determined.
    """
    text = masked_decl.strip()
    if not text.endswith(";"):
        return None
    body = text[:-1]
    if "{" in body:
        return _alias_after_braces(body)

    handled, fp_name = _function_pointer_alias(body)
    if handled:
        return fp_name
    return _last_identifier(_strip_trailing_arrays(body))


def _line_number(source: str, pos: int) -> int:
    if pos < 0:
        return 1
    if pos >= len(source):
        pos = max(0, len(source) - 1)
    return source.count("\n", 0, pos) + 1


class TypedefScanner:
    """Scanner for typedef statements that create time_t aliases."""

    def __init__(
        self,
        max_hops: int = 5,
        max_aliases: int = 64,
        max_file_size: Optional[int] = None,
    ):
        """
        Initialize the typedef scanner.

        Args:
            max_hops: Maximum number of hops to follow typedef chains
            max_aliases: Maximum number of aliases to discover
            max_file_size: Optional per-file byte limit; larger files are not read
        """
        self.max_hops = max_hops
        self.max_aliases = max_aliases
        self.max_file_size = max_file_size

    def scan_directory(
        self,
        root_path: str,
        include_patterns: List[str],
        exclude_patterns: List[str],
    ) -> Dict[str, Dict[str, List[str]]]:
        """
        Scan directory for typedef statements, grouped by defining file.

        Args:
            root_path: Root directory to scan
            include_patterns: List of glob patterns to include
            exclude_patterns: List of glob patterns to exclude

        Returns:
            Mapping of absolute file path → typedef name → definition strings.
            Definitions are not merged across translation units.
        """
        from tacs.core.path_utils import canonical_source_path

        by_file: Dict[str, Dict[str, List[str]]] = {}

        files = self._get_files(root_path, include_patterns, exclude_patterns)

        for file_path in files:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                abs_path = canonical_source_path(file_path)
                file_typedefs = self._find_typedefs(content, abs_path)
                by_file[abs_path] = file_typedefs

            except Exception as e:
                from tacs.core.status_logger import StatusLogger

                StatusLogger.timestamped_warning(f"Could not read {file_path}: {e}")
                continue

        return by_file

    def _get_files(
        self, root_path: str, include_patterns: List[str], exclude_patterns: List[str]
    ) -> List[Path]:
        """Get unique in-repo source files matching include/exclude patterns."""
        from tacs.core.source_files import enumerate_source_files
        from tacs.core.status_logger import StatusLogger

        enumeration = enumerate_source_files(
            root_path,
            include_patterns,
            exclude_patterns=exclude_patterns,
            max_file_size=self.max_file_size,
        )
        for display in enumeration.skipped_external:
            StatusLogger.timestamped_debug(
                f"Ignoring source symlink outside repository root: {display}"
            )
        return enumeration.files

    def _find_typedefs(self, content: str, file_path: str) -> Dict[str, List[str]]:
        """Find typedef statements in file content."""
        typedefs: Dict[str, List[str]] = defaultdict(list)
        masked = mask_non_code(content)
        search_from = 0
        while True:
            match = _TYPEDEF_KEYWORD.search(masked, search_from)
            if not match:
                break
            start = match.start()
            end = _end_of_declaration(masked, start)
            if end is None:
                # Incomplete or unbalanced: do not consume later declarations.
                search_from = match.end()
                continue
            masked_decl = masked[start : end + 1]
            alias = alias_from_declaration(masked_decl)
            if alias:
                line_num = _line_number(content, start)
                original = content[start : end + 1].strip()
                typedefs[alias].append(f"{file_path}:{line_num}: {original}")
            search_from = end + 1
        return dict(typedefs)

    def find_time_t_aliases(
        self, typedef_map: Dict[str, List[str]], seed_types: Set[str] = None
    ) -> Dict[str, List[str]]:
        """
        Find typedefs that are aliases for time_t or other time-related types.

        A typedef is treated as time-related when its bounded definition text
        contains a seed type as a whole word. That includes return types and
        parameter types of function-pointer typedefs. ``voidFuncPtr`` is
        therefore not promoted; ``typedef time_t (*time_source_fn)(void);`` is.

        Args:
            typedef_map: Dictionary of all typedefs found
            seed_types: Initial set of time-related types to search from

        Returns:
            Dictionary of time-related typedef aliases
        """
        if seed_types is None:
            seed_types = {"time_t", "clock_t", "timer_t", "suseconds_t", "useconds_t"}

        time_aliases = {}
        visited = set()
        current_level = seed_types.copy()

        for hop in range(self.max_hops):
            if not current_level:
                break

            next_level = set()

            for typedef_name in current_level:
                if typedef_name in visited:
                    continue

                visited.add(typedef_name)

                # Look for typedefs that reference this type
                for alias_name, definitions in typedef_map.items():
                    if alias_name in visited:
                        continue

                    for definition in definitions:
                        # Check if this typedef references our current type
                        if self._references_type(definition, typedef_name):
                            time_aliases[alias_name] = definitions
                            next_level.add(alias_name)

            current_level = next_level

            # Check if we've exceeded the alias limit
            if len(time_aliases) >= self.max_aliases:
                from tacs.core.status_logger import StatusLogger

                StatusLogger.timestamped_warning(
                    f"Reached maximum alias limit ({self.max_aliases})"
                )
                break

        return time_aliases

    def _references_type(self, definition: str, type_name: str) -> bool:
        """Check if a typedef definition references a specific type."""
        # More precise check: look for the type name as a whole word
        # This avoids false positives like "time_timestamp" matching "time_t"
        # Extract just the typedef part (after the colon and line number)
        # Format is: "file:line: typedef ..."
        if ":" in definition:
            # Get the typedef part (everything after the second colon)
            parts = definition.split(":", 2)
            if len(parts) >= 3:
                typedef_part = parts[2].strip()
            else:
                typedef_part = definition
        else:
            typedef_part = definition

        # Ignore comments/strings/character literals in the stored definition.
        typedef_part = mask_non_code(typedef_part)
        pattern = r"\b" + re.escape(type_name) + r"\b"
        return bool(re.search(pattern, typedef_part))

    def print_discovered_aliases(self, aliases: Dict[str, List[str]]):
        """Log discovered time_t aliases (DEBUG)."""
        from tacs.core.status_logger import StatusLogger

        if not aliases:
            StatusLogger.timestamped_debug("No time_t aliases discovered")
            return

        StatusLogger.timestamped_debug(f"Discovered {len(aliases)} time_t aliases:")
        for alias_name, definitions in aliases.items():
            StatusLogger.timestamped_debug(
                f"  {alias_name}: {len(definitions)} definition(s)"
            )
