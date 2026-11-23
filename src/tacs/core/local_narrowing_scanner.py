# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Function-local detection of time-derived narrowing conversions.

Bounded lexical analysis only: establish that a local carries time semantics,
compare source and destination representations, recognize explicit or implicit
narrowing, note visible range guards, and emit deterministic candidates.

This is reusable by later caller-to-callee work (issue #57). It does not
perform interprocedural propagation, alias analysis, or symbolic execution.
TACS remains a bounded lexical analyzer, not a complete C or C++ parser.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from tacs.core.function_scanner import ScannedFunction, mask_non_code, scan_functions

# Fixed-width integer types with documented bit widths and signedness.
_FIXED_WIDTH: Dict[str, Tuple[int, str]] = {
    "int8_t": (8, "signed"),
    "uint8_t": (8, "unsigned"),
    "int16_t": (16, "signed"),
    "uint16_t": (16, "unsigned"),
    "int32_t": (32, "signed"),
    "uint32_t": (32, "unsigned"),
    "int64_t": (64, "signed"),
    "uint64_t": (64, "unsigned"),
    "int_least8_t": (8, "signed"),
    "uint_least8_t": (8, "unsigned"),
    "int_least16_t": (16, "signed"),
    "uint_least16_t": (16, "unsigned"),
    "int_least32_t": (32, "signed"),
    "uint_least32_t": (32, "unsigned"),
    "int_least64_t": (64, "signed"),
    "uint_least64_t": (64, "unsigned"),
    "int_fast8_t": (8, "signed"),
    "uint_fast8_t": (8, "unsigned"),
    "int_fast16_t": (16, "signed"),
    "uint_fast16_t": (16, "unsigned"),
    "int_fast32_t": (32, "signed"),
    "uint_fast32_t": (32, "unsigned"),
    "int_fast64_t": (64, "signed"),
    "uint_fast64_t": (64, "unsigned"),
}

# Exact C library / POSIX APIs whose *return value* is Unix-epoch seconds
# (or time_t). Out-parameter clocks such as ``clock_gettime`` / ``gettimeofday``
# are excluded: their return value is a status code, not a timestamp.
# Matched case-sensitively on the final call identifier.
_DEFAULT_TIME_FUNCTIONS = frozenset(
    {
        "time",
        "mktime",
        "timegm",
        "timelocal",
    }
)

# APIs that accept time-related arguments or fill out-params but whose return
# value is a status / pointer / resolution — never treat the call's return
# assignment target as Unix-epoch seconds.
_NON_RETURN_TIME_APIS = frozenset(
    {
        "gmtime",
        "localtime",
        "gmtime_r",
        "localtime_r",
        "clock_gettime",
        "clock_getres",
        "gettimeofday",
        "timespec_get",
        "timespec_getres",
        "strftime",
        "strptime",
    }
)

# Project-local / helper identifiers that convert calendar or named Unix-epoch
# representations into absolute seconds. These are *fullmatch* patterns on the
# call identifier only (case-sensitive). Substring matches are intentionally
# rejected so names like ``make_timeout`` or ``getTimeoutSeconds`` do not seed
# Unix-epoch provenance.
#
# Justification per family:
# - *SecondsUtc / *_seconds_utc: explicit UTC seconds (e.g. uTimeMonthsToSecondsUtc)
# - *SecondsSinceEpoch / *_seconds_since_epoch: explicit epoch offset
# - *UnixTime / *UnixSeconds / get_unix_time / get_unix_seconds: Unix time APIs
# - *ToEpoch* / *EpochSeconds* / *UtcSeconds*: epoch/UTC absolute conversion
# Bare ``*time*`` / ``*seconds*`` / duration / timeout / boot / monotonic names
# are not accepted.
_EPOCH_UTC_PRODUCER_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.ASCII)
    for p in (
        r".*SecondsUtc",
        r".*_seconds_utc",
        r".*ToSecondsUtc",
        r".*_to_seconds_utc",
        r".*SecondsSinceEpoch",
        r"seconds_since_epoch",
        r".*_seconds_since_epoch",
        r".*UnixTime",
        r".*_unix_time",
        r".*UnixSeconds",
        r".*_unix_seconds",
        r"unix_seconds",
        r"unix_time",
        r"get_unix",
        r"get_unix_time",
        r"get_unix_seconds",
        r".*ToUnixTime",
        r".*_to_unix_time",
        r".*ToEpochSeconds",
        r".*_to_epoch_seconds",
        r".*ToEpoch",
        r".*_to_epoch",
        r".*EpochSeconds",
        r"epoch_seconds",
        r".*_epoch_seconds",
        r".*UtcSeconds",
        r"utc_seconds",
        r".*_utc_seconds",
    )
)

# Relative / non-absolute names that must never establish Unix-epoch provenance
# even if they also match a producer pattern (defense in depth).
_NON_EPOCH_REJECT = re.compile(
    r"(?i)"
    r"(?:"
    r"timeout|time_out|"
    r"since_?boot|uptime|"
    r"monotonic|elapsed|duration|interval|delay|sleep|"
    r"processing|relative|"
    r"packet|counter|(?<![A-Za-z])count(?![A-Za-z])|"
    r"deadline|tick(?:s)?(?!_to_)"
    r")",
    re.ASCII,
)

_IDENT = re.compile(r"[A-Za-z_]\w*")
_TYPE_TOKEN = re.compile(
    r"(?:unsigned|signed|long|short|int|char|const|volatile|static|register|"
    r"extern|auto|inline|_Atomic|restrict|"
    r"[A-Za-z_]\w*)"
)

# Explicit cast: (type) expr_start
_EXPLICIT_CAST = re.compile(
    r"\(\s*((?:unsigned\s+|signed\s+)?"
    r"(?:long\s+long|long|short|int|char|"
    r"[A-Za-z_]\w*)"
    r"(?:\s+(?:long|short|int|char))?)\s*\)\s*"
    r"([A-Za-z_]\w*)(?!\s*\()",
    re.ASCII,
)

# Declaration / assignment targets.
_DECL_ASSIGN = re.compile(
    r"(?P<type>(?:(?:unsigned|signed|const|volatile|static|register|extern|auto|"
    r"inline|_Atomic|restrict|long|short|int|char)\s+)*"
    r"[A-Za-z_]\w*(?:\s+(?:long|short|int|char))?)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=\s*(?P<rhs>[^;]+))?;",
    re.ASCII,
)

_SIMPLE_ASSIGN = re.compile(
    r"(?P<lhs>(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*|->[A-Za-z_]\w*)*))\s*"
    r"(?P<op>\+=|-=|=)\s*(?P<rhs>[^;]+);",
    re.ASCII,
)

_FIELD_DECL = re.compile(
    r"(?P<type>(?:(?:unsigned|signed|const|volatile|long|short|int|char)\s+)*"
    r"[A-Za-z_]\w*)\s+(?P<name>[A-Za-z_]\w*)\s*;",
    re.ASCII,
)

# Visible bound checks against INT32 / UINT32 limits or numeric 32-bit extremes.
_BOUND_COMPARE = re.compile(
    r"\b(?P<var>[A-Za-z_]\w*)\s*(?P<op><=|>=|<|>)\s*"
    r"(?P<bound>INT32_MIN|INT32_MAX|UINT32_MAX|INT_MIN|INT_MAX|"
    r"-?214748364[0-8]|429496729[0-5]|0x[0-9a-fA-F]+)",
    re.ASCII,
)

_CALENDAR_SECONDS = re.compile(
    r"(?:3600\s*\*\s*24|24\s*\*\s*3600|86400|3600|60)\b"
)


@dataclass
class TypeRepr:
    """Source-supported integer representation."""

    type_name: str
    bits: Optional[int]
    signedness: Optional[str]  # "signed" | "unsigned" | None
    known: bool


@dataclass
class TimeLocal:
    """A function-local value known to carry time semantics."""

    name: str
    type_repr: TypeRepr
    provenance: str
    decl_line: Optional[int] = None


@dataclass
class NarrowingMatch:
    """One function-local time-derived narrowing site."""

    file_path: str
    line_number: int
    col_start: int
    col_end: int
    full_line: str
    symbol: str
    risk: str
    description: str
    source_var: str
    source_type: str
    source_bits: Optional[int]
    source_signedness: Optional[str]
    dest_type: str
    dest_bits: Optional[int]
    dest_signedness: Optional[str]
    destination: str
    provenance: str
    guarded: bool
    guard_evidence: str = ""
    conversion_kind: str = "width_reduction"  # width_reduction|signedness_change|both|unknown
    unresolved: List[str] = field(default_factory=list)


def _normalize_type(raw: str) -> str:
    parts = [p for p in re.split(r"\s+", raw.strip()) if p]
    # Drop storage / cv qualifiers that are not part of the integer type.
    drop = {
        "const",
        "volatile",
        "static",
        "register",
        "extern",
        "auto",
        "inline",
        "_Atomic",
        "restrict",
    }
    kept = [p for p in parts if p not in drop]
    return " ".join(kept) if kept else raw.strip()


def resolve_type_repr(
    type_name: str,
    *,
    environment_config: Optional[Dict[str, Any]] = None,
    time_t_aliases: Optional[Iterable[str]] = None,
) -> TypeRepr:
    """Resolve a C type to width/signedness using fixed-width types or env config."""
    name = _normalize_type(type_name)
    aliases = set(time_t_aliases or ())
    env = environment_config or {}
    hw = str(env.get("hardware_model") or "").upper()
    time_bits = env.get("time_t_size_bits")
    time_signed = env.get("time_t_signed")

    if name in _FIXED_WIDTH:
        bits, signedness = _FIXED_WIDTH[name]
        return TypeRepr(name, bits, signedness, True)

    if name in {"time_t"} or name in aliases:
        bits = int(time_bits) if time_bits in (32, 64) else None
        signedness = (
            str(time_signed)
            if time_signed in ("signed", "unsigned")
            else "signed"
        )
        return TypeRepr(name, bits, signedness, bits is not None)

    if name in {"int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64"}:
        # Non-standard aliases sometimes appear in embedded code.
        mapping = {
            "int8": (8, "signed"),
            "uint8": (8, "unsigned"),
            "int16": (16, "signed"),
            "uint16": (16, "unsigned"),
            "int32": (32, "signed"),
            "uint32": (32, "unsigned"),
            "int64": (64, "signed"),
            "uint64": (64, "unsigned"),
        }
        bits, signedness = mapping[name]
        return TypeRepr(name, bits, signedness, True)

    # Implementation-defined types: use selected target ABI when available.
    if name == "char":
        return TypeRepr(name, 8, None, False)
    if name in {"signed char"}:
        return TypeRepr(name, 8, "signed", True)
    if name in {"unsigned char"}:
        return TypeRepr(name, 8, "unsigned", True)
    if name in {"short", "short int", "signed short", "signed short int"}:
        return TypeRepr(name, 16, "signed", True)
    if name in {"unsigned short", "unsigned short int"}:
        return TypeRepr(name, 16, "unsigned", True)
    if name in {"int", "signed", "signed int"}:
        return TypeRepr(name, 32, "signed", True)
    if name in {"unsigned", "unsigned int"}:
        return TypeRepr(name, 32, "unsigned", True)
    if name in {"long", "long int", "signed long", "signed long int"}:
        if hw == "ILP32":
            return TypeRepr(name, 32, "signed", True)
        if hw == "LP64":
            return TypeRepr(name, 64, "signed", True)
        return TypeRepr(name, None, "signed", False)
    if name in {"unsigned long", "unsigned long int"}:
        if hw == "ILP32":
            return TypeRepr(name, 32, "unsigned", True)
        if hw == "LP64":
            return TypeRepr(name, 64, "unsigned", True)
        return TypeRepr(name, None, "unsigned", False)
    if name in {"long long", "long long int", "signed long long", "signed long long int"}:
        return TypeRepr(name, 64, "signed", True)
    if name in {"unsigned long long", "unsigned long long int"}:
        return TypeRepr(name, 64, "unsigned", True)

    return TypeRepr(name, None, None, False)


def classify_conversion(source: TypeRepr, dest: TypeRepr) -> Tuple[str, List[str]]:
    """Return conversion_kind and unresolved assumptions."""
    unresolved: List[str] = []
    if source.bits is None:
        unresolved.append(f"unknown source width for {source.type_name}")
    if dest.bits is None:
        unresolved.append(f"unknown destination width for {dest.type_name}")

    width_reduced = (
        source.bits is not None
        and dest.bits is not None
        and dest.bits < source.bits
    )
    signedness_changed = (
        source.signedness is not None
        and dest.signedness is not None
        and source.signedness != dest.signedness
    )

    if width_reduced and signedness_changed:
        return "both", unresolved
    if width_reduced:
        return "width_reduction", unresolved
    if signedness_changed and source.bits is not None and dest.bits == source.bits:
        return "signedness_change", unresolved
    if unresolved:
        return "unknown", unresolved
    return "unknown", unresolved


def _call_names(expr: str) -> List[str]:
    return re.findall(r"\b([A-Za-z_]\w*)\s*\(", expr)


def _is_time_producing_call(name: str, time_functions: Set[str]) -> bool:
    """True when ``name`` is a Unix-epoch / absolute-time producing call.

    Exact catalog/stdlib names win first. Otherwise the identifier must
    *fullmatch* a bounded epoch/UTC producer pattern and must not match the
    non-epoch reject list. Identifier names alone on variables are never used
    here; this predicate is only for call expressions.
    """
    if not name:
        return False
    # Use the final qualification segment: ``ns::foo`` / ``Type::foo``.
    simple = name.rsplit("::", 1)[-1]
    simple = simple.rsplit(".", 1)[-1]
    if simple in _NON_RETURN_TIME_APIS:
        return False
    if _NON_EPOCH_REJECT.search(simple):
        return False
    if simple in _DEFAULT_TIME_FUNCTIONS:
        return True
    # Catalog-supplied names are accepted only when they are known return-value
    # epoch producers (same allowlist). Broader catalog symbols such as sleep
    # helpers must not seed absolute-time provenance.
    if simple in time_functions and simple in _DEFAULT_TIME_FUNCTIONS:
        return True
    return any(pat.fullmatch(simple) for pat in _EPOCH_UTC_PRODUCER_PATTERNS)


def _rhs_has_time_call(rhs: str, time_functions: Set[str]) -> Optional[str]:
    for name in _call_names(rhs):
        if _is_time_producing_call(name, time_functions):
            return name
    return None


def _rhs_refs_time_local(rhs: str, time_locals: Dict[str, TimeLocal]) -> Optional[str]:
    # Prefer longer names to avoid partial matches; require whole identifiers.
    for name in sorted(time_locals.keys(), key=len, reverse=True):
        if re.search(rf"\b{re.escape(name)}\b", rhs):
            # Skip if it is only the function name of a call we already handle.
            return name
    return None


def _looks_like_calendar_epoch_rhs(rhs: str) -> bool:
    """Heuristic for calendar fields folded into Unix seconds (no name inference)."""
    if not _CALENDAR_SECONDS.search(rhs):
        return False
    # Require an arithmetic combine, not a lone constant.
    return any(op in rhs for op in ("+", "-", "*", "/"))


class LocalNarrowingScanner:
    """Scan function bodies for time-derived narrowing conversions."""

    def __init__(
        self,
        *,
        time_t_aliases: Optional[Iterable[str]] = None,
        time_functions: Optional[Iterable[str]] = None,
        environment_config: Optional[Dict[str, Any]] = None,
    ):
        self.time_t_aliases = set(time_t_aliases or ())
        self.time_functions = set(time_functions or ()) | set(_DEFAULT_TIME_FUNCTIONS)
        self.environment_config = environment_config or {}
        self._time_types = {"time_t"} | self.time_t_aliases

    def scan_source(self, source: str, file_path: str) -> List[NarrowingMatch]:
        if not source:
            return []
        functions = scan_functions(source)
        if not functions:
            return []
        lines = source.splitlines(keepends=True)
        # 0-based offsets for line starts in original source.
        line_starts = [0]
        for line in lines:
            line_starts.append(line_starts[-1] + len(line))
        matches: List[NarrowingMatch] = []
        for fn in functions:
            matches.extend(
                self._scan_function(source, lines, line_starts, file_path, fn)
            )
        matches.sort(
            key=lambda m: (m.file_path, m.line_number, m.col_start, m.symbol)
        )
        return matches

    def _scan_function(
        self,
        source: str,
        lines: List[str],
        line_starts: List[int],
        file_path: str,
        fn: ScannedFunction,
    ) -> List[NarrowingMatch]:
        start_idx = max(0, fn.start_line - 1)
        end_idx = min(len(lines), fn.end_line)
        body_lines = lines[start_idx:end_idx]
        body_text = "".join(body_lines)
        masked_body = mask_non_code(body_text)

        time_locals: Dict[str, TimeLocal] = {}
        # Track declared types for locals (even non-time) for dest width.
        local_types: Dict[str, TypeRepr] = {}
        # Struct/union field types declared in this function's nested scopes.
        field_types: Dict[str, TypeRepr] = {}
        guards: Dict[str, List[str]] = {}

        # First pass: declarations, assignments, provenance, guards.
        offset = 0
        for rel_i, raw_line in enumerate(body_lines):
            abs_line = start_idx + rel_i + 1
            masked_line = masked_body[offset : offset + len(raw_line)]
            offset += len(raw_line)
            self._ingest_line(
                masked_line,
                abs_line,
                time_locals,
                local_types,
                field_types,
                guards,
            )

        # Second pass: narrowing sites.
        matches: List[NarrowingMatch] = []
        offset = 0
        for rel_i, raw_line in enumerate(body_lines):
            abs_line = start_idx + rel_i + 1
            masked_line = masked_body[offset : offset + len(raw_line)]
            line_abs_start = line_starts[abs_line - 1] if abs_line - 1 < len(line_starts) else 0
            offset += len(raw_line)
            matches.extend(
                self._find_narrowing_on_line(
                    raw_line=raw_line,
                    masked_line=masked_line,
                    file_path=file_path,
                    line_number=abs_line,
                    line_abs_start=line_abs_start,
                    time_locals=time_locals,
                    local_types=local_types,
                    field_types=field_types,
                    guards=guards,
                )
            )
        return matches

    def _ingest_line(
        self,
        masked_line: str,
        line_number: int,
        time_locals: Dict[str, TimeLocal],
        local_types: Dict[str, TypeRepr],
        field_types: Dict[str, TypeRepr],
        guards: Dict[str, List[str]],
    ) -> None:
        cleaned = masked_line.strip()
        if not cleaned:
            return

        for match in _BOUND_COMPARE.finditer(masked_line):
            var = match.group("var")
            guards.setdefault(var, []).append(match.group(0).strip())

        # Declarations with optional initializer.
        for match in _DECL_ASSIGN.finditer(masked_line):
            type_name = _normalize_type(match.group("type"))
            var_name = match.group("name")
            rhs = (match.group("rhs") or "").strip()
            # Skip if this looks like a function definition/call residue.
            if var_name in {"if", "for", "while", "switch", "return"}:
                continue
            trepr = resolve_type_repr(
                type_name,
                environment_config=self.environment_config,
                time_t_aliases=self.time_t_aliases,
            )
            local_types[var_name] = trepr
            if type_name in self._time_types:
                time_locals[var_name] = TimeLocal(
                    name=var_name,
                    type_repr=trepr,
                    provenance=f"declared as {type_name}",
                    decl_line=line_number,
                )
            if rhs:
                self._maybe_mark_from_rhs(
                    var_name, trepr, rhs, line_number, time_locals
                )

        # Simple / compound assignments (including field stores).
        for match in _SIMPLE_ASSIGN.finditer(masked_line):
            lhs = match.group("lhs")
            op = match.group("op")
            rhs = match.group("rhs").strip()
            base = lhs.split(".", 1)[0].split("->", 1)[0]
            trepr = local_types.get(base) or (
                time_locals[base].type_repr if base in time_locals else None
            )
            if trepr is None and re.fullmatch(r"[A-Za-z_]\w*", lhs):
                trepr = TypeRepr("unknown", None, None, False)
            if trepr is None:
                continue

            if op in {"+=", "-="}:
                # Compound update can seed or strengthen time provenance.
                call = _rhs_has_time_call(rhs, self.time_functions)
                if call:
                    prior = time_locals.get(base)
                    provenance = (
                        f"accumulated from Unix-epoch/absolute-time call {call}()"
                    )
                    if prior:
                        provenance = f"{prior.provenance}; {provenance}"
                    time_locals[base] = TimeLocal(
                        name=base,
                        type_repr=trepr if trepr.known else (
                            prior.type_repr if prior else trepr
                        ),
                        provenance=provenance,
                        decl_line=prior.decl_line if prior else line_number,
                    )
                elif base in time_locals and _looks_like_calendar_epoch_rhs(rhs):
                    existing = time_locals[base]
                    time_locals[base] = TimeLocal(
                        name=base,
                        type_repr=existing.type_repr,
                        provenance=(
                            f"{existing.provenance}; calendar/epoch accumulation"
                        ),
                        decl_line=existing.decl_line or line_number,
                    )
                continue

            self._maybe_mark_from_rhs(
                base, trepr, rhs, line_number, time_locals
            )

        # Nested struct/union field declarations (including one-line structs).
        for match in _FIELD_DECL.finditer(masked_line):
            type_name = _normalize_type(match.group("type"))
            field_name = match.group("name")
            # Skip storage declarations that are plain locals already handled.
            # Field names inside struct/union bodies are still useful.
            if type_name in self._time_types or type_name in _FIXED_WIDTH:
                field_types[field_name] = resolve_type_repr(
                    type_name,
                    environment_config=self.environment_config,
                    time_t_aliases=self.time_t_aliases,
                )

    def _maybe_mark_from_rhs(
        self,
        var_name: str,
        trepr: TypeRepr,
        rhs: str,
        line_number: int,
        time_locals: Dict[str, TimeLocal],
    ) -> None:
        call = _rhs_has_time_call(rhs, self.time_functions)
        if call:
            time_locals[var_name] = TimeLocal(
                name=var_name,
                type_repr=trepr,
                provenance=(
                    f"assigned from Unix-epoch/absolute-time call {call}()"
                ),
                decl_line=line_number,
            )
            return
        ref = _rhs_refs_time_local(rhs, time_locals)
        if ref:
            parent = time_locals[ref]
            time_locals[var_name] = TimeLocal(
                name=var_name,
                type_repr=trepr if trepr.known else parent.type_repr,
                provenance=f"assigned from time-derived {ref} ({parent.provenance})",
                decl_line=line_number,
            )
            return
        # Cast of a time-derived value in the RHS.
        for cast in _EXPLICIT_CAST.finditer(rhs):
            src = cast.group(2)
            if src in time_locals:
                parent = time_locals[src]
                time_locals[var_name] = TimeLocal(
                    name=var_name,
                    type_repr=trepr if trepr.known else parent.type_repr,
                    provenance=(
                        f"assigned from cast of time-derived {src} "
                        f"({parent.provenance})"
                    ),
                    decl_line=line_number,
                )
                return
        # Calendar/epoch construction only strengthens an already time-bearing
        # local (e.g. after SecondsUtc seed). Alone it is not enough: many
        # non-time counters also multiply by 60/3600.
        if var_name in time_locals and _looks_like_calendar_epoch_rhs(rhs):
            existing = time_locals[var_name]
            time_locals[var_name] = TimeLocal(
                name=var_name,
                type_repr=existing.type_repr,
                provenance=f"{existing.provenance}; calendar/epoch accumulation",
                decl_line=existing.decl_line or line_number,
            )

    def _find_narrowing_on_line(
        self,
        *,
        raw_line: str,
        masked_line: str,
        file_path: str,
        line_number: int,
        line_abs_start: int,
        time_locals: Dict[str, TimeLocal],
        local_types: Dict[str, TypeRepr],
        field_types: Dict[str, TypeRepr],
        guards: Dict[str, List[str]],
    ) -> List[NarrowingMatch]:
        out: List[NarrowingMatch] = []
        snippet = raw_line.rstrip("\n")

        # Explicit casts of time-derived locals.
        for match in _EXPLICIT_CAST.finditer(masked_line):
            dest_type = _normalize_type(match.group(1))
            src_name = match.group(2)
            if src_name not in time_locals:
                continue
            if dest_type in self._time_types:
                continue
            if dest_type in {"void", "const", "volatile"}:
                continue
            src = time_locals[src_name]
            dest = resolve_type_repr(
                dest_type,
                environment_config=self.environment_config,
                time_t_aliases=self.time_t_aliases,
            )
            kind, unresolved = classify_conversion(src.type_repr, dest)
            if kind == "unknown" and not (
                src.type_repr.bits is not None
                and dest.bits is not None
                and dest.bits < src.type_repr.bits
            ):
                # Fail closed when we cannot establish narrowing/signedness change.
                if kind != "signedness_change":
                    continue
            if kind == "unknown":
                continue
            guarded, guard_ev = self._guard_info(src_name, guards)
            risk = "medium" if guarded else "high"
            col_start = match.start(1)  # start of type inside parens-ish; use cast start
            col_start = match.start()
            col_end = match.end()
            dest_desc = f"explicit cast to {dest.type_name}"
            description = self._build_description(
                src=src,
                dest=dest,
                kind=kind,
                destination=dest_desc,
                guarded=guarded,
                guard_evidence=guard_ev,
                unresolved=unresolved,
            )
            out.append(
                NarrowingMatch(
                    file_path=file_path,
                    line_number=line_number,
                    col_start=col_start,
                    col_end=col_end,
                    full_line=snippet,
                    symbol="cast_from_time_var",
                    risk=risk,
                    description=description,
                    source_var=src_name,
                    source_type=src.type_repr.type_name,
                    source_bits=src.type_repr.bits,
                    source_signedness=src.type_repr.signedness,
                    dest_type=dest.type_name,
                    dest_bits=dest.bits,
                    dest_signedness=dest.signedness,
                    destination=dest_desc,
                    provenance=src.provenance,
                    guarded=guarded,
                    guard_evidence=guard_ev,
                    conversion_kind=kind,
                    unresolved=unresolved,
                )
            )

        # Implicit assignment / init to a narrower local or field.
        for match in _DECL_ASSIGN.finditer(masked_line):
            dest_type_name = _normalize_type(match.group("type"))
            dest_name = match.group("name")
            rhs = (match.group("rhs") or "").strip()
            if not rhs:
                continue
            # ``T x = (U)time_var;`` is covered by the explicit-cast emitter.
            if _EXPLICIT_CAST.fullmatch(rhs):
                continue
            src_name = None
            m_id = re.fullmatch(r"([A-Za-z_]\w*)", rhs)
            if m_id and m_id.group(1) in time_locals:
                src_name = m_id.group(1)
            else:
                continue
            if dest_type_name in self._time_types:
                continue
            src = time_locals[src_name]
            dest = resolve_type_repr(
                dest_type_name,
                environment_config=self.environment_config,
                time_t_aliases=self.time_t_aliases,
            )
            kind, unresolved = classify_conversion(src.type_repr, dest)
            if kind not in {"width_reduction", "both", "signedness_change"}:
                continue
            if kind == "signedness_change" and (
                src.type_repr.bits is None or dest.bits is None
            ):
                continue
            guarded, guard_ev = self._guard_info(src_name, guards)
            risk = "medium" if guarded else "high"
            description = self._build_description(
                src=src,
                dest=dest,
                kind=kind,
                destination=f"implicit assignment to {dest_type_name} {dest_name}",
                guarded=guarded,
                guard_evidence=guard_ev,
                unresolved=unresolved,
            )
            out.append(
                NarrowingMatch(
                    file_path=file_path,
                    line_number=line_number,
                    col_start=match.start(),
                    col_end=match.end(),
                    full_line=snippet,
                    symbol="implicit_cast_from_time",
                    risk=risk,
                    description=description,
                    source_var=src_name,
                    source_type=src.type_repr.type_name,
                    source_bits=src.type_repr.bits,
                    source_signedness=src.type_repr.signedness,
                    dest_type=dest.type_name,
                    dest_bits=dest.bits,
                    dest_signedness=dest.signedness,
                    destination=f"{dest_type_name} {dest_name}",
                    provenance=src.provenance,
                    guarded=guarded,
                    guard_evidence=guard_ev,
                    conversion_kind=kind,
                    unresolved=unresolved,
                )
            )

        for match in _SIMPLE_ASSIGN.finditer(masked_line):
            lhs = match.group("lhs")
            op = match.group("op")
            if op != "=":
                continue
            # Skip declaration-initializers already handled by _DECL_ASSIGN
            # (e.g. ``int32_t narrow = now;`` also matches ``narrow = now``).
            prefix = masked_line[: match.start()].rstrip()
            if prefix and not prefix.endswith(";") and not prefix.endswith("{"):
                continue
            rhs = match.group("rhs").strip()
            if _EXPLICIT_CAST.fullmatch(rhs):
                continue
            src_name = None
            m_id = re.fullmatch(r"([A-Za-z_]\w*)", rhs)
            if m_id and m_id.group(1) in time_locals:
                src_name = m_id.group(1)
            else:
                continue
            # Destination must be a narrower typed field or local.
            dest_repr: Optional[TypeRepr] = None
            dest_label = lhs
            if "." in lhs or "->" in lhs:
                field = lhs.replace("->", ".").split(".")[-1]
                dest_repr = field_types.get(field) or local_types.get(field)
                dest_label = f"field {lhs}"
            else:
                dest_repr = local_types.get(lhs)
                dest_label = f"variable {lhs}"
            if dest_repr is None or not dest_repr.known:
                continue
            src = time_locals[src_name]
            kind, unresolved = classify_conversion(src.type_repr, dest_repr)
            if kind not in {"width_reduction", "both", "signedness_change"}:
                continue
            guarded, guard_ev = self._guard_info(src_name, guards)
            risk = "medium" if guarded else "high"
            description = self._build_description(
                src=src,
                dest=dest_repr,
                kind=kind,
                destination=f"implicit assignment to {dest_label}",
                guarded=guarded,
                guard_evidence=guard_ev,
                unresolved=unresolved,
            )
            out.append(
                NarrowingMatch(
                    file_path=file_path,
                    line_number=line_number,
                    col_start=match.start(),
                    col_end=match.end(),
                    full_line=snippet,
                    symbol="implicit_cast_from_time",
                    risk=risk,
                    description=description,
                    source_var=src_name,
                    source_type=src.type_repr.type_name,
                    source_bits=src.type_repr.bits,
                    source_signedness=src.type_repr.signedness,
                    dest_type=dest_repr.type_name,
                    dest_bits=dest_repr.bits,
                    dest_signedness=dest_repr.signedness,
                    destination=dest_label,
                    provenance=src.provenance,
                    guarded=guarded,
                    guard_evidence=guard_ev,
                    conversion_kind=kind,
                    unresolved=unresolved,
                )
            )
        return out

    @staticmethod
    def _guard_info(
        var_name: str, guards: Dict[str, List[str]]
    ) -> Tuple[bool, str]:
        evidence = guards.get(var_name) or []
        if not evidence:
            return False, ""
        joined = "; ".join(evidence)
        has_upper = any(
            re.search(
                r"(?:MAX|2147483647|0x7fffffff|4294967295)", e, re.IGNORECASE
            )
            for e in evidence
        )
        has_lower = any(
            re.search(r"(?:MIN|-2147483648)", e, re.IGNORECASE) for e in evidence
        )
        if has_upper and has_lower:
            return True, joined
        # One-sided / insufficient: record evidence but do not treat as guarded.
        return False, f"insufficient/one-sided: {joined}"

    @staticmethod
    def _build_description(
        *,
        src: TimeLocal,
        dest: TypeRepr,
        kind: str,
        destination: str,
        guarded: bool,
        guard_evidence: str,
        unresolved: Sequence[str],
    ) -> str:
        src_bits = (
            f"{src.type_repr.bits}-bit" if src.type_repr.bits is not None else "unknown-width"
        )
        dest_bits = f"{dest.bits}-bit" if dest.bits is not None else "unknown-width"
        parts = [
            "Potential time-representation narrowing: "
            f"time-derived {src_bits} {src.type_repr.type_name} '{src.name}' "
            f"({src.provenance}) converted via {destination} "
            f"to {dest_bits} {dest.type_name} ({kind}). "
            "May produce an incorrect value after the signed 32-bit Unix-time "
            "boundary; review candidate, not a confirmed defect."
        ]
        if guarded:
            parts.append(f" Visible range check present ({guard_evidence}).")
        elif guard_evidence:
            parts.append(f" Partial range evidence ({guard_evidence}).")
        if unresolved:
            parts.append(" Unresolved: " + "; ".join(unresolved) + ".")
        return "".join(parts)


def narrowing_matches_to_candidates(
    matches: Sequence[NarrowingMatch],
) -> List["Candidate"]:
    """Convert narrowing matches to public Candidate objects."""
    from tacs.core.path_utils import canonical_source_path
    from tacs.core.schema import Candidate

    candidates: List[Candidate] = []
    for match in matches:
        candidates.append(
            Candidate(
                file=canonical_source_path(match.file_path),
                line=match.line_number,
                symbol=match.symbol,
                one_line_snippet=match.full_line,
                risk=match.risk,
                description=match.description,
                col_start=match.col_start,
                col_end=match.col_end,
                discovery_method="time_t_cast",
                rule_id=None,
            )
        )
    return candidates
