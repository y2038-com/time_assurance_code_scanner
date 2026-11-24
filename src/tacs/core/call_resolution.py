# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Conservative call-target resolution for one-hop time propagation (#57).

Only ``resolved`` targets may propagate. Unique project-wide names alone are
never sufficient without a visible compatible declaration (basis B). Cross-file
``static`` definitions are never linked. Preprocessor-condition mismatches and
function-pointer / name shadowing fail closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple

from tacs.core.alias_scope import include_closure
from tacs.core.call_site_index import CallSite
from tacs.core.preprocessor_conditions import (
    build_condition_stack_cache,
    condition_stack_at_line,
    conditions_compatible,
    stack_at_cached,
)
from tacs.core.schema import CallResolutionBasis, CallResolutionState
from tacs.core.source_index import IndexedFunction, SourceIndex

#: Maximum ambiguous targets retained for diagnostics (not used for propagation).
MAX_AMBIGUOUS_TARGETS = 8

_FP_DECL = re.compile(
    r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)",
    re.ASCII,
)
# Local / file-scope variable declarations only — never ``name(`` (calls).
_LOCAL_DECL = re.compile(
    r"(?:^|[;{}\n])\s*(?:(?:const|volatile|static|extern|register|auto|typedef)\s+)*"
    r"(?:struct\s+|enum\s+|union\s+)?"
    r"(?P<type>[A-Za-z_]\w*(?:\s*\*|\s+)+)"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:[=\[;,])",
    re.ASCII,
)


@dataclass(frozen=True)
class ResolvedCall:
    """Resolution result for one call site."""

    site: CallSite
    state: CallResolutionState
    basis: Optional[CallResolutionBasis]
    callees: Tuple[IndexedFunction, ...]
    stop_reasons: Tuple[str, ...]


def _arity_compatible(site: CallSite, fn: IndexedFunction) -> bool:
    if fn.is_variadic:
        return site.argument_count >= fn.arity
    return site.argument_count == fn.arity


def _simple_symbol(symbol: str) -> str:
    # Prefer IndexedFunction.simple_symbol when available; this helper remains
    # for raw strings and CallSite.simple_name comparisons.
    return symbol.rsplit("::", 1)[-1] if "::" in symbol else symbol


def _normalize_type(text: str) -> str:
    return " ".join((text or "").replace("*", " * ").split())


def _param_types_compatible(decl: IndexedFunction, target: IndexedFunction) -> bool:
    """Fail closed: require equal arity and matching normalized type text.

    Pointer/reference presence must agree. Distinct fixed-width spellings
    (e.g. ``int32_t`` vs ``int64_t``) are incompatible.
    """
    if decl.arity != target.arity:
        return False
    if not decl.parameters and not target.parameters:
        return True
    if len(decl.parameters) != len(target.parameters):
        return False
    for a, b in zip(decl.parameters, target.parameters):
        if a.is_pointer != b.is_pointer or a.is_reference != b.is_reference:
            return False
        if a.is_array != b.is_array:
            return False
        na, nb = _normalize_type(a.declared_type), _normalize_type(b.declared_type)
        if na != nb:
            return False
    return True


def _line_text_before(source: str, line: int) -> str:
    if not source or line < 1:
        return ""
    lines = source.splitlines(keepends=True)
    end = min(len(lines), max(0, line - 1))
    return "".join(lines[:end])


def caller_shadows_as_non_function(
    source: str,
    caller: IndexedFunction,
    name: str,
    call_line: int,
) -> Optional[str]:
    """Return a stop reason when ``name`` is shadowed in the caller scope.

    Detects function-pointer parameters/locals and ordinary locals/parameters
    that would make ``name(...)`` an indirect or non-direct-function call.
    Does not perform pointer-target analysis.
    """
    if not name:
        return None
    # Parameters of the caller with this name shadow an outer function.
    for param in caller.parameters:
        if param.name == name:
            if param.is_pointer or param.is_reference or param.is_array:
                return "indirect_call"
            # Non-pointer parameter of the same name: calling it is not a
            # direct project function (compile error or FP via typedef).
            return "indirect_call"

    prefix = _line_text_before(source, call_line)
    # Restrict to the caller's body when possible.
    body_start = None
    lines = source.splitlines(keepends=True)
    start_idx = max(0, caller.start_line - 1)
    span = "".join(lines[start_idx : min(len(lines), caller.end_line)])
    brace = span.find("{")
    if brace >= 0:
        abs_body = sum(len(lines[i]) for i in range(start_idx)) + brace + 1
        # Character offset of call_line start.
        call_abs = sum(len(lines[i]) for i in range(min(len(lines), call_line - 1)))
        if call_abs > abs_body:
            prefix = source[abs_body:call_abs]

    for match in _FP_DECL.finditer(prefix):
        if match.group("name") == name:
            return "indirect_call"

    for match in _LOCAL_DECL.finditer(prefix):
        if match.group("name") == name:
            # typedef void (*name)(...) is also caught via FP_DECL usually;
            # any local with this name shadows a direct function call.
            return "indirect_call"
    return None


def resolve_same_file_static(site: CallSite, index: SourceIndex) -> Optional[ResolvedCall]:
    """Basis A: unique same-file ``static`` definition with matching arity."""
    if site.call_form != "direct_id":
        return None
    name = site.simple_name
    same_file = [
        fn
        for fn in index.definitions_by_file.get(site.caller.file_abs, ())
        if fn.simple_symbol == name and fn.is_definition and fn.is_static
    ]
    if not same_file:
        return None
    compatible = [fn for fn in same_file if _arity_compatible(site, fn)]
    if len(compatible) == 1 and not compatible[0].is_variadic:
        target = compatible[0]
        if site.argument_count > 0 and not target.parameters:
            return ResolvedCall(
                site=site,
                state=CallResolutionState.UNRESOLVED,
                basis=None,
                callees=(),
                stop_reasons=("unsupported_parameter_form",),
            )
        return ResolvedCall(
            site=site,
            state=CallResolutionState.RESOLVED,
            basis=CallResolutionBasis.SAME_FILE_STATIC,
            callees=(target,),
            stop_reasons=(),
        )
    if len(same_file) > 1 or len(compatible) > 1:
        kept = tuple(compatible[:MAX_AMBIGUOUS_TARGETS] or same_file[:MAX_AMBIGUOUS_TARGETS])
        reasons = (
            ("ambiguous_target_limit",)
            if len(compatible) > MAX_AMBIGUOUS_TARGETS or len(same_file) > MAX_AMBIGUOUS_TARGETS
            else ()
        )
        return ResolvedCall(
            site=site,
            state=CallResolutionState.AMBIGUOUS,
            basis=None,
            callees=kept,
            stop_reasons=tuple(reasons),
        )
    if compatible and compatible[0].is_variadic:
        return ResolvedCall(
            site=site,
            state=CallResolutionState.UNRESOLVED,
            basis=None,
            callees=tuple(compatible),
            stop_reasons=("variadic_parameter",),
        )
    if same_file and not compatible:
        return ResolvedCall(
            site=site,
            state=CallResolutionState.UNRESOLVED,
            basis=None,
            callees=tuple(same_file[:MAX_AMBIGUOUS_TARGETS]),
            stop_reasons=("arity_mismatch",),
        )
    return None


def _visible_declarations_for_name(
    caller_abs: str,
    name: str,
    index: SourceIndex,
    adjacency: Mapping[str, Set[str]],
) -> List[IndexedFunction]:
    closure = include_closure(caller_abs, adjacency)
    visible: List[IndexedFunction] = []
    for decl in index.declarations_by_simple_name.get(name, ()):
        # Never treat a foreign-file static as a visible linkage declaration.
        if decl.is_static and decl.file_abs != caller_abs:
            continue
        if decl.file_abs in closure or decl.file_abs == caller_abs:
            visible.append(decl)
    for fn in index.definitions_by_simple_name.get(name, ()):
        # Cross-file static definitions are never visible linkage for basis B.
        if fn.is_static and fn.file_abs != caller_abs:
            continue
        if fn.file_abs in closure or fn.file_abs == caller_abs:
            visible.append(fn)
    return visible


def resolve_visible_cross_file(
    site: CallSite,
    index: SourceIndex,
    adjacency: Mapping[str, Set[str]],
) -> Optional[ResolvedCall]:
    """Basis B: unique project definition + visible compatible declaration."""
    if site.call_form != "direct_id":
        return None
    name = site.simple_name
    # Never select a static definition from any file for basis B.
    defs = [
        fn
        for fn in index.definitions_named(name)
        if fn.is_definition and not fn.is_static
    ]
    uniq: Dict[str, IndexedFunction] = {fn.internal_id: fn for fn in defs}
    defs = list(uniq.values())

    # If the only project definitions are static (possibly other files), this
    # is external / unresolved for cross-file purposes — never link them.
    if not defs:
        static_only = [
            fn
            for fn in index.definitions_named(name)
            if fn.is_definition
            and fn.is_static
            and fn.file_abs != site.caller.file_abs
        ]
        if static_only:
            return ResolvedCall(
                site=site,
                state=CallResolutionState.UNRESOLVED,
                basis=None,
                callees=(),
                stop_reasons=("unresolved_target",),
            )
        return ResolvedCall(
            site=site,
            state=CallResolutionState.EXTERNAL,
            basis=None,
            callees=(),
            stop_reasons=("external_target",),
        )

    compatible_defs = [fn for fn in defs if _arity_compatible(site, fn) and not fn.is_variadic]
    if len(compatible_defs) != 1:
        if len(defs) > 1:
            return ResolvedCall(
                site=site,
                state=CallResolutionState.AMBIGUOUS,
                basis=None,
                callees=tuple(defs[:MAX_AMBIGUOUS_TARGETS]),
                stop_reasons=(
                    ("ambiguous_target_limit",)
                    if len(defs) > MAX_AMBIGUOUS_TARGETS
                    else ()
                ),
            )
        if defs and not compatible_defs:
            return ResolvedCall(
                site=site,
                state=CallResolutionState.UNRESOLVED,
                basis=None,
                callees=tuple(defs[:MAX_AMBIGUOUS_TARGETS]),
                stop_reasons=("arity_mismatch",),
            )
        return None

    target = compatible_defs[0]
    if target.is_static:
        # Defensive: static must never be a basis-B target.
        return ResolvedCall(
            site=site,
            state=CallResolutionState.UNRESOLVED,
            basis=None,
            callees=(),
            stop_reasons=("unresolved_target",),
        )
    if not target.parameters and site.argument_count > 0:
        return ResolvedCall(
            site=site,
            state=CallResolutionState.UNRESOLVED,
            basis=None,
            callees=(target,),
            stop_reasons=("unsupported_parameter_form",),
        )

    visible = _visible_declarations_for_name(
        site.caller.file_abs, name, index, adjacency
    )
    compatible_visible = [
        d
        for d in visible
        if d.arity == target.arity
        and not d.is_variadic
        and _param_types_compatible(d, target)
    ]
    if not compatible_visible:
        # Unique project-wide name alone is insufficient; also covers
        # arity-matched but type-incompatible visible declarations.
        arity_only = [
            d
            for d in visible
            if d.arity == target.arity and not d.is_variadic
        ]
        if arity_only:
            return ResolvedCall(
                site=site,
                state=CallResolutionState.UNRESOLVED,
                basis=None,
                callees=(target,),
                stop_reasons=("unresolved_target",),
            )
        return ResolvedCall(
            site=site,
            state=CallResolutionState.UNRESOLVED,
            basis=None,
            callees=(target,),
            stop_reasons=("unresolved_target",),
        )

    return ResolvedCall(
        site=site,
        state=CallResolutionState.RESOLVED,
        basis=CallResolutionBasis.VISIBLE_DECLARATION_UNIQUE_DEFINITION,
        callees=(target,),
        stop_reasons=(),
    )


def _preprocessor_compatible(
    site: CallSite,
    callee: IndexedFunction,
    sources_by_abs: Mapping[str, str],
    pp_cache_by_abs: Optional[Mapping[str, List[Tuple[str, ...]]]] = None,
) -> bool:
    if pp_cache_by_abs is not None:
        caller_cache = pp_cache_by_abs.get(site.caller.file_abs)
        callee_cache = pp_cache_by_abs.get(callee.file_abs)
        if caller_cache is not None and callee_cache is not None:
            return conditions_compatible(
                stack_at_cached(caller_cache, site.line),
                stack_at_cached(callee_cache, callee.start_line),
            )
    caller_src = sources_by_abs.get(site.caller.file_abs, "")
    callee_src = sources_by_abs.get(callee.file_abs, "")
    caller_stack = condition_stack_at_line(caller_src, site.line)
    callee_stack = condition_stack_at_line(callee_src, callee.start_line)
    return conditions_compatible(caller_stack, callee_stack)


def resolve_call_site(
    site: CallSite,
    index: SourceIndex,
    adjacency: Mapping[str, Set[str]],
    *,
    sources_by_abs: Optional[Mapping[str, str]] = None,
    pp_cache_by_abs: Optional[Mapping[str, List[Tuple[str, ...]]]] = None,
) -> ResolvedCall:
    """Resolve one call site; only ``resolved`` may propagate."""
    sources_by_abs = sources_by_abs or {}

    if site.call_form in {"member_dot", "member_arrow"}:
        return ResolvedCall(
            site=site,
            state=CallResolutionState.UNRESOLVED,
            basis=None,
            callees=(),
            stop_reasons=("unsupported_call_form",),
        )
    if site.call_form in {"macro_like", "qualified"}:
        return ResolvedCall(
            site=site,
            state=CallResolutionState.UNRESOLVED,
            basis=None,
            callees=(),
            stop_reasons=("unsupported_call_form",),
        )
    if site.truncated:
        return ResolvedCall(
            site=site,
            state=CallResolutionState.UNRESOLVED,
            basis=None,
            callees=(),
            stop_reasons=tuple(site.stop_reasons) or ("parse_truncated",),
        )

    caller_src = sources_by_abs.get(site.caller.file_abs, "")
    if caller_src:
        shadow = caller_shadows_as_non_function(
            caller_src, site.caller, site.simple_name, site.line
        )
        if shadow:
            return ResolvedCall(
                site=site,
                state=CallResolutionState.INDIRECT,
                basis=None,
                callees=(),
                stop_reasons=(shadow,),
            )

    static_hit = resolve_same_file_static(site, index)
    if static_hit is not None:
        if (
            static_hit.state == CallResolutionState.RESOLVED
            and static_hit.callees
            and sources_by_abs
        ):
            if not _preprocessor_compatible(
                site,
                static_hit.callees[0],
                sources_by_abs,
                pp_cache_by_abs=pp_cache_by_abs,
            ):
                return ResolvedCall(
                    site=site,
                    state=CallResolutionState.CONFIGURATION_DEPENDENT,
                    basis=None,
                    callees=static_hit.callees,
                    stop_reasons=("unresolved_target",),
                )
        return static_hit

    cross = resolve_visible_cross_file(site, index, adjacency)
    if cross is not None:
        if (
            cross.state == CallResolutionState.RESOLVED
            and cross.callees
            and sources_by_abs
        ):
            if not _preprocessor_compatible(
                site,
                cross.callees[0],
                sources_by_abs,
                pp_cache_by_abs=pp_cache_by_abs,
            ):
                return ResolvedCall(
                    site=site,
                    state=CallResolutionState.CONFIGURATION_DEPENDENT,
                    basis=None,
                    callees=cross.callees,
                    stop_reasons=("unresolved_target",),
                )
        return cross

    return ResolvedCall(
        site=site,
        state=CallResolutionState.UNRESOLVED,
        basis=None,
        callees=(),
        stop_reasons=("unresolved_target",),
    )
