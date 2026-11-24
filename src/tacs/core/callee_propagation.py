# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""One-hop direct-callee time-argument propagation (issue #57).

Builds a minimal source/call index, resolves only ``resolved`` targets, maps
time-bearing caller arguments to callee parameters, and reseeds the issue #52
local narrowing scanner. Does not implement multi-hop graph traversal (#58).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from tacs.core.alias_scope import build_include_adjacency
from tacs.core.call_resolution import resolve_call_site
from tacs.core.call_site_index import (
    MAX_CALL_EXPRESSION_CHARS,
    CallSite,
    find_call_sites_in_function,
)
from tacs.core.candidate_utils import candidate_id_for
from tacs.core.function_scanner import ScannedFunction, mask_non_code, scan_functions
from tacs.core.local_narrowing_scanner import (
    ExternalTimeSeed,
    LocalNarrowingScanner,
    TimeLocal,
    narrowing_matches_to_candidates,
)
from tacs.core.path_utils import canonical_source_path, repo_relative_path
from tacs.core.preprocessor_conditions import build_condition_stack_cache
from tacs.core.schema import (
    CallResolutionState,
    Candidate,
    PropagationArgument,
    PropagationCallSite,
    PropagationKind,
    PropagationParameter,
    PropagationPath,
    PropagationResolution,
    PropagationStopReason,
    TimeSemantic,
)
from tacs.core.source_index import (
    IndexedFunction,
    SourceIndex,
    _index_definitions_from_source,
    build_source_index,
)

MAX_PROPAGATED_PARAMETERS_PER_CALL = 4
MAX_ORIGIN_CANDIDATE_IDS = 32
MAX_PROPAGATION_PATHS_PER_CANDIDATE = 32

#: Lexical hints that a file or function span may carry absolute-time
#: provenance. Fail-open only: a hit admits deeper analysis; it does not
#: assert time semantics. Includes seed time types and stdlib return-value
#: producers; project-local epoch/UTC producers and discovered typedef
#: aliases are checked separately in ``_lexical_time_hint``.
_TIME_HINT_RE = re.compile(
    r"\b(?:time_t|clock_t|timer_t|suseconds_t|useconds_t|"
    r"mktime|timegm|timelocal|gmtime|localtime|gettimeofday|"
    r"clock_gettime)\b|\btime\s*\(",
    re.ASCII,
)

#: Cheap gate before running TypedefScanner on a loaded buffer.
_TYPEDEF_HINT_RE = re.compile(r"\btypedef\b", re.ASCII)

_OUTER_CAST = re.compile(
    r"^\(\s*((?:unsigned\s+|signed\s+)?"
    r"(?:long\s+long|long|short|int|char|[A-Za-z_]\w*)"
    r"(?:\s+(?:long|short|int|char))?)\s*\)\s*(.+)$",
    re.ASCII | re.DOTALL,
)


@dataclass(frozen=True)
class PropagationScanStats:
    """Internal counters for tests and diagnostics (one scan lifetime)."""

    files_loaded: int = 0
    functions_scanned: int = 0
    eligible_callers: int = 0
    callers_with_call_sites_parsed: int = 0
    calls_with_time_args: int = 0
    calls_resolved: int = 0
    callees_seeded: int = 0
    seeded_scans: int = 0
    skipped_no_eligible_callers: bool = False
    skipped_no_time_bearing_calls: bool = False


@dataclass
class _PendingSeed:
    callee: IndexedFunction
    param: Any
    seed: ExternalTimeSeed
    path: PropagationPath
    site: CallSite


def _semantic_enum(value: str) -> TimeSemantic:
    try:
        return TimeSemantic(value)
    except ValueError:
        return TimeSemantic.TIME_RELATED_UNKNOWN


def _is_safe_repo_relative(path: str) -> bool:
    if not path or path.startswith("/") or path.startswith("\\"):
        return False
    if re.match(r"^[A-Za-z]:[\\/]", path):
        return False
    if ".." in path.replace("\\", "/").split("/"):
        return False
    return True


def path_referentially_valid(
    path: PropagationPath,
    *,
    existing_candidates: Sequence[Candidate],
    caller: IndexedFunction,
    callee: IndexedFunction,
    site: CallSite,
    param_name: str,
    param_type: str,
    param_index: int,
) -> bool:
    """Fail closed when a path would publish dangling or inconsistent references.

    Unknown ``origin_candidate_ids`` reject the path (callers should filter
    with ``filter_origin_ids`` first). Does not invent missing records.
    """
    if path.depth != 1 or path.propagation_depth != 1:
        return False
    if path.caller_function_id != caller.public_function_id:
        return False
    if path.callee_function_id != callee.public_function_id:
        return False
    if path.argument.index < 0 or path.argument.index >= site.argument_count:
        return False
    if path.parameter.index != param_index or path.parameter.name != param_name:
        return False
    if path.parameter.declared_type != param_type:
        return False
    if param_index < 0 or param_index >= len(callee.parameters):
        return False
    if path.call_site.file != caller.file_rel:
        return False
    if not _is_safe_repo_relative(path.call_site.file):
        return False
    if path.call_site.line < caller.start_line or path.call_site.line > caller.end_line:
        return False
    if path.origin_candidate_ids:
        known: Set[str] = {candidate_id_for(c, c.file) for c in existing_candidates}
        for oid in path.origin_candidate_ids:
            if oid not in known:
                return False
    return True


def filter_origin_ids(
    origin_ids: Sequence[str],
    existing_candidates: Sequence[Candidate],
) -> List[str]:
    """Keep only origin IDs that exist in the current candidate set.

    Does not invent missing records. Returns a sorted, deduplicated list.
    """
    if not origin_ids or not existing_candidates:
        return []
    known: Set[str] = {candidate_id_for(c, c.file) for c in existing_candidates}
    kept = sorted({oid for oid in origin_ids if oid in known})
    return kept[:MAX_ORIGIN_CANDIDATE_IDS]


def _strip_outer_cast(expr: str) -> Tuple[str, Optional[str]]:
    text = expr.strip()
    match = _OUTER_CAST.match(text)
    if not match:
        return text, None
    return match.group(2).strip(), _normalize_ws(match.group(1))


def _normalize_ws(text: str) -> str:
    return " ".join(text.split())


def _expr_time_local(
    expr: str,
    time_locals: Mapping[str, TimeLocal],
) -> Optional[TimeLocal]:
    """Return a time-local referenced by a simple or cast expression."""
    inner, _cast = _strip_outer_cast(expr)
    inner = inner.strip()
    # Direct identifier.
    if re.fullmatch(r"[A-Za-z_]\w*", inner):
        return time_locals.get(inner)
    # Cast of identifier already handled by strip; nested cast.
    inner2, _ = _strip_outer_cast(inner)
    if re.fullmatch(r"[A-Za-z_]\w*", inner2):
        return time_locals.get(inner2)
    # Field access: obj.field / ptr->field when the field name is a time local
    # (rare) or the base is time-bearing — only accept when the full field
    # path's final identifier is a known time local name (structure fields
    # seeded as locals are uncommon; caller-side field time locals use the
    # field name key in #52 when declared locally).
    field = inner.replace("->", ".").split(".")[-1]
    if field in time_locals and ("." in inner or "->" in inner):
        return time_locals[field]
    # Call expression: time(NULL) etc. — require the call itself to be a
    # time-producing call assigned through #52; bare call args are handled
    # when collect_time_locals already marked temporaries. For direct
    # ``save(time(NULL))`` synthesize a transient TimeLocal when the call
    # name is a known producer.
    return None


def _classify_call_arg_semantic(
    expr: str,
    time_locals: Mapping[str, TimeLocal],
    scanner: LocalNarrowingScanner,
) -> Optional[TimeLocal]:
    hit = _expr_time_local(expr, time_locals)
    if hit is not None:
        return hit
    inner, _ = _strip_outer_cast(expr.strip())
    # Direct time-producing call as the argument.
    from tacs.core.local_narrowing_scanner import _is_time_producing_call, _call_names

    for name in _call_names(inner):
        if _is_time_producing_call(name, scanner.time_functions):
            return TimeLocal(
                name=name,
                type_repr=scanner.resolve_placeholder_time_t(),
                provenance=f"Unix-epoch/absolute-time call {name}()",
                time_semantic="unix_epoch_seconds",
            )
    return None


def _build_candidates_by_file(
    existing: Sequence[Candidate],
    root_path: str,
) -> Dict[str, List[Candidate]]:
    """Index existing candidates by repo-relative file (one scan lifetime).

    Avoids repeated ``repo_relative_path`` / ``canonical_source_path`` work
    inside per-call origin lookup (was the dominant cost on large corpora).
    """
    by_file: Dict[str, List[Candidate]] = {}
    for cand in existing:
        rel = repo_relative_path(cand.file, root_path)
        if not rel:
            rel = repo_relative_path(canonical_source_path(cand.file), root_path)
        if not rel:
            continue
        by_file.setdefault(rel, []).append(cand)
    return by_file


def _origin_ids_for_caller(
    caller: IndexedFunction,
    existing: Sequence[Candidate],
    root_path: str,
    time_local: TimeLocal,
    *,
    candidates_by_file: Optional[Mapping[str, Sequence[Candidate]]] = None,
) -> List[str]:
    """Collect origin candidate IDs from existing candidates in the caller span."""
    ids: List[str] = []
    seen: Set[str] = set()
    if candidates_by_file is not None:
        pool: Sequence[Candidate] = candidates_by_file.get(caller.file_rel, ())
    else:
        pool = existing
    for cand in pool:
        if candidates_by_file is None:
            rel = repo_relative_path(cand.file, root_path)
            if rel != caller.file_rel and canonical_source_path(cand.file) != caller.file_abs:
                if repo_relative_path(canonical_source_path(cand.file), root_path) != caller.file_rel:
                    continue
        line = int(cand.line or 0)
        if line < caller.start_line or line > caller.end_line:
            continue
        # Prefer time-related catalog / cast symbols near the provenance.
        sym = (cand.symbol or "").lower()
        if sym in {"time", "time_t", "mktime", "timegm", "timelocal"} or "time" in sym:
            cid = candidate_id_for(cand, caller.file_rel)
            if cid not in seen:
                seen.add(cid)
                ids.append(cid)
    if time_local.origin_candidate_ids:
        for cid in time_local.origin_candidate_ids:
            if cid not in seen:
                seen.add(cid)
                ids.append(cid)
    return sorted(ids)


def _alias_names(time_t_aliases: Optional[Dict[str, Any]]) -> List[str]:
    alias_names: List[str] = []
    if not time_t_aliases:
        return alias_names
    sample = next(iter(time_t_aliases.values()), None)
    if isinstance(sample, dict):
        for amap in time_t_aliases.values():
            if isinstance(amap, dict):
                alias_names.extend(str(k) for k in amap.keys())
    elif isinstance(sample, list):
        alias_names.extend(str(k) for k in time_t_aliases.keys())
    return alias_names


def _function_body_text(source: str, scanned: ScannedFunction) -> str:
    lines = source.splitlines(keepends=True)
    start_idx = max(0, scanned.start_line - 1)
    end_idx = min(len(lines), scanned.end_line)
    span = "".join(lines[start_idx:end_idx])
    brace = span.find("{")
    if brace < 0:
        return ""
    return span[brace + 1 :]


def _function_span_text(source: str, scanned: ScannedFunction) -> str:
    """Full function text including the declarator (parameter types matter)."""
    lines = source.splitlines(keepends=True)
    start_idx = max(0, scanned.start_line - 1)
    end_idx = min(len(lines), scanned.end_line)
    return "".join(lines[start_idx:end_idx])


def _lexical_time_hint(
    text: str,
    alias_names: Sequence[str],
    *,
    time_functions: Optional[Set[str]] = None,
) -> bool:
    """Cheap fail-open prefilter: text may contain absolute-time provenance.

    Admits deeper analysis only. Does not classify values as time-bearing.
    Checks: seed time types / stdlib tokens; discovered typedef alias names;
    and Issue #52-recognized epoch/UTC producer call identifiers.
    """
    if not text:
        return False
    if _TIME_HINT_RE.search(text):
        return True
    for alias in alias_names:
        if alias and re.search(rf"\b{re.escape(alias)}\b", text):
            return True
    # Fail-open for supported producer call forms (same predicate as #52).
    from tacs.core.local_narrowing_scanner import _is_time_producing_call, _call_names

    funcs = set(time_functions or ())
    for name in _call_names(text):
        if _is_time_producing_call(name, funcs):
            return True
    return False


def _discover_alias_names_from_sources(
    sources: Mapping[str, str],
    seed_alias_names: Sequence[str],
) -> List[str]:
    """Merge pipeline aliases with typedef aliases found in loaded sources.

    Runs TypedefScanner only on buffers that already contain ``typedef`` and a
    seed time type or known alias token — no extra disk reads. One scan
    lifetime only.
    """
    names: Set[str] = {a for a in seed_alias_names if a}
    # Files that cannot define a time_t alias chain need not be parsed.
    seed_tokens = {"time_t", "clock_t", "timer_t", "suseconds_t", "useconds_t"} | names
    candidates = {
        path: src
        for path, src in sources.items()
        if _TYPEDEF_HINT_RE.search(src)
        and any(tok in src for tok in seed_tokens)
    }
    if not candidates:
        return sorted(names)

    from tacs.core.typedef_scanner import TypedefScanner

    scanner = TypedefScanner()
    typedef_map: Dict[str, List[str]] = {}
    for path, src in candidates.items():
        found = scanner._find_typedefs(src, path)
        if found:
            typedef_map[path] = found
    if not typedef_map:
        return sorted(names)

    # Flatten name → defs across files for hop closure.
    flat: Dict[str, List[str]] = {}
    for file_map in typedef_map.values():
        for alias, defs in file_map.items():
            flat.setdefault(alias, []).extend(defs)
    discovered = scanner.find_time_t_aliases(flat)
    names.update(discovered.keys())
    return sorted(names)


def _body_has_time_producing_call(
    body: str, scanner: LocalNarrowingScanner
) -> bool:
    from tacs.core.local_narrowing_scanner import _is_time_producing_call, _call_names

    for name in _call_names(body):
        if _is_time_producing_call(name, scanner.time_functions):
            return True
    return False


def _time_typed_parameter_seeds(
    source: str,
    scanned: ScannedFunction,
    scanner: LocalNarrowingScanner,
) -> Dict[str, ExternalTimeSeed]:
    """Seed scalar by-value parameters typed as ``time_t`` / known aliases.

    ``collect_time_locals`` only matches ``type name;`` / ``type name = ...;``,
    so a declarator like ``void f(epoch_t now)`` would miss supported provenance
    (and break later cast/assignment chains such as ``int64_t x = (int64_t)now``).
    Seeds are applied *before* body ingestion so those chains still propagate.
    Pointer, reference, and array parameters are ignored (same as #57 seeding).
    """
    from tacs.core.local_narrowing_scanner import _normalize_type
    from tacs.core.source_index import parse_parameter_list

    span = _function_span_text(source, scanned)
    brace = span.find("{")
    if brace < 0:
        return {}
    params, _variadic, stop = parse_parameter_list(span[:brace])
    if stop or not params:
        return {}
    seeds: Dict[str, ExternalTimeSeed] = {}
    for param in params:
        if param.is_pointer or param.is_reference or param.is_array:
            continue
        type_name = _normalize_type(param.declared_type.replace("*", " "))
        if type_name not in scanner._time_types:
            continue
        seeds[param.name] = ExternalTimeSeed(
            name=param.name,
            declared_type=type_name,
            time_semantic="time_t_value",
            provenance=f"declared as {type_name}",
        )
    return seeds


def _env_cache_token(environment_config: Optional[Dict[str, Any]]) -> Tuple:
    if not environment_config:
        return ()
    return (
        environment_config.get("config_id"),
        environment_config.get("hardware_model"),
        environment_config.get("time_t_size_bits"),
        environment_config.get("time_t_signed"),
    )


def _seed_cache_key(
    callee: IndexedFunction,
    seed: ExternalTimeSeed,
    environment_config: Optional[Dict[str, Any]],
) -> Tuple:
    """Deterministic key for reusing seeded local-narrowing analysis.

    Lifecycle: one ``propagate_direct_callee_time`` invocation (one scan).
    Distinguishes callee, parameter identity, semantic, width/signedness, and
    environment. Distinct callers still attach distinct propagation paths.
    """
    return (
        callee.internal_id,
        seed.name,
        seed.declared_type,
        seed.time_semantic,
        seed.bits,
        seed.signedness,
        _env_cache_token(environment_config),
    )


def propagate_direct_callee_time(
    *,
    root_path: str,
    files: Sequence[Path],
    existing_candidates: Sequence[Candidate],
    time_t_aliases: Optional[Dict[str, Any]] = None,
    time_functions: Optional[Sequence[str]] = None,
    environment_config: Optional[Dict[str, Any]] = None,
    _stats_out: Optional[List[PropagationScanStats]] = None,
) -> List[Candidate]:
    """Return new/augmented narrowing candidates from one-hop propagation.

    Demand-driven: expensive call-site parsing and resolution run only for
    functions with deterministic time-bearing evidence. Definition indexing
    and include adjacency are deferred until at least one time-bearing call
    argument is observed.
    """
    root = canonical_source_path(root_path)
    file_list = [Path(canonical_source_path(p)) for p in files]
    sources: Dict[str, str] = {}
    for path in file_list:
        try:
            sources[str(path)] = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

    pipeline_aliases = _alias_names(time_t_aliases)
    # Include typedef aliases declared in loaded headers/sources so a caller
    # file that only spells ``epoch_t`` is not skipped when ``time_t`` lives
    # in an included project header in the same scan set.
    alias_names = _discover_alias_names_from_sources(sources, pipeline_aliases)
    scanner = LocalNarrowingScanner(
        time_t_aliases=alias_names,
        time_functions=list(time_functions or ()),
        environment_config=environment_config,
    )
    candidates_by_file = _build_candidates_by_file(existing_candidates, root)
    producer_funcs = set(scanner.time_functions)

    # Per-scan caches (not retained across repositories/configs).
    masked_by_abs: Dict[str, str] = {}
    scanned_by_abs: Dict[str, List[ScannedFunction]] = {}

    # --- Phase 1: eligible time-bearing callers (no call-site parsing yet) ---
    eligible: List[Tuple[str, ScannedFunction, Dict[str, TimeLocal]]] = []
    functions_scanned = 0
    for abs_path, source in sources.items():
        # File-level fail-open prefilter: skip mask/scan when the file cannot
        # contain absolute-time provenance.
        if not _lexical_time_hint(
            source, alias_names, time_functions=producer_funcs
        ):
            continue
        masked = mask_non_code(source)
        masked_by_abs[abs_path] = masked
        scanned_list = scan_functions(source, masked=masked)
        scanned_by_abs[abs_path] = scanned_list
        functions_scanned += len(scanned_list)
        for scanned in scanned_list:
            # Use the full declarator+body span so parameter types such as
            # ``epoch_t now`` are visible to the hint (body-after-``{`` alone
            # would false-negative supported callers).
            span = _function_span_text(source, scanned)
            if not _lexical_time_hint(
                span, alias_names, time_functions=producer_funcs
            ):
                continue
            param_seeds = _time_typed_parameter_seeds(source, scanned, scanner)
            time_locals = scanner.collect_time_locals(
                source,
                scanned,
                externally_time_derived_parameters=param_seeds or None,
            )
            body = _function_body_text(source, scanned)
            if time_locals or _body_has_time_producing_call(body, scanner):
                eligible.append((abs_path, scanned, time_locals))

    if not eligible:
        stats = PropagationScanStats(
            files_loaded=len(sources),
            functions_scanned=functions_scanned,
            skipped_no_eligible_callers=True,
        )
        if _stats_out is not None:
            _stats_out.append(stats)
        return []

    # --- Phase 2: parse call sites only in eligible callers; gate on time args ---
    # Index only eligible caller definitions (not the whole project) so CallSite
    # has a real IndexedFunction for shadowing checks before full resolution.
    pending: List[Tuple[IndexedFunction, CallSite, Dict[str, TimeLocal], List[Tuple]]] = []
    callers_parsed = 0
    for abs_path, scanned, time_locals in eligible:
        source = sources[abs_path]
        rel = repo_relative_path(abs_path, root) or abs_path
        caller_defs = _index_definitions_from_source(
            source,
            abs_path,
            rel,
            masked=masked_by_abs.get(abs_path),
            scanned_functions=[scanned],
        )
        if not caller_defs:
            continue
        caller = caller_defs[0]
        sites = find_call_sites_in_function(
            source, caller, masked_source=masked_by_abs.get(abs_path)
        )
        callers_parsed += 1
        if not sites:
            continue
        for site in sites:
            if site.call_form != "direct_id":
                continue
            time_args: List[Tuple] = []
            for arg in site.arguments:
                tlocal = _classify_call_arg_semantic(
                    arg.expression, time_locals, scanner
                )
                if tlocal is not None:
                    time_args.append((arg, tlocal))
            if time_args:
                pending.append((caller, site, time_locals, time_args))

    if not pending:
        stats = PropagationScanStats(
            files_loaded=len(sources),
            functions_scanned=functions_scanned,
            eligible_callers=len(eligible),
            callers_with_call_sites_parsed=callers_parsed,
            skipped_no_time_bearing_calls=True,
        )
        if _stats_out is not None:
            _stats_out.append(stats)
        return []

    # --- Phase 3: resolve with lazy indexes ---
    # Prefer per-file definition indexes for same-file static (basis A).
    # Build the project-wide index (with declarations + include adjacency)
    # only when at least one call still needs cross-file resolution.
    from tacs.core.call_resolution import resolve_same_file_static
    from tacs.core.schema import CallResolutionBasis

    def _ensure_file_masked(abs_path: str) -> None:
        if abs_path in masked_by_abs:
            return
        src = sources.get(abs_path)
        if not src:
            return
        masked_by_abs[abs_path] = mask_non_code(src)
        if abs_path not in scanned_by_abs:
            scanned_by_abs[abs_path] = scan_functions(src, masked=masked_by_abs[abs_path])

    file_def_indexes: Dict[str, SourceIndex] = {}

    def _file_index(abs_path: str) -> SourceIndex:
        hit = file_def_indexes.get(abs_path)
        if hit is not None:
            return hit
        _ensure_file_masked(abs_path)
        src = sources.get(abs_path, "")
        rel = repo_relative_path(abs_path, root) or abs_path
        idx = SourceIndex()
        if src:
            defs = _index_definitions_from_source(
                src,
                abs_path,
                rel,
                masked=masked_by_abs.get(abs_path),
                scanned_functions=scanned_by_abs.get(abs_path),
            )
            for fn in defs:
                idx.definitions.append(fn)
                idx.by_internal_id[fn.internal_id] = fn
                idx.definitions_by_name.setdefault(fn.symbol, []).append(fn)
                idx.definitions_by_simple_name.setdefault(
                    fn.simple_symbol, []
                ).append(fn)
                idx.definitions_by_file.setdefault(fn.file_abs, []).append(fn)
        file_def_indexes[abs_path] = idx
        return idx

    pp_cache_by_abs: Dict[str, List[Tuple[str, ...]]] = {}

    def _pp_cache(abs_path: str) -> List[Tuple[str, ...]]:
        hit = pp_cache_by_abs.get(abs_path)
        if hit is not None:
            return hit
        cache = build_condition_stack_cache(sources.get(abs_path, ""))
        pp_cache_by_abs[abs_path] = cache
        return cache

    project_index: Optional[SourceIndex] = None
    adjacency = None

    def _ensure_project_index() -> SourceIndex:
        nonlocal project_index, adjacency
        if project_index is not None:
            return project_index
        # Ensure every loaded file has mask/scan for index reuse.
        for abs_path in sources:
            _ensure_file_masked(abs_path)
        project_index = build_source_index(
            file_list,
            root,
            sources_by_abs=sources,
            masked_by_abs=masked_by_abs,
            scanned_by_abs=scanned_by_abs,
            include_declarations=True,
        )
        adjacency = build_include_adjacency(file_list, root)
        return project_index

    seeds_by_callee: Dict[str, Dict[str, ExternalTimeSeed]] = {}
    paths_by_callee_param: Dict[Tuple[str, str], List[PropagationPath]] = {}
    visited_edges: Set[Tuple[str, int, str, str]] = set()
    callees_by_id: Dict[str, IndexedFunction] = {}
    calls_resolved = 0

    for caller, site, time_locals, time_args in pending:
        # Basis A: same-file static via a per-file definitions index.
        local_idx = _file_index(caller.file_abs)
        # Rebind caller to the file-index entry when present.
        local_matches = [
            fn
            for fn in local_idx.definitions_by_file.get(caller.file_abs, ())
            if fn.start_line == caller.start_line
            and fn.end_line == caller.end_line
            and fn.symbol == caller.symbol
        ]
        if local_matches:
            caller = local_matches[0]
            site = CallSite(
                caller=caller,
                file_rel=site.file_rel,
                line=site.line,
                column=site.column,
                raw_expression=site.raw_expression,
                callee_expr=site.callee_expr,
                simple_name=site.simple_name,
                call_form=site.call_form,
                arguments=site.arguments,
                argument_count=site.argument_count,
                stop_reasons=site.stop_reasons,
                truncated=site.truncated,
            )

        # Shadowing / function-pointer checks must run before basis A/B.
        from tacs.core.call_resolution import (
            ResolvedCall,
            caller_shadows_as_non_function,
        )

        shadow = caller_shadows_as_non_function(
            sources.get(caller.file_abs, ""),
            caller,
            site.simple_name,
            site.line,
        )
        if shadow:
            resolved = ResolvedCall(
                site=site,
                state=CallResolutionState.INDIRECT,
                basis=None,
                callees=(),
                stop_reasons=(shadow,),
            )
        else:
            resolved = resolve_same_file_static(site, local_idx)
        if (
            shadow is None
            and resolved is not None
            and resolved.state == CallResolutionState.RESOLVED
        ):
            # Preprocessor check with lazy per-file caches.
            callee0 = resolved.callees[0]
            from tacs.core.preprocessor_conditions import (
                conditions_compatible,
                stack_at_cached,
            )

            if not conditions_compatible(
                stack_at_cached(_pp_cache(caller.file_abs), site.line),
                stack_at_cached(_pp_cache(callee0.file_abs), callee0.start_line),
            ):
                resolved = ResolvedCall(
                    site=site,
                    state=CallResolutionState.CONFIGURATION_DEPENDENT,
                    basis=None,
                    callees=resolved.callees,
                    stop_reasons=("unresolved_target",),
                )
        elif shadow is None and (
            resolved is None or resolved.state != CallResolutionState.RESOLVED
        ):
            # Basis B: project-wide index only when same-file static cannot resolve.
            index = _ensure_project_index()
            # Rebind to project canonical entry.
            canon = index.by_internal_id.get(caller.internal_id)
            if canon is None:
                matches = [
                    fn
                    for fn in index.definitions_by_file.get(caller.file_abs, ())
                    if fn.start_line == caller.start_line
                    and fn.end_line == caller.end_line
                    and fn.symbol == caller.symbol
                ]
                canon = matches[0] if matches else caller
            caller = canon
            site = CallSite(
                caller=caller,
                file_rel=site.file_rel,
                line=site.line,
                column=site.column,
                raw_expression=site.raw_expression,
                callee_expr=site.callee_expr,
                simple_name=site.simple_name,
                call_form=site.call_form,
                arguments=site.arguments,
                argument_count=site.argument_count,
                stop_reasons=site.stop_reasons,
                truncated=site.truncated,
            )
            resolved = resolve_call_site(
                site,
                index,
                adjacency or {},
                sources_by_abs=sources,
                pp_cache_by_abs=pp_cache_by_abs,
            )

        if resolved.state != CallResolutionState.RESOLVED or not resolved.callees:
            continue
        if resolved.basis is None:
            continue
        callee = resolved.callees[0]
        if callee.internal_id == caller.internal_id:
            continue
        calls_resolved += 1
        callees_by_id[callee.internal_id] = callee

        propagated_this_call = 0
        truncated_this_call = False
        for arg, tlocal in time_args:
            if propagated_this_call >= MAX_PROPAGATED_PARAMETERS_PER_CALL:
                truncated_this_call = True
                break
            if arg.index >= len(callee.parameters):
                continue
            param = callee.parameters[arg.index]
            edge_key = (
                caller.internal_id,
                site.line,
                callee.internal_id,
                param.name,
            )
            if edge_key in visited_edges:
                continue
            if param.is_pointer or param.is_reference or param.is_array:
                continue
            if callee.is_variadic and arg.index >= callee.arity:
                continue

            semantic = _semantic_enum(tlocal.time_semantic)
            expr = arg.expression.strip()
            if len(expr) > MAX_CALL_EXPRESSION_CHARS:
                continue

            visited_edges.add(edge_key)
            origin_ids = filter_origin_ids(
                _origin_ids_for_caller(
                    caller,
                    existing_candidates,
                    root,
                    tlocal,
                    candidates_by_file=candidates_by_file,
                ),
                existing_candidates,
            )
            path = PropagationPath(
                kind=PropagationKind.DIRECT_CALLEE_ARGUMENT,
                depth=1,
                origin_candidate_ids=origin_ids,
                caller_function_id=caller.public_function_id,
                call_site=PropagationCallSite(
                    file=caller.file_rel,
                    line=site.line,
                    column=site.column,
                ),
                resolution=PropagationResolution(
                    state=CallResolutionState.RESOLVED,
                    basis=resolved.basis,
                ),
                argument=PropagationArgument(index=arg.index, expression=expr),
                callee_function_id=callee.public_function_id,
                parameter=PropagationParameter(
                    index=param.index,
                    name=param.name,
                    declared_type=param.declared_type,
                ),
                time_semantic=semantic,
                propagation_depth=1,
                truncated=False,
                stop_reasons=[],
            )
            if not path_referentially_valid(
                path,
                existing_candidates=existing_candidates,
                caller=caller,
                callee=callee,
                site=site,
                param_name=param.name,
                param_type=param.declared_type,
                param_index=param.index,
            ):
                continue
            seed = ExternalTimeSeed(
                name=param.name,
                declared_type=param.declared_type,
                time_semantic=semantic.value,
                provenance=(
                    f"propagated from {caller.public_function_id} "
                    f"call arg {arg.index} ({expr}); {tlocal.provenance}"
                ),
                origin_candidate_ids=origin_ids,
                bits=tlocal.type_repr.bits,
                signedness=tlocal.type_repr.signedness,
            )
            bucket = seeds_by_callee.setdefault(callee.internal_id, {})
            if param.name not in bucket:
                bucket[param.name] = seed
            key = (callee.internal_id, param.name)
            paths_by_callee_param.setdefault(key, []).append(path)
            propagated_this_call += 1

        if truncated_this_call:
            for param_key, plist in list(paths_by_callee_param.items()):
                if param_key[0] != callee.internal_id:
                    continue
                for i, path in enumerate(plist):
                    if (
                        path.caller_function_id == caller.public_function_id
                        and path.call_site.line == site.line
                        and not path.truncated
                    ):
                        plist[i] = path.model_copy(
                            update={
                                "truncated": True,
                                "stop_reasons": list(path.stop_reasons)
                                + [PropagationStopReason.TOO_MANY_PROPAGATED_PARAMETERS],
                            }
                        )

    if not seeds_by_callee:
        stats = PropagationScanStats(
            files_loaded=len(sources),
            functions_scanned=functions_scanned,
            eligible_callers=len(eligible),
            callers_with_call_sites_parsed=callers_parsed,
            calls_with_time_args=len(pending),
            calls_resolved=calls_resolved,
        )
        if _stats_out is not None:
            _stats_out.append(stats)
        return []

    # --- Phase 4: seeded callee narrowing with deterministic reuse cache ---
    seed_scan_cache: Dict[Tuple, List] = {}
    out_candidates: List[Candidate] = []
    seeded_scans = 0
    file_scanner = LocalNarrowingScanner(
        time_t_aliases=alias_names,
        time_functions=list(time_functions or ()),
        environment_config=environment_config,
    )

    for callee_id, seed_map in sorted(seeds_by_callee.items()):
        callee = callees_by_id.get(callee_id)
        if callee is None and project_index is not None:
            callee = project_index.by_internal_id.get(callee_id)
        if callee is None:
            continue
        source = sources.get(callee.file_abs)
        if not source:
            continue
        scanned = ScannedFunction(
            start_line=callee.start_line,
            end_line=callee.end_line,
            symbol=callee.symbol,
        )
        # Cache key covers the full seed map identity for this callee.
        cache_key = (
            callee.internal_id,
            tuple(
                sorted(
                    (
                        s.name,
                        s.declared_type,
                        s.time_semantic,
                        s.bits,
                        s.signedness,
                    )
                    for s in seed_map.values()
                )
            ),
            _env_cache_token(environment_config),
        )
        if cache_key in seed_scan_cache:
            seeded_matches = seed_scan_cache[cache_key]
        else:
            matches = file_scanner.scan_function(
                source,
                callee.file_abs,
                scanned,
                externally_time_derived_parameters=seed_map,
            )
            seeded_matches = [m for m in matches if m.from_external_seed]
            seed_scan_cache[cache_key] = seeded_matches
            seeded_scans += 1
        if not seeded_matches:
            continue
        cands = narrowing_matches_to_candidates(seeded_matches)
        for match, cand in zip(seeded_matches, cands):
            paths: List[PropagationPath] = []
            for param_name, seed in seed_map.items():
                if param_name == match.source_var or param_name in match.provenance:
                    paths.extend(paths_by_callee_param.get((callee_id, param_name), []))
            if not paths:
                for param_name in seed_map:
                    if param_name in (match.provenance or ""):
                        paths.extend(
                            paths_by_callee_param.get((callee_id, param_name), [])
                        )
            paths = _dedupe_paths(paths)[:MAX_PROPAGATION_PATHS_PER_CANDIDATE]
            if cand.line < callee.start_line or cand.line > callee.end_line:
                continue
            cand = cand.model_copy(
                update={
                    "discovery_method": "direct_callee_time_propagation",
                    "rule_id": None,
                    "propagation_paths": paths or None,
                }
            )
            out_candidates.append(cand)

    stats = PropagationScanStats(
        files_loaded=len(sources),
        functions_scanned=functions_scanned,
        eligible_callers=len(eligible),
        callers_with_call_sites_parsed=callers_parsed,
        calls_with_time_args=len(pending),
        calls_resolved=calls_resolved,
        callees_seeded=len(seeds_by_callee),
        seeded_scans=seeded_scans,
    )
    if _stats_out is not None:
        _stats_out.append(stats)
    return out_candidates


def _dedupe_paths(paths: Sequence[PropagationPath]) -> List[PropagationPath]:
    seen: Set[Tuple] = set()
    out: List[PropagationPath] = []
    for path in sorted(
        paths,
        key=lambda p: (
            p.caller_function_id,
            p.call_site.file,
            p.call_site.line,
            p.call_site.column or 0,
            p.argument.index,
            p.callee_function_id,
            p.parameter.index,
        ),
    ):
        key = (
            path.caller_function_id,
            path.call_site.file,
            path.call_site.line,
            path.call_site.column,
            path.argument.index,
            path.argument.expression,
            path.callee_function_id,
            path.parameter.index,
            path.parameter.name,
            path.resolution.basis.value if path.resolution.basis else None,
            path.time_semantic.value,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(path)
    return out


def merge_propagation_into_existing(
    existing: Sequence[Candidate],
    propagated: Sequence[Candidate],
) -> List[Candidate]:
    """Merge propagated candidates into existing, preserving local discovery_method.

    Precedence: when the same sink identity already exists from local
    discovery (``time_t_cast``), keep that discovery_method and attach
    ``propagation_paths``. When only propagation found the sink, keep
    ``direct_callee_time_propagation``.
    """
    from tacs.core.candidate_utils import (
        candidate_identity_key,
        normalize_candidate_file,
    )

    by_key: Dict[Tuple, Candidate] = {}
    order: List[Tuple] = []
    for cand in list(existing) + list(propagated):
        normalized = normalize_candidate_file(cand)
        key = candidate_identity_key(normalized)
        if key not in by_key:
            by_key[key] = normalized
            order.append(key)
            continue
        prior = by_key[key]
        prior_method = prior.discovery_method
        new_method = normalized.discovery_method
        paths = _merge_path_lists(
            getattr(prior, "propagation_paths", None),
            getattr(normalized, "propagation_paths", None),
        )
        # Preserve established local method when combining with propagation.
        if prior_method == "time_t_cast" and new_method == "direct_callee_time_propagation":
            by_key[key] = prior.model_copy(update={"propagation_paths": paths})
        elif prior_method == "direct_callee_time_propagation" and new_method == "time_t_cast":
            by_key[key] = normalized.model_copy(
                update={
                    "discovery_method": "time_t_cast",
                    "propagation_paths": paths,
                    "description": normalized.description or prior.description,
                }
            )
        elif prior_method == new_method:
            by_key[key] = prior.model_copy(update={"propagation_paths": paths})
        else:
            # Fall back to prepare_candidates conflict rules via identity merge
            # without changing method when unrelated.
            by_key[key] = prior.model_copy(update={"propagation_paths": paths})
    from tacs.core.candidate_utils import sort_candidates

    merged = [by_key[k] for k in order]
    return sort_candidates(merged)


def _merge_path_lists(
    a: Optional[Sequence[PropagationPath]],
    b: Optional[Sequence[PropagationPath]],
) -> Optional[List[PropagationPath]]:
    paths = list(a or []) + list(b or [])
    if not paths:
        return None
    return _dedupe_paths(paths)
