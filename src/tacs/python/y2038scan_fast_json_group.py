#!/usr/bin/env python3
# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

# y2038scan_fast_json_group.py
# Fast Y2038 scanner with inverted token index, bigrams, comment/string stripping,
# function-call guard via category, risk filtering, group-by-line, and JSON output.

import argparse, json, os, re, sys, glob
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any, Optional

# ---- color output (safe if colorama not installed) --------------------------
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init()
    RISK_COLORS = {
        'low':    Fore.CYAN,
        'medium': Fore.YELLOW,
        'high':   Fore.LIGHTRED_EX
    }
    RESET = Style.RESET_ALL
except Exception:
    RISK_COLORS = {'low':'', 'medium':'', 'high':''}
    RESET = ''

# ---- risk ordering ----------------------------------------------------------
RANK = {'low': 0, 'medium': 1, 'high': 2}

# Categories that are NOT function calls (do NOT require a following '(')
NON_CALLABLE_CATEGORIES = {
    'constant/definition', 'env variable', 'global variable',
    'macro', 'simple type', 'structure'
}

# Allowed source file extensions
SRC_EXTS = {'.c', '.h', '.hpp', '.hh', '.cpp', '.cc', '.cxx'}


# ============================== Rule handling ===============================

def _norm_keys(d: Dict[str, Any]) -> Dict[str, Any]:
    """Lowercase the top-level keys of a dict; do not alter values."""
    return { (k.lower() if isinstance(k, str) else k): v for k, v in d.items() }

def load_rules(path: str, min_risk: str) -> Tuple[Dict[str, List[Dict[str,Any]]], int]:
    """
    Load rules JSON. Build a token-index dict: key (token or bigram) -> [rules].
    Also compute 'needs_paren' from 'category' (unless explicitly provided).
    Returns (tok_idx, min_rank)

    ``rule_id`` is copied from the catalog when present. Packaged catalogs are
    validated fail-closed. External catalogs may omit IDs (null); any supplied
    non-null ID must be well-formed.
    """
    from tacs.core.rule_catalog import (
        CatalogRuleIdError,
        is_packaged_rules_path,
        load_rules_document,
        validate_catalog_entries,
        validate_packaged_catalog,
        validate_rule_id_value,
    )

    if is_packaged_rules_path(path):
        raw_entries = validate_packaged_catalog(path)
    else:
        raw_entries, _retired = load_rules_document(path)
        try:
            validate_catalog_entries(
                raw_entries, strict=False, context=str(path)
            )
        except CatalogRuleIdError:
            raise

    tok_idx: Dict[str, List[Dict[str,Any]]] = defaultdict(list)
    min_rank = RANK[min_risk]

    for entry in raw_entries:
        e = _norm_keys(entry)
        # symbol/name normalization
        symbol = e.get('symbol') or e.get('name')
        if not isinstance(symbol, str) or not symbol:
            continue

        # risk normalization
        risk = (e.get('risk') or 'high')
        if isinstance(risk, str):
            risk = risk.lower()
        if risk not in RANK:
            risk = 'high'

        # category normalization
        category = e.get('category') or ''
        category_l = category.lower() if isinstance(category, str) else ''

        # compute needs_paren if not given (function-like unless in non-callable categories)
        needs_paren = e.get('needs_paren')
        if needs_paren is None:
            needs_paren = (category_l not in NON_CALLABLE_CATEGORIES)

        raw_rid = e.get('rule_id')
        rule_id = None
        if raw_rid is not None and not (isinstance(raw_rid, str) and not raw_rid.strip()):
            # Non-null IDs always validated (never silently nulled).
            rule_id = validate_rule_id_value(
                raw_rid, context=f"rules file {path} symbol={symbol!r}"
            )

        rule = {
            'symbol': symbol,                 # case-sensitive match
            'risk': risk,
            'category': category,
            'description': e.get('description') or '',
            'needs_paren': bool(needs_paren),
            'rule_id': rule_id,
        }

        # Index the exact symbol; if it's multi-word, we store it as-is (bigram key).
        tok_idx[symbol].append(rule)

    return tok_idx, min_rank


# ============================== Scanning utils ==============================

def strip_comments_and_strings(line: str, in_block: bool) -> Tuple[str, bool]:
    """
    Remove //... and /*...*/ (multi-line) and string/char literals,
    returning the cleaned line used for tokenization, and the updated in_block flag.
    We preserve spaces where we remove content to avoid merging tokens.
    """
    i, n = 0, len(line)
    out = []
    in_str = False
    str_delim = ''
    while i < n:
        if in_block:
            # look for end of block comment
            end = line.find('*/', i)
            if end == -1:
                # whole rest is comment
                return ''.join(out), True
            # replace comment region with a space and continue after */
            out.append(' ')
            i = end + 2
            in_block = False
            continue

        ch = line[i]

        # line comment
        if ch == '/' and i + 1 < n and line[i+1] == '/':
            # rest of line ignored
            break

        # start block comment
        if ch == '/' and i + 1 < n and line[i+1] == '*':
            in_block = True
            i += 2
            continue

        # string or char literal start
        if not in_str and (ch == '"' or ch == "'"):
            in_str = True
            str_delim = ch
            i += 1
            # put a space placeholder for the entire literal
            out.append(' ')
            # consume till closing quote (respect simple escapes)
            esc = False
            while i < n:
                c2 = line[i]
                i += 1
                if esc:
                    esc = False
                    continue
                if c2 == '\\':
                    esc = True
                    continue
                if c2 == str_delim:
                    in_str = False
                    str_delim = ''
                    break
            continue

        # normal character
        out.append(ch)
        i += 1

    return ''.join(out), in_block


WORD_RE = re.compile(r'\b[_A-Za-z]\w*\b')

def tokenize_words(cleaned: str) -> List[str]:
    return WORD_RE.findall(cleaned)

def bigrams(words: List[str]) -> List[str]:
    if len(words) < 2:
        return []
    return [words[i] + ' ' + words[i+1] for i in range(len(words)-1)]


def has_call_paren(cleaned: str, symbol: str) -> bool:
    """
    Check cheaply if 'symbol' is followed by optional spaces and '(' in 'cleaned' text.
    Uses word-boundary regex for correctness but is only run on a small subset of lines.
    """
    pat = r'\b' + re.escape(symbol) + r'\b\s*\('
    return re.search(pat, cleaned) is not None


def detect_time_t_casts(cleaned: str, original: str, time_t_aliases: List[str], 
                        time_functions: List[str]) -> Optional[Dict[str, Any]]:
    """
    Detect casts from time_t sources (variables or functions).
    
    Args:
        cleaned: Line with comments/strings stripped
        original: Original line text
        time_t_aliases: List of discovered time_t typedef aliases
        time_functions: List of time-related function names
        
    Returns:
        Dict with cast match info, or None if no cast detected
    """
    # Common time_t function names (standard + discovered)
    all_time_functions = set(time_functions)
    all_time_functions.update(['time', 'mktime', 'gmtime', 'localtime', 'clock_gettime', 
                               'gettimeofday', 'timespec_get', 'timespec_getres'])
    
    # All time_t type names (base + aliases)
    all_time_types = set(['time_t'])
    all_time_types.update(time_t_aliases)
    
    # Pattern 1: Explicit cast to narrower type from time_t function
    # Matches: (int)time(), (long)mktime(), etc.
    for func in all_time_functions:
        # Pattern: (target_type)function_name(
        pattern = r'\(\s*(\w+(?:\s+\w+)?)\s*\)\s*\b' + re.escape(func) + r'\s*\('
        match = re.search(pattern, cleaned)
        if match:
            target_type = match.group(1).strip()
            # Only flag casts to narrower types (not time_t itself)
            if target_type not in all_time_types and target_type not in ['void', 'const', 'volatile']:
                return {
                    'file': '',  # Will be set by caller
                    'line': 0,   # Will be set by caller
                    'symbol': f'cast_from_{func}',
                    'risk': 'high',
                    'lineText': original,
                    'description': f'Cast from time_t function {func}() to {target_type}',
                    'discovery_method': 'time_t_cast',
                }
    
    # Pattern 2: Explicit cast to narrower type from time_t variable
    # Matches: (int)time_value, (long)timestamp, (int32_t)ts, (unsigned int)ts, etc.
    # Look for cast pattern followed by identifier (not function call)
    # Pattern: (type)identifier where identifier is not followed by (
    # Updated to handle underscores in type names like int32_t
    cast_pattern = r'\(\s*((?:unsigned\s+|signed\s+)?\w+(?:_\w+)*(?:\s+\w+)?)\s*\)\s*(\w+)(?!\s*\()'
    for match in re.finditer(cast_pattern, cleaned):
        target_type = match.group(1).strip()
        var_name = match.group(2)
        
        # Skip if casting to time_t itself
        if target_type in all_time_types:
            continue
        
        # Skip void/const/volatile casts
        if target_type in ['void', 'const', 'volatile']:
            continue
        
        # Skip pointer casts (e.g., (int*) - these are different)
        if target_type.endswith('*'):
            continue
        
        # Check if variable name suggests time_t (heuristic)
        time_indicators = ['time', 'timestamp', 'ts', 'tick', 'epoch', 'unix_time']
        var_lower = var_name.lower()
        
        # High confidence: variable name clearly time-related
        if any(indicator in var_lower for indicator in time_indicators):
            return {
                'file': '',  # Will be set by caller
                'line': 0,   # Will be set by caller
                'symbol': f'cast_from_time_var',
                'risk': 'high',
                'lineText': original,
                'description': f'Cast from time_t variable {var_name} to {target_type}',
                'discovery_method': 'time_t_cast',
            }
        
        # Medium confidence: check if variable was declared as time_t type
        # This is harder to detect without context, but we can check if
        # the line contains time_t type declaration nearby
        if any(alias in cleaned for alias in all_time_types):
            # If line contains time_t type, variable might be time_t
            # Look for pattern: time_t var_name or alias var_name
            type_var_pattern = r'\b(' + '|'.join(re.escape(t) for t in all_time_types) + r')\s+' + re.escape(var_name) + r'\b'
            if re.search(type_var_pattern, cleaned):
                return {
                    'file': '',  # Will be set by caller
                    'line': 0,   # Will be set by caller
                    'symbol': f'cast_from_time_var',
                    'risk': 'high',
                    'lineText': original,
                    'description': f'Cast from time_t variable {var_name} to {target_type}',
                    'discovery_method': 'time_t_cast',
                }
    
    # Pattern 3: Implicit cast via assignment (lower confidence)
    # Matches: int x = time_value; int32_t narrow = t; (where source is time_t)
    # Updated to handle underscores in type names like int32_t
    # Also checks if source variable was declared as time_t on the same line
    assignment_pattern = r'(\w+(?:_\w+)*(?:\s+\w+)?)\s+(\w+)\s*=\s*(\w+)'
    for match in re.finditer(assignment_pattern, cleaned):
        target_type = match.group(1).strip()
        var_name = match.group(2)  # Variable being assigned to
        source_var = match.group(3)  # Source variable
        
        # Skip if target is time_t
        if target_type in all_time_types:
            continue
        
        # Check if source variable was declared as time_t on the same line
        # Look for pattern: time_t source_var or alias source_var
        type_var_pattern = r'\b(' + '|'.join(re.escape(t) for t in all_time_types) + r')\s+' + re.escape(source_var) + r'\b'
        if re.search(type_var_pattern, cleaned):
            # Source variable is time_t, this is a narrowing assignment
            # Check if it's a function call (would have been caught by Pattern 1)
            var_pos = cleaned.find(source_var)
            if var_pos >= 0:
                remaining = cleaned[var_pos + len(source_var):var_pos + len(source_var) + 10]
                if '(' in remaining:
                    continue  # It's a function call, skip
            
            return {
                'file': '',  # Will be set by caller
                'line': 0,   # Will be set by caller
                'symbol': f'implicit_cast_from_time',
                'risk': 'high',  # High confidence if we found time_t declaration
                'lineText': original,
                'description': f'Implicit narrowing assignment from time_t variable {source_var} to {target_type}',
                'discovery_method': 'time_t_cast',
            }
        
        # Fallback: Check variable name heuristics (lower confidence)
        time_indicators = ['time', 'timestamp', 'ts', 'tick', 'epoch', 'unix_time']
        var_lower = source_var.lower()
        if any(indicator in var_lower for indicator in time_indicators):
            # Check if it's a function call (would have been caught by Pattern 1)
            var_pos = cleaned.find(source_var)
            if var_pos >= 0:
                remaining = cleaned[var_pos + len(source_var):var_pos + len(source_var) + 10]
                if '(' in remaining:
                    continue  # It's a function call, skip
            
            return {
                'file': '',  # Will be set by caller
                'line': 0,   # Will be set by caller
                'symbol': f'implicit_cast_from_time',
                'risk': 'medium',
                'lineText': original,
                'description': f'Possible implicit cast from time_t variable {source_var} to {target_type}',
                'discovery_method': 'time_t_cast',
            }
    
    return None


# ============================== Directory walk ==============================

def iter_source_files(root: str, include_patterns: List[str] = None, exclude_patterns: List[str] = None,
                      max_file_size: int = None):
    """
    Iterate over unique in-repo source files, respecting include/exclude patterns.

    Symlink aliases inside the repository collapse to one real path. Symlinks that
    resolve outside the repository root are skipped.
    """
    patterns = include_patterns or [f"**/*{ext}" for ext in sorted(SRC_EXTS)]
    try:
        from tacs.core.source_files import enumerate_source_files

        enumeration = enumerate_source_files(
            root,
            patterns,
            exclude_patterns=exclude_patterns,
            max_file_size=max_file_size,
            allowed_extensions=SRC_EXTS,
        )
        for display in enumeration.skipped_external:
            print(f"Ignoring source symlink outside repository root: {display}", file=sys.stderr)
        for file_path in enumeration.files:
            yield str(file_path)
        return
    except ImportError:
        pass

    # Fallback when the package is not importable (standalone script use).
    root_path = os.path.realpath(root)
    all_files = set()
    for pattern in patterns:
        if not pattern.startswith('/') and not os.path.isabs(pattern):
            pattern_path = os.path.join(root_path, pattern)
        else:
            pattern_path = pattern
        for match in glob.glob(pattern_path, recursive=True):
            if not os.path.isfile(match):
                continue
            ext = os.path.splitext(match)[1].lower()
            if ext not in SRC_EXTS:
                continue
            real = os.path.realpath(match)
            try:
                common = os.path.commonpath([root_path, real])
            except ValueError:
                print(
                    f"Ignoring source symlink outside repository root: {match}",
                    file=sys.stderr,
                )
                continue
            if common != root_path:
                print(
                    f"Ignoring source symlink outside repository root: {match}",
                    file=sys.stderr,
                )
                continue
            all_files.add(real)

    if exclude_patterns:
        excluded_files = set()
        for pattern in exclude_patterns:
            if not pattern.startswith('/') and not os.path.isabs(pattern):
                pattern_path = os.path.join(root_path, pattern)
            else:
                pattern_path = pattern
            for match in glob.glob(pattern_path, recursive=True):
                excluded_files.add(os.path.realpath(match))
        all_files -= excluded_files

    for file_path in sorted(all_files):
        if max_file_size is not None:
            try:
                if os.path.getsize(file_path) > max_file_size:
                    continue
            except OSError:
                pass
        yield file_path


# ================================ Main scan =================================

def scan_file(path: str,
              tok_idx: Dict[str, List[Dict[str,Any]]],
              min_rank: int,
              time_t_aliases: List[str] = None,
              time_functions: List[str] = None) -> Tuple[List[Dict[str,Any]], Counter]:
    """
    Scan a single file and return (results, per_symbol_counter).
    
    Args:
        path: File path to scan
        tok_idx: Token index dictionary
        min_rank: Minimum risk rank
        time_t_aliases: List of discovered time_t typedef aliases for cast detection
        time_functions: List of time-related function names for cast detection
    """
    results: List[Dict[str,Any]] = []
    per_symbol = Counter()
    
    if time_t_aliases is None:
        time_t_aliases = []
    if time_functions is None:
        time_functions = []

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            in_block = False
            for ln, raw in enumerate(f, 1):
                original = raw.rstrip('\n')
                cleaned, in_block = strip_comments_and_strings(original, in_block)

                # quick skip for empty/whitespace lines after stripping
                if not cleaned.strip():
                    continue

                w = tokenize_words(cleaned)
                if not w:
                    continue
                keys = set(w)
                keys.update(bigrams(w))

                for key in keys:
                    if key not in tok_idx:
                        continue
                    rules = tok_idx[key]
                    for rule in rules:
                        # risk filter first
                        if RANK[rule['risk']] < min_rank:
                            continue
                        sym = rule['symbol']
                        # enforce function-call guard
                        if rule.get('needs_paren', False) and not has_call_paren(cleaned, sym):
                            continue

                        results.append({
                            'file': path,
                            'line': ln,
                            'symbol': sym,
                            'risk': rule['risk'],
                            'lineText': original,
                            'description': rule.get('description','') or '',
                            'discovery_method': 'catalog_symbol_match',
                            'rule_id': rule.get('rule_id'),
                        })
                        per_symbol[sym] += 1
                
                # Check for casts from time_t (after token matching)
                if time_t_aliases or time_functions:
                    cast_match = detect_time_t_casts(cleaned, original, time_t_aliases, time_functions)
                    if cast_match:
                        cast_match['file'] = path
                        cast_match['line'] = ln
                        cast_match['discovery_method'] = 'time_t_cast'
                        cast_match['rule_id'] = None
                        # Apply risk filter
                        if RANK[cast_match['risk']] >= min_rank:
                            results.append(cast_match)
                            per_symbol[cast_match['symbol']] += 1

    except Exception as e:
        print(f"Error reading {path}: {e}", file=sys.stderr)

    return results, per_symbol


def group_by_line(results: List[Dict[str,Any]]) -> List[Dict[str,Any]]:
    """
    Merge results with the same (file,line) into one record.
    symbols → list; discovery_methods / rule_ids → parallel lists; risk → max
    risk among merged; lineText preserved from first.
    """
    grouped_map: Dict[Tuple[str,int], Dict[str,Any]] = {}
    for r in results:
        key = (r['file'], r['line'])
        method = r.get('discovery_method')
        rule_id = r.get('rule_id')
        g = grouped_map.get(key)
        if not g:
            grouped_map[key] = {
                'file': r['file'],
                'line': r['line'],
                'symbols': [r['symbol']],
                'discovery_methods': [method],
                'rule_ids': [rule_id],
                'risk': r['risk'],
                'lineText': r['lineText'],
                'description': r.get('description','') or ''
            }
        else:
            if r['symbol'] not in g['symbols']:
                g['symbols'].append(r['symbol'])
                g['discovery_methods'].append(method)
                g['rule_ids'].append(rule_id)
            if RANK[r['risk']] > RANK[g['risk']]:
                g['risk'] = r['risk']
    return sorted(grouped_map.values(), key=lambda x: (x['file'], x['line']))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('directory', help='root directory to scan')
    ap.add_argument('rules', help='rules JSON file')
    ap.add_argument('--min-risk', choices=['low','medium','high'], default='medium')
    ap.add_argument('--verbosity', type=int, choices=[0,1,2,3,4], default=0)
    ap.add_argument('--json-out', help='write JSON results to file (grouped or raw)')
    ap.add_argument('--group-by-line', action='store_true', help='merge multiple symbols per line into one record')
    ap.add_argument('--time-t-aliases', help='JSON file with time_t aliases for cast detection')
    ap.add_argument('--time-functions', help='JSON file with time function names for cast detection')
    ap.add_argument('--include', action='append', default=None, help='Include glob patterns (can be specified multiple times)')
    ap.add_argument('--exclude', action='append', default=None, help='Exclude glob patterns (can be specified multiple times)')
    ap.add_argument('--max-file-size', type=int, default=None, help='Skip source files larger than this many bytes (default: no limit)')
    args = ap.parse_args()

    tok_idx, min_rank = load_rules(args.rules, args.min_risk)
    
    # Load time_t aliases and functions for cast detection
    time_t_aliases = []
    time_functions = []
    
    if args.time_t_aliases:
        try:
            with open(args.time_t_aliases, 'r', encoding='utf-8') as f:
                aliases_data = json.load(f)
                # Handle both list format and dict format
                if isinstance(aliases_data, list):
                    time_t_aliases = aliases_data
                elif isinstance(aliases_data, dict):
                    # Extract alias names from dict of {alias: [definitions]}
                    time_t_aliases = list(aliases_data.keys())
        except Exception as e:
            print(f"Warning: Could not load time_t aliases from {args.time_t_aliases}: {e}", file=sys.stderr)
    
    if args.time_functions:
        try:
            with open(args.time_functions, 'r', encoding='utf-8') as f:
                time_functions = json.load(f)
                if not isinstance(time_functions, list):
                    time_functions = []
        except Exception as e:
            print(f"Warning: Could not load time functions from {args.time_functions}: {e}", file=sys.stderr)

    all_results: List[Dict[str,Any]] = []
    totals = Counter()
    per_symbol_total = Counter()

    # Count total files first for progress tracking
    file_list = list(iter_source_files(args.directory, args.include, args.exclude, args.max_file_size))
    total_files = len(file_list)
    files_processed = 0
    last_progress = 0
    
    for fp in file_list:
        res, per_sym = scan_file(fp, tok_idx, min_rank, time_t_aliases, time_functions)
        all_results.extend(res)
        per_symbol_total.update(per_sym)
        for r in res:
            totals[r['risk']] += 1
        
        # Progress tracking: output to stderr at 10% increments
        files_processed += 1
        if total_files > 0:
            progress_pct = int((files_processed * 100) / total_files)
            # Show progress at 10%, 20%, 30%, etc.
            if progress_pct >= last_progress + 10:
                print(f"Progress: {progress_pct}% ({files_processed}/{total_files} files)", file=sys.stderr, flush=True)
                last_progress = (progress_pct // 10) * 10

    grouped = group_by_line(all_results) if args.group_by_line else None

    # ---- summary header ----
    # Colorize each risk line at verbosity 0
    for risk in ('high', 'medium', 'low'):
        if totals[risk]:
            color = RISK_COLORS.get(risk, '')
            print(f"{color}{risk.upper()}: {totals[risk]} match(es){RESET}")

    # ---- per-symbol tally (only for verbosity >= 1) ----
    if args.verbosity >= 1 and sum(totals.values()) > 0:
        for sym in sorted(per_symbol_total.keys()):
            print(f"  {sym}: {per_symbol_total[sym]}")

    # ---- JSON output (if requested) ----
    if args.json_out:
        payload = grouped if grouped is not None else all_results
        try:
            with open(args.json_out, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            print(f"Error writing JSON: {e}", file=sys.stderr)

    # ---- per-match printing (single source of truth) ----
    '''
    if args.verbosity >= 2:
        src = grouped if grouped is not None else all_results
        for r in src:
            color = RISK_COLORS.get(r['risk'], '')
            sym_disp = r.get('symbols', r.get('symbol', ''))
            if isinstance(sym_disp, list):
                sym_disp = ', '.join(sym_disp)
            header = f"{r['file']}:{r['line']}: {sym_disp}"

            if args.verbosity in (2,3):
                print(f"{color}{header}{RESET}")
            else:
                print(f"{color}{header}{RESET}")
                print(f"    Line: {r['lineText']}")
                if args.verbosity >= 5 and r.get('description'):
                    print(f"    Desc: {r['description']}")
                print()  # blank line between entries
    '''

    # ---- per-match printing (single source of truth) ----
    if args.verbosity >= 2:
        src = grouped if grouped is not None else all_results
        for r in src:
            color = RISK_COLORS.get(r['risk'], '')
            sym_disp = r.get('symbols', r.get('symbol', ''))
            if isinstance(sym_disp, list):
                sym_disp = ', '.join(sym_disp)
            header = f"{r['file']}:{r['line']}: {sym_disp}"

            if args.verbosity == 2:
                # 2: header only
                print(f"{color}{header}{RESET}")
            elif args.verbosity == 3:
                # 3: header + source line
                print(f"{color}{header}{RESET}")
                print(f"    Line: {r['lineText']}")
                print()
            elif args.verbosity == 4:
                # 4: header + source line + description (if any)
                print(f"{color}{header}{RESET}")
                print(f"    Line: {r['lineText']}")
                if r.get('description'):
                    print(f"    Desc: {r['description']}")
                print()


if __name__ == '__main__':
    main()

