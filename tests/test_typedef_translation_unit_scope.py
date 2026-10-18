# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for typedef / translation-unit alias scope."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from tacs.core.alias_scope import (
    aliases_for_source_file,
    build_include_adjacency,
    compute_scoped_time_aliases,
    flatten_scoped_aliases,
    relativize_scoped_aliases,
)
from tacs.core.candidate_utils import (
    CandidateProvenanceConflictError,
    candidate_identity_key,
    dedupe_candidates,
    prepare_candidates,
)
from tacs.core.discovery_manager import DiscoveryManager
from tacs.core.pipeline import ScanningPipeline
from tacs.core.schema import Candidate
from tacs.core.typedef_scanner import TypedefScanner

REPO = Path(__file__).resolve().parents[1]
PATTERNS = Path(__file__).resolve().parent / "patterns"
RULES = REPO / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
SCANNER = REPO / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"


def _line45_hits(result: Dict[str, Any], stem: str = "arith") -> List[Dict[str, Any]]:
    out = []
    for cand in result.get("candidates") or []:
        file_name = Path(str(cand.get("file") or "")).name
        if cand.get("line") == 45 and stem in file_name:
            out.append(cand)
    return out


def _candidate_fingerprint(result: Dict[str, Any]) -> List[Tuple[Any, ...]]:
    rows = []
    for cand in result.get("candidates") or []:
        rows.append(
            (
                Path(str(cand.get("file") or "")).name,
                cand.get("line"),
                cand.get("symbol"),
                cand.get("rule_id"),
                cand.get("description"),
                cand.get("risk"),
                cand.get("function_id"),
                cand.get("candidate_id"),
            )
        )
    return sorted(rows)


def _run_scan(root: Path, out: Path) -> Dict[str, Any]:
    if not RULES.is_file() or not SCANNER.is_file():
        pytest.skip("sample rules or scanner missing")
    pipeline = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        function_first=True,
        confidence_floor=0.0,
        enable_pass1=False,
        enable_io_analysis=False,
        enable_discovery=True,
    )
    results = pipeline.scan(
        root_path=str(root),
        rules_path=str(RULES),
        min_risk="low",
        include_patterns=["**/*.c", "**/*.h"],
        exclude_patterns=[],
        session_dir=str(root / "session"),
    )
    pipeline.save_results(results, str(out))
    return json.loads(out.read_text(encoding="utf-8"))


def test_arithmetic_plus_type_patterns_completes(tmp_path: Path) -> None:
    root = tmp_path / "pair_type"
    root.mkdir()
    shutil.copy(PATTERNS / "test_arithmetic_patterns.c", root / "arith.c")
    shutil.copy(PATTERNS / "test_type_patterns.c", root / "types.c")
    result = _run_scan(root, root / "findings.json")
    hits = _line45_hits(result, stem="arith")
    symbols = {(c["symbol"], c.get("rule_id")) for c in hits}
    assert ("time", "TACS-RULE-0040") in symbols
    assert ("time_t", "TACS-RULE-0192") in symbols


def test_arithmetic_plus_cast_patterns_completes(tmp_path: Path) -> None:
    root = tmp_path / "pair_cast"
    root.mkdir()
    shutil.copy(PATTERNS / "test_arithmetic_patterns.c", root / "arith.c")
    shutil.copy(PATTERNS / "test_cast_patterns.c", root / "casts.c")
    result = _run_scan(root, root / "findings.json")
    hits = _line45_hits(result, stem="arith")
    symbols = {(c["symbol"], c.get("rule_id")) for c in hits}
    assert ("time", "TACS-RULE-0040") in symbols
    assert ("time_t", "TACS-RULE-0192") in symbols


def test_reversed_file_order_same_candidates(tmp_path: Path) -> None:
    a = tmp_path / "order_a"
    b = tmp_path / "order_b"
    a.mkdir()
    b.mkdir()
    shutil.copy(PATTERNS / "test_arithmetic_patterns.c", a / "arith.c")
    shutil.copy(PATTERNS / "test_type_patterns.c", a / "types.c")
    shutil.copy(PATTERNS / "test_type_patterns.c", b / "aaa_types.c")
    shutil.copy(PATTERNS / "test_arithmetic_patterns.c", b / "zzz_arith.c")

    ra = _run_scan(a, a / "findings.json")
    rb = _run_scan(b, b / "findings.json")

    def arith_rows(result: Dict[str, Any]) -> List[Tuple[Any, ...]]:
        rows = []
        for cand in result.get("candidates") or []:
            name = Path(str(cand.get("file") or "")).name
            if "arith" not in name:
                continue
            rows.append(
                (
                    cand.get("line"),
                    cand.get("symbol"),
                    cand.get("rule_id"),
                    cand.get("description"),
                    cand.get("risk"),
                )
            )
        return sorted(rows)

    assert arith_rows(ra) == arith_rows(rb)


def test_typedef_in_one_c_does_not_affect_another(tmp_path: Path) -> None:
    root = tmp_path / "isolated"
    root.mkdir()
    (root / "alias_owner.c").write_text(
        "#include <time.h>\n"
        "typedef time_t isolated_time_t;\n"
        "void owner(void) { isolated_time_t t = 0; (void)t; }\n",
        encoding="utf-8",
    )
    (root / "other.c").write_text(
        "#include <time.h>\n"
        "// Unrelated identifier that must not inherit the alias rule.\n"
        "int isolated_time_t = 0;\n"
        "void other(void) { (void)isolated_time_t; }\n",
        encoding="utf-8",
    )
    result = _run_scan(root, root / "findings.json")
    other_hits = [
        c
        for c in result.get("candidates") or []
        if Path(str(c.get("file") or "")).name == "other.c"
        and c.get("symbol") == "isolated_time_t"
    ]
    assert other_hits == []


def test_typedef_applies_within_declaring_translation_unit(tmp_path: Path) -> None:
    root = tmp_path / "local_alias"
    root.mkdir()
    (root / "local.c").write_text(
        "#include <time.h>\n"
        "typedef time_t local_epoch_t;\n"
        "void use_alias(void) {\n"
        "    local_epoch_t t = time(NULL);\n"
        "    (void)t;\n"
        "}\n",
        encoding="utf-8",
    )
    result = _run_scan(root, root / "findings.json")
    alias_hits = [
        c
        for c in result.get("candidates") or []
        if c.get("symbol") == "local_epoch_t"
    ]
    assert alias_hits, "declared typedef alias should produce candidates in its TU"
    assert all(Path(str(c["file"])).name == "local.c" for c in alias_hits)


def test_header_typedef_applies_only_to_includers(tmp_path: Path) -> None:
    root = tmp_path / "hdr_scope"
    root.mkdir()
    (root / "alias.h").write_text(
        "#ifndef ALIAS_H\n#define ALIAS_H\n"
        "#include <time.h>\n"
        "typedef time_t header_epoch_t;\n"
        "#endif\n",
        encoding="utf-8",
    )
    (root / "with_include.c").write_text(
        '#include "alias.h"\n'
        "void with_it(void) { header_epoch_t t = 0; (void)t; }\n",
        encoding="utf-8",
    )
    (root / "without_include.c").write_text(
        "#include <time.h>\n"
        "int header_epoch_t = 1;\n"
        "void without_it(void) { (void)header_epoch_t; }\n",
        encoding="utf-8",
    )
    result = _run_scan(root, root / "findings.json")

    with_hits = [
        c
        for c in result.get("candidates") or []
        if Path(str(c.get("file") or "")).name == "with_include.c"
        and c.get("symbol") == "header_epoch_t"
    ]
    without_hits = [
        c
        for c in result.get("candidates") or []
        if Path(str(c.get("file") or "")).name == "without_include.c"
        and c.get("symbol") == "header_epoch_t"
    ]
    assert with_hits, "including TU should see header typedef alias"
    assert without_hits == [], "non-including TU must not inherit header alias"


def test_time_and_time_t_both_retained_exactly_once(tmp_path: Path) -> None:
    root = tmp_path / "both"
    root.mkdir()
    shutil.copy(PATTERNS / "test_arithmetic_patterns.c", root / "arith.c")
    shutil.copy(PATTERNS / "test_type_patterns.c", root / "types.c")
    result = _run_scan(root, root / "findings.json")
    hits = _line45_hits(result, stem="arith")
    time_hits = [c for c in hits if c.get("symbol") == "time"]
    time_t_hits = [c for c in hits if c.get("symbol") == "time_t"]
    assert len(time_hits) == 1
    assert time_hits[0].get("rule_id") == "TACS-RULE-0040"
    assert len(time_t_hits) == 1
    assert time_t_hits[0].get("rule_id") == "TACS-RULE-0192"


def test_arithmetic_fixture_candidate_stability(tmp_path: Path) -> None:
    root = tmp_path / "stable"
    root.mkdir()
    shutil.copy(PATTERNS / "test_arithmetic_patterns.c", root / "arith.c")
    first = _run_scan(root, root / "findings1.json")
    second = _run_scan(root, root / "findings2.json")
    assert _candidate_fingerprint(first) == _candidate_fingerprint(second)

    hits = _line45_hits(first, stem="arith")
    by_sym = {c["symbol"]: c for c in hits}
    assert by_sym["time"]["rule_id"] == "TACS-RULE-0040"
    assert by_sym["time_t"]["rule_id"] == "TACS-RULE-0192"
    assert by_sym["time"]["description"].startswith("Gets time since epoch")
    assert by_sym["time"]["function_id"]


def test_genuine_same_scope_conflict_still_fails_closed() -> None:
    a = Candidate(
        file="x.c",
        line=1,
        symbol="time",
        risk="high",
        description="Gets time since epoch in a time_t",
        one_line_snippet="time(NULL);",
        discovery_method="catalog_symbol_match",
        rule_id="TACS-RULE-0040",
    )
    b = Candidate(
        file="x.c",
        line=1,
        symbol="time",
        risk="high",
        description="Typedef alias for time_t (discovered: 1 definitions)",
        one_line_snippet="time(NULL);",
        discovery_method="catalog_symbol_match",
        rule_id=None,
    )
    assert candidate_identity_key(a) == candidate_identity_key(b)
    with pytest.raises(CandidateProvenanceConflictError, match="Conflicting description"):
        dedupe_candidates([a, b])
    with pytest.raises(CandidateProvenanceConflictError, match="Conflicting description"):
        prepare_candidates([a, b])


def test_repeated_scans_identical_candidates(tmp_path: Path) -> None:
    root = tmp_path / "repeat"
    root.mkdir()
    shutil.copy(PATTERNS / "test_arithmetic_patterns.c", root / "arith.c")
    shutil.copy(PATTERNS / "test_type_patterns.c", root / "types.c")
    r1 = _run_scan(root, root / "a.json")
    r2 = _run_scan(root, root / "b.json")
    assert _candidate_fingerprint(r1) == _candidate_fingerprint(r2)


def test_catalog_colliding_alias_promoted_scoped_type_use_only(tmp_path: Path) -> None:
    """Colliding spellings are promoted with scope + type_use_only, not suppressed."""
    rules = tmp_path / "rules.json"
    rules.write_text(
        json.dumps(
            [
                {
                    "symbol": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "Gets time since epoch in a time_t",
                    "rule_id": "TACS-RULE-0040",
                },
                {
                    "symbol": "time_t",
                    "risk": "high",
                    "category": "simple type",
                    "description": "Secs since epoch",
                    "rule_id": "TACS-RULE-0192",
                },
            ]
        ),
        encoding="utf-8",
    )
    mgr = DiscoveryManager()
    scoped = {
        str(tmp_path / "a.c"): {
            "time": [f"{tmp_path / 'a.c'}:1: typedef time_t time;"],
            "my_time_t": [f"{tmp_path / 'a.c'}:2: typedef time_t my_time_t;"],
        }
    }
    updated = Path(
        mgr.update_rules_with_discoveries(
            str(rules),
            scoped,
            {},
            output_dir=str(tmp_path / "prescan"),
            root_path=str(tmp_path),
            scoped_aliases=scoped,
        )
    )
    payload = json.loads(updated.read_text(encoding="utf-8"))
    discovered = [r for r in payload if r.get("discovered")]
    time_rules = [r for r in discovered if r["symbol"] == "time"]
    assert len(time_rules) == 1
    assert time_rules[0]["type_use_only"] is True
    assert time_rules[0]["scope_files"] == ["a.c"]
    assert "Typedef alias" in time_rules[0]["description"]
    # Catalog function row is unchanged.
    catalog_time = [r for r in payload if r.get("rule_id") == "TACS-RULE-0040"]
    assert len(catalog_time) == 1
    assert catalog_time[0].get("discovered") in (None, False)
    my_rules = [r for r in discovered if r["symbol"] == "my_time_t"]
    assert len(my_rules) == 1
    assert my_rules[0].get("type_use_only") in (None, False)
    assert "a.c" in my_rules[0]["scope_files"]


def test_catalog_colliding_local_alias_vs_other_tu_function_call(tmp_path: Path) -> None:
    """File A typedefs ``time``; File B still sees only the catalog ``time()`` rule."""
    root = tmp_path / "collide"
    root.mkdir()
    (root / "a.c").write_text(
        "#include <time.h>\n"
        "typedef time_t time;\n"
        "time deadline;\n"
        "void fa(void) { (void)deadline; }\n",
        encoding="utf-8",
    )
    (root / "b.c").write_text(
        "#include <time.h>\n"
        "void fb(void) {\n"
        "    time_t now = time(NULL);\n"
        "    (void)now;\n"
        "}\n",
        encoding="utf-8",
    )
    result = _run_scan(root, root / "findings.json")

    a_time = [
        c
        for c in result["candidates"]
        if Path(c["file"]).name == "a.c" and c["symbol"] == "time"
    ]
    # The declaration ``time deadline;`` must be the local typedef alias, not
    # the catalog ``time()`` function. Other in-file ``time`` tokens (include /
    # typedef lines) may also match the scoped typedef rule; none may carry the
    # catalog function description.
    deadline = [c for c in a_time if c.get("line") == 3]
    assert len(deadline) == 1
    assert deadline[0].get("rule_id") is None
    assert "Typedef alias" in (deadline[0].get("description") or "")
    assert all(
        "Gets time since epoch" not in (c.get("description") or "")
        for c in a_time
    )
    assert all(
        "Typedef alias" in (c.get("description") or "")
        for c in a_time
    )

    b_time = [
        c
        for c in result["candidates"]
        if Path(c["file"]).name == "b.c" and c["symbol"] == "time"
    ]
    b_time_t = [
        c
        for c in result["candidates"]
        if Path(c["file"]).name == "b.c" and c["symbol"] == "time_t"
    ]
    assert len(b_time) == 1
    assert b_time[0].get("rule_id") == "TACS-RULE-0040"
    assert b_time[0].get("description", "").startswith("Gets time since epoch")
    assert len(b_time_t) == 1
    assert b_time_t[0].get("rule_id") == "TACS-RULE-0192"

    # No typedef-alias description for ``time`` leaked into B.
    assert all("Typedef alias" not in (c.get("description") or "") for c in b_time)


def test_io_boundary_does_not_use_cross_tu_flat_alias(tmp_path: Path) -> None:
    """An alias declared only in A must not make I/O treat B's identifier as time_t."""
    from tacs.core.io_boundary_analyzer import IOBoundaryAnalyzer

    root = tmp_path / "io_scope"
    root.mkdir()
    (root / "owner.c").write_text(
        "#include <time.h>\n"
        "typedef time_t only_here_t;\n"
        "void owner(void) { only_here_t t = 0; (void)t; }\n",
        encoding="utf-8",
    )
    other = root / "other.c"
    other.write_text(
        '#include <stdio.h>\n'
        "int only_here_t = 42;\n"
        "void other(void) { printf(\"%d\", only_here_t); }\n",
        encoding="utf-8",
    )

    # Scoped map: alias visible only in owner.c
    scoped = {
        "owner.c": {
            "only_here_t": ["owner.c:2: typedef time_t only_here_t;"],
        },
        "other.c": {},
    }
    analyzer = IOBoundaryAnalyzer(
        time_t_aliases={"only_here_t": ["owner.c:2: typedef time_t only_here_t;"]},
        time_bearing_symbols={"only_here_t"},
        environment_config={
            "hardware_model": "ILP32",
            "time_t_size_bits": 32,
            "time_t_signed": "signed",
        },
        enable_io_analysis=True,
        score_threshold=0.0,
    )
    analyzer.update_time_context(
        time_t_aliases={"only_here_t": ["owner.c:2: typedef time_t only_here_t;"]},
        time_bearing_symbols={"only_here_t"},
        scoped_time_t_aliases=scoped,
        root_path=str(root),
    )
    io_hits = analyzer._analyze_file(str(other))
    # Flat union would treat only_here_t as a time type in printf; scoped must not.
    assert io_hits == []


def test_llm_prompt_aliases_are_batch_file_scoped() -> None:
    """Optional LLM data plane lists only aliases visible to the batch's files."""
    from tacs.core.llm_client import LLMClient
    from tacs.core.schema import Candidate

    client = LLMClient("none", "none")
    client.time_t_aliases = {
        "only_in_a": ["a.c:1: typedef time_t only_in_a;"],
        "only_in_b": ["b.c:1: typedef time_t only_in_b;"],
    }
    client.scoped_time_t_aliases = {
        "a.c": {"only_in_a": ["a.c:1: typedef time_t only_in_a;"]},
        "b.c": {"only_in_b": ["b.c:1: typedef time_t only_in_b;"]},
    }
    client.alias_root_path = None
    batch = [
        Candidate(
            file="a.c",
            line=2,
            symbol="only_in_a",
            risk="high",
            description="",
            one_line_snippet="only_in_a t;",
        )
    ]
    assert client._alias_names_for_candidates(batch) == ["only_in_a"]


def test_scoped_alias_computation_unit_and_header(tmp_path: Path) -> None:
    (tmp_path / "alias.h").write_text(
        "#include <time.h>\ntypedef time_t header_t;\n",
        encoding="utf-8",
    )
    (tmp_path / "user.c").write_text(
        '#include "alias.h"\nvoid f(void) { header_t t = 0; (void)t; }\n',
        encoding="utf-8",
    )
    (tmp_path / "other.c").write_text(
        "#include <time.h>\nvoid g(void) {}\n",
        encoding="utf-8",
    )
    scanner = TypedefScanner()
    per_file = scanner.scan_directory(
        str(tmp_path), ["**/*.c", "**/*.h"], []
    )
    adjacency = build_include_adjacency(
        [Path(p) for p in per_file], str(tmp_path)
    )
    scoped = compute_scoped_time_aliases(
        per_file, adjacency, scanner.find_time_t_aliases, {"time_t"}
    )
    scoped_rel = relativize_scoped_aliases(
        scoped, str(tmp_path), DiscoveryManager._relativize_definition
    )
    user_aliases = aliases_for_source_file(scoped_rel, "user.c", str(tmp_path))
    other_aliases = aliases_for_source_file(scoped_rel, "other.c", str(tmp_path))
    assert "header_t" in user_aliases
    assert "header_t" not in other_aliases
    flat = flatten_scoped_aliases(scoped_rel)
    assert "header_t" in flat
