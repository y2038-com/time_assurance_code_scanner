# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for symlink containment, metrics, candidate IDs, and LLM merge."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tacs.core.candidate_utils import (
    candidate_id_for,
    dedupe_candidates,
    make_candidate_id,
    prepare_candidates,
    sort_candidates,
)
from tacs.core.function_analyzer import FunctionAnalyzer
from tacs.core.function_llm_client import FunctionLLMClient
from tacs.core.function_schemas import FunctionAnalysis, FunctionBody, Y2038Summary
from tacs.core.ir_adapter import IRAdapter
from tacs.core.metrics import calculate_metrics
from tacs.core.path_utils import canonical_source_path
from tacs.core.schema import Candidate
from tacs.core.source_files import enumerate_source_files, path_is_within_root

SOURCE = """#include <time.h>

static time_t my_difftime(time_t a, time_t b) {
    return a - b;
}

int check_date_max(struct tm *t, time_t *out) {
    time_t now = time(NULL);
    *out = now;
    return (int)now;
}
"""

RULES = [
    {"symbol": "time_t", "risk": "high", "category": "type", "description": "time_t"},
    {"symbol": "struct tm", "risk": "high", "category": "structure", "description": "tm"},
    {"symbol": "time", "risk": "high", "category": "function", "description": "time"},
]


def _write_repo_with_symlinks(tmp_path: Path) -> tuple[Path, Path]:
    """
    Build a synthetic tree:

    * ``src/time.c`` — real in-repo source
    * ``alias/time.c`` — in-repo symlink to ``src/time.c``
    * ``alias2/time.c`` — second in-repo alias to the same file
    * ``escape/out.c`` — relative ``../..`` escape to an external file
    * ``abs_link/out.c`` — absolute symlink to an external file
    """
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "alias").mkdir(parents=True)
    (root / "alias2").mkdir(parents=True)
    (root / "escape").mkdir(parents=True)
    (root / "abs_link").mkdir(parents=True)

    real = root / "src" / "time.c"
    real.write_text(SOURCE, encoding="utf-8")
    (root / "alias" / "time.c").symlink_to(Path("../src/time.c"))
    (root / "alias2" / "time.c").symlink_to(Path("../src/time.c"))

    external = tmp_path / "outside" / "secret.c"
    external.parent.mkdir(parents=True)
    external.write_text("int leak(void) { return 0; }\n", encoding="utf-8")
    (root / "escape" / "out.c").symlink_to(Path("../../outside/secret.c"))
    (root / "abs_link" / "out.c").symlink_to(external.resolve())

    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps(RULES), encoding="utf-8")
    return root, rules


def test_path_is_within_root_rejects_external(tmp_path: Path) -> None:
    root, _ = _write_repo_with_symlinks(tmp_path)
    assert path_is_within_root(root / "src" / "time.c", root)
    assert path_is_within_root(root / "alias" / "time.c", root)
    assert not path_is_within_root(root / "escape" / "out.c", root)
    assert not path_is_within_root(root / "abs_link" / "out.c", root)


def test_enumerate_collapses_aliases_and_skips_external(tmp_path: Path) -> None:
    root, _ = _write_repo_with_symlinks(tmp_path)

    enumeration = enumerate_source_files(str(root), ["**/*.c"])

    assert len(enumeration.files) == 1
    assert enumeration.files[0] == (root / "src" / "time.c").resolve()
    skipped = set(enumeration.skipped_external)
    assert "escape/out.c" in skipped
    assert "abs_link/out.c" in skipped
    assert "alias/time.c" not in skipped
    assert "alias2/time.c" not in skipped


def test_metrics_count_in_repo_source_once(tmp_path: Path) -> None:
    root, _ = _write_repo_with_symlinks(tmp_path)
    expected_lines = SOURCE.count("\n")
    expected_chars = sum(len(line.rstrip("\n\r")) for line in SOURCE.splitlines(True))

    metrics = calculate_metrics(str(root), ["**/*.c"], [])

    assert metrics.total_files == 1
    assert metrics.total_lines == expected_lines
    assert metrics.total_chars == expected_chars


def test_ir_discovery_ignores_external_and_dedupes_aliases(tmp_path: Path) -> None:
    root, rules = _write_repo_with_symlinks(tmp_path)
    adapter = IRAdapter("src/tacs/python/y2038scan_fast_json_group.py")

    candidates = adapter.discover_candidates(str(root), str(rules), min_risk="low")

    keys = [(c.file, c.line, c.symbol) for c in candidates]
    assert len(keys) == len(set(keys))
    for c in candidates:
        assert Path(c.file).resolve() == (root / "src" / "time.c").resolve()
        assert "outside" not in c.file
        assert "secret" not in c.file


def test_canonical_source_path_collapses_symlink_alias(tmp_path: Path) -> None:
    root, _ = _write_repo_with_symlinks(tmp_path)
    real = root / "src" / "time.c"
    link = root / "alias" / "time.c"
    assert canonical_source_path(str(link)) == canonical_source_path(str(real))


def test_candidate_id_distinguishes_column_and_risk() -> None:
    a = Candidate(
        file="/r/a.c", line=10, symbol="time_t", one_line_snippet="x",
        risk="high", col_start=0, col_end=6,
    )
    b = Candidate(
        file="/r/a.c", line=10, symbol="time_t", one_line_snippet="x",
        risk="high", col_start=8, col_end=14,
    )
    c = Candidate(
        file="/r/a.c", line=10, symbol="time_t", one_line_snippet="x",
        risk="medium", col_start=0, col_end=6,
    )

    id_a = candidate_id_for(a, "a.c")
    id_b = candidate_id_for(b, "a.c")
    id_c = candidate_id_for(c, "a.c")

    assert id_a != id_b
    assert id_a != id_c
    assert id_a == "a.c:10:0:6:high:time_t"
    assert make_candidate_id("a.c", 10, "time_t", 0, 6, "high") == id_a

    prepared = prepare_candidates([a, b, c, a])
    assert len(prepared) == 3


def test_prepare_candidates_dedupes_and_sorts() -> None:
    a = Candidate(file="/r/a.c", line=2, symbol="time_t", one_line_snippet="x", risk="high")
    b = Candidate(file="/r/a.c", line=2, symbol="time_t", one_line_snippet="x", risk="high")
    c = Candidate(file="/r/a.c", line=1, symbol="time", one_line_snippet="y", risk="high")
    d = Candidate(file="/r/a.c", line=2, symbol="struct tm", one_line_snippet="z", risk="high")

    prepared = prepare_candidates([a, b, d, c])

    assert len(prepared) == 3
    assert [p.line for p in prepared] == [1, 2, 2]
    assert [p.symbol for p in prepared] == ["time", "struct tm", "time_t"]


def test_functionization_dedupes_symlink_path_forms(tmp_path: Path) -> None:
    root, _ = _write_repo_with_symlinks(tmp_path)
    real = root / "src" / "time.c"
    link = root / "alias" / "time.c"
    analyzer = FunctionAnalyzer(root_path=str(root))
    candidates = [
        Candidate(file=str(real), line=4, symbol="time_t", one_line_snippet="x", risk="high"),
        Candidate(file=str(link), line=4, symbol="time_t", one_line_snippet="x", risk="high"),
        Candidate(file=str(real), line=9, symbol="time", one_line_snippet="y", risk="high"),
        Candidate(file=str(link), line=9, symbol="time", one_line_snippet="y", risk="high"),
    ]

    functions = analyzer.extract_functions_with_candidates(candidates)
    ids = [f.function_id for f in functions]

    assert len(ids) == len(set(ids))
    assert len(functions) == 2
    assert all(fid.startswith("src/time.c@") for fid in ids)


def _align(summaries: list[str]) -> FunctionAnalysis:
    client = FunctionLLMClient.__new__(FunctionLLMClient)
    func = FunctionBody(
        function_id="a.c@fn:1-3",
        file_path="/tmp/a.c",
        symbol="fn",
        start_line=1,
        end_line=3,
        body="int fn(void) { return 0; }",
        candidate_lines=[2],
    )
    analyses = [
        FunctionAnalysis(
            function_id="a.c@fn:1-3",
            y2038_summary=Y2038Summary(s),
            confidence=0.5 + i * 0.1,
            issues=[{"type": "x", "line": 2, "description": s}],
        )
        for i, s in enumerate(summaries)
    ]
    aligned = client._align_analyses_to_functions(analyses, [func], "S2_P1", "test")
    assert len(aligned) == 1
    return aligned[0]


@pytest.mark.parametrize(
    "summaries,expected",
    [
        (["yes", "yes"], "yes"),
        (["no", "no"], "no"),
        (["abstain", "abstain"], "abstain"),
        (["yes", "no"], "abstain"),
        (["yes", "abstain"], "abstain"),
        (["no", "abstain"], "abstain"),
    ],
)
def test_align_duplicate_outputs(summaries: list[str], expected: str) -> None:
    result = _align(summaries)
    assert result.y2038_summary.value == expected
    if expected == "abstain" and len(set(summaries)) > 1:
        assert any(i.get("type") == "duplicate_conflict" for i in result.issues)


def test_batch_accounting_invariant_helper() -> None:
    functions = [
        FunctionBody(
            function_id=f"f.c@fn{i}:1-2",
            file_path="/tmp/f.c",
            symbol=f"fn{i}",
            start_line=1,
            end_line=2,
            body="void fn(void) {}",
            candidate_lines=[1],
        )
        for i in range(3)
    ]
    summaries = [Y2038Summary.YES, Y2038Summary.NO, Y2038Summary.ABSTAIN]
    analyses = [
        FunctionAnalysis(
            function_id=fn.function_id,
            y2038_summary=summary,
            confidence=0.5,
            issues=[],
        )
        for fn, summary in zip(functions, summaries)
    ]
    yes = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.YES)
    no = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.NO)
    abstain = sum(1 for a in analyses if a.y2038_summary == Y2038Summary.ABSTAIN)
    assert len(functions) == len({f.function_id for f in functions})
    assert yes + no + abstain == len(functions)


def test_dedupe_preserves_distinct_symbols_on_same_line() -> None:
    a = Candidate(file="/r/a.c", line=10, symbol="time_t", one_line_snippet="x", risk="high")
    b = Candidate(file="/r/a.c", line=10, symbol="struct tm", one_line_snippet="x", risk="high")
    out = dedupe_candidates([a, b, a])
    assert len(out) == 2
    assert {c.symbol for c in out} == {"time_t", "struct tm"}


def test_sort_candidates_is_deterministic() -> None:
    items = [
        Candidate(file="/r/b.c", line=1, symbol="a", one_line_snippet="", risk="high"),
        Candidate(file="/r/a.c", line=2, symbol="z", one_line_snippet="", risk="high"),
        Candidate(file="/r/a.c", line=1, symbol="m", one_line_snippet="", risk="high"),
    ]
    assert sort_candidates(items) == sort_candidates(reversed(items))
