# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Default C/C++ include-scope contract for tacs scan and tacs repos."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from tacs.batch_scan_repos import (
    DEFAULT_EXCLUDE_PATTERNS as REPOS_EXCLUDE,
    DEFAULT_INCLUDE_PATTERNS as REPOS_INCLUDE,
    _build_parser,
)
from tacs.cli import app
from tacs.core.include_patterns import (
    DEFAULT_EXCLUDE_PATTERNS,
    DEFAULT_INCLUDE_PATTERNS,
    DEFAULT_SOURCE_EXTENSIONS,
)
from tacs.core.schema import PUBLIC_RESULT_SCHEMA_VERSION, ScanResults
from tacs.core.source_files import enumerate_source_files
from tacs.scan_command import main as scan_command

EXTENSIONS = DEFAULT_SOURCE_EXTENSIONS
FRAGMENTS = (".ipp", ".tpp", ".inl", ".tcc")
TIME_BODY = '#include <time.h>\ntime_t stamp(void) { return time(NULL); }\n'
CPP_BODY = """#include <ctime>

time_t stamp() {
    return time(nullptr);
}
"""
RULES = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tacs"
    / "rules"
    / "y2038_sample_rules.json"
)


def _names(root: Path, files: list[Path]) -> list[str]:
    return [p.relative_to(root).as_posix() for p in files]


def _write_scope_tree(root: Path) -> None:
    nested = root / "nested"
    nested.mkdir()
    tests_dir = root / "tests"
    tests_dir.mkdir()
    for ext in EXTENSIONS:
        (root / f"root{ext}").write_text(f"int root_{ext[1:]} = 0;\n", encoding="utf-8")
        (nested / f"nested{ext}").write_text(
            f"int nested_{ext[1:]} = 0;\n", encoding="utf-8"
        )
    for ext in FRAGMENTS:
        (root / f"skip{ext}").write_text("int skip = 0;\n", encoding="utf-8")
    (tests_dir / "hidden.c").write_text("int hidden = 0;\n", encoding="utf-8")


def test_authoritative_defaults_are_the_documented_globs() -> None:
    assert DEFAULT_INCLUDE_PATTERNS == (
        "**/*.c",
        "**/*.h",
        "**/*.cc",
        "**/*.cpp",
        "**/*.cxx",
        "**/*.hh",
        "**/*.hpp",
        "**/*.hxx",
    )
    assert DEFAULT_EXCLUDE_PATTERNS == ("**/tests/**",)
    assert REPOS_INCLUDE == DEFAULT_INCLUDE_PATTERNS
    assert REPOS_EXCLUDE == DEFAULT_EXCLUDE_PATTERNS


def test_scan_and_repos_resolve_the_same_default_patterns() -> None:
    scan_defaults = {p.name: p.default for p in scan_command.params}
    assert tuple(scan_defaults["include"]) == DEFAULT_INCLUDE_PATTERNS
    assert tuple(scan_defaults["exclude"]) == DEFAULT_EXCLUDE_PATTERNS

    args = _build_parser().parse_args(["--repos-file", "x"])
    assert args.include is None
    resolved_include = list(args.include or DEFAULT_INCLUDE_PATTERNS)
    resolved_exclude = list(args.exclude or DEFAULT_EXCLUDE_PATTERNS)
    assert resolved_include == list(DEFAULT_INCLUDE_PATTERNS)
    assert resolved_exclude == list(DEFAULT_EXCLUDE_PATTERNS)


def test_help_lists_the_default_include_and_exclude_patterns() -> None:
    scan_help = CliRunner().invoke(app, ["scan", "--help"])
    assert scan_help.exit_code == 0, scan_help.output
    repos_help = _build_parser().format_help()
    for text in (scan_help.output, repos_help):
        collapsed = " ".join(text.split())
        for pattern in DEFAULT_INCLUDE_PATTERNS:
            assert pattern in collapsed
        assert "**/tests/**" in collapsed
        assert "replaces the defaults" in collapsed
        assert ".ipp" not in collapsed
        assert ".tpp" not in collapsed


def test_defaults_match_root_and_nested_files(tmp_path: Path) -> None:
    _write_scope_tree(tmp_path)
    enumeration = enumerate_source_files(
        tmp_path,
        DEFAULT_INCLUDE_PATTERNS,
        exclude_patterns=DEFAULT_EXCLUDE_PATTERNS,
    )
    names = set(_names(tmp_path, enumeration.files))
    expected = {f"root{ext}" for ext in EXTENSIONS} | {
        f"nested/nested{ext}" for ext in EXTENSIONS
    }
    assert names == expected
    for ext in FRAGMENTS:
        assert f"skip{ext}" not in names
    assert "tests/hidden.c" not in names


def test_overlapping_patterns_scan_a_file_once_in_stable_order(tmp_path: Path) -> None:
    (tmp_path / "z.c").write_text("int z;\n", encoding="utf-8")
    nested = tmp_path / "a"
    nested.mkdir()
    (nested / "m.c").write_text("int m;\n", encoding="utf-8")
    (tmp_path / "b.c").write_text("int b;\n", encoding="utf-8")

    enumeration = enumerate_source_files(
        tmp_path,
        ["**/*.c", "*.c", "a/**/*.c"],
        exclude_patterns=[],
    )
    names = _names(tmp_path, enumeration.files)
    assert names == sorted(set(names))
    assert names == ["a/m.c", "b.c", "z.c"]
    assert len(enumeration.files) == 3


def test_default_exclude_still_drops_tests_tree(tmp_path: Path) -> None:
    (tmp_path / "keep.c").write_text("int keep;\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "drop.c").write_text("int drop;\n", encoding="utf-8")
    enumeration = enumerate_source_files(
        tmp_path,
        DEFAULT_INCLUDE_PATTERNS,
        exclude_patterns=DEFAULT_EXCLUDE_PATTERNS,
    )
    assert _names(tmp_path, enumeration.files) == ["keep.c"]


def test_explicit_include_replaces_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "keep.c").write_text(TIME_BODY, encoding="utf-8")
    (tmp_path / "drop.cpp").write_text(TIME_BODY, encoding="utf-8")
    out = tmp_path / "out.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--root",
            str(tmp_path),
            "--rules",
            str(RULES),
            "--include",
            "**/*.c",
            "--llm",
            "none",
            "--min-risk",
            "low",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output + (result.stderr or "")
    payload = json.loads(out.read_text(encoding="utf-8"))
    files = {c["file"] for c in payload["candidates"]} | {
        f["file"] for f in payload["findings"]
    }
    assert "keep.c" in files
    assert "drop.cpp" not in files
    assert payload["schema_version"] == "1.2"


def test_c_only_explicit_include_still_scans_c(tmp_path: Path) -> None:
    (tmp_path / "only.c").write_text(TIME_BODY, encoding="utf-8")
    enumeration = enumerate_source_files(tmp_path, ["**/*.c"], exclude_patterns=[])
    assert _names(tmp_path, enumeration.files) == ["only.c"]


def test_default_scan_attributes_cpp_and_records_llm_none_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "clock.cpp"
    src.write_text(CPP_BODY, encoding="utf-8")
    out = tmp_path / "out.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--root",
            str(tmp_path),
            "--rules",
            str(RULES),
            "--llm",
            "none",
            "--min-risk",
            "low",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output + (result.stderr or "")
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == PUBLIC_RESULT_SCHEMA_VERSION
    ScanResults.model_validate(payload)
    meta = payload["meta"]
    assert meta.get("llm_provider") == "none"
    assert meta.get("model") == "none"
    assert meta.get("reasoning_effort") is None

    assert payload["candidates"], "expected catalog candidates in clock.cpp"
    for candidate in payload["candidates"]:
        assert candidate["file"] == "clock.cpp"
        assert isinstance(candidate.get("line"), int)
        assert candidate.get("rule_id")
        assert candidate.get("function_id")
        assert "clock.cpp" in str(candidate["function_id"])
    summary = meta.get("candidate_summary") or {}
    assert summary.get("functions_with_candidates", 0) >= 1
    findings = payload["findings"]
    assert findings
    finding = findings[0]
    assert finding["file"] == "clock.cpp"
    assert finding.get("lines")


def test_ir_allowlist_matches_default_source_extensions() -> None:
    from tacs.python.y2038scan_fast_json_group import SRC_EXTS

    assert SRC_EXTS == set(DEFAULT_SOURCE_EXTENSIONS)
    assert ".hxx" in SRC_EXTS
    assert ".ipp" not in SRC_EXTS


def test_standalone_src_exts_fallback_matches_defaults() -> None:
    """The ImportError copy of SRC_EXTS must not drift from DEFAULT_SOURCE_EXTENSIONS."""
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "tacs"
        / "python"
        / "y2038scan_fast_json_group.py"
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fallback = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        err = node.type
        if not isinstance(err, ast.Name) or err.id != "ImportError":
            continue
        for stmt in node.body:
            if not isinstance(stmt, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == "SRC_EXTS" for t in stmt.targets):
                continue
            fallback = ast.literal_eval(stmt.value)
    assert fallback == set(DEFAULT_SOURCE_EXTENSIONS)


def test_explicit_fragment_include_does_not_catalog_scan_ipp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "frag.ipp").write_text(TIME_BODY, encoding="utf-8")
    out = tmp_path / "out.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--root",
            str(tmp_path),
            "--rules",
            str(RULES),
            "--include",
            "**/*.ipp",
            "--llm",
            "none",
            "--min-risk",
            "low",
            "--out",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output + (result.stderr or "")
    payload = json.loads(out.read_text(encoding="utf-8"))
    files = {c["file"] for c in payload["candidates"]} | {
        f["file"] for f in payload["findings"]
    }
    assert "frag.ipp" not in files
