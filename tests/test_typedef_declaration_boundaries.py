# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for typedef declaration-boundary scanning (issue #49).

A function-pointer typedef must close at its own semicolon. Later C++ members
such as ``bool _configured;`` must not become ``time_t`` aliases.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from tacs.core.discovery_manager import DiscoveryManager
from tacs.core.include_patterns import DEFAULT_INCLUDE_PATTERNS
from tacs.core.pipeline import ScanningPipeline
from tacs.core.typedef_scanner import (
    TypedefScanner,
    _end_of_declaration,
    alias_from_declaration,
)
from tacs.core.function_scanner import mask_non_code

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
SCANNER = REPO / "src" / "tacs" / "python" / "y2038scan_fast_json_group.py"

EXAMPLE_CLOCK = """\
typedef void(*voidFuncPtr)(void);

class ExampleClock {
public:
    time_t now() const;

private:
    bool _configured;
};
"""

COMPACT_FP = "typedef void(*voidFuncPtr)(void);"
SPACED_FP = "typedef void (*voidFuncPtr)(void);"
MULTILINE_FP = """\
typedef void
    (*voidFuncPtr)
    (void);
"""
COMMENTED_FP = """\
/* callback */ typedef void (*voidFuncPtr)(void); // end
"""
TIME_FP = "typedef time_t (*time_source_fn)(void);"
TIME_FP_PARAM = "typedef void (*time_sink_fn)(time_t);"
MULTILINE_TIME_ALIAS = """\
typedef
    time_t
    epoch_t;
"""
ANON_STRUCT = """\
typedef struct {
    int field;
    time_t timestamp;
} record_t;
"""
NAMED_STRUCT = """\
typedef struct stamp {
    time_t seconds;
} stamp_t;
"""
NAMED_UNION = """\
typedef union clock_bits {
    time_t epoch;
    unsigned long raw;
} clock_bits_t;
"""
NAMED_ENUM = """\
typedef enum mode {
    MODE_OFF,
    MODE_ON
} mode_t;
"""
LITERAL_SEMICOLONS = r"""
typedef char delim_t;
const char *msg = "time_t; _configured;";
char ch = ';';
bool _configured;
"""
ADJACENT = """\
typedef void(*voidFuncPtr)(void);
typedef time_t epoch_t;
"""
INCOMPLETE = """\
typedef void(*voidFuncPtr)(void)

class ExampleClock {
public:
    time_t now() const;
private:
    bool _configured;
};
"""


def _names(source: str, path: str = "sample.cpp") -> Dict[str, List[str]]:
    return TypedefScanner()._find_typedefs(source, path)


def _time_aliases(source: str, path: str = "sample.cpp") -> Dict[str, List[str]]:
    scanner = TypedefScanner()
    found = scanner._find_typedefs(source, path)
    return scanner.find_time_t_aliases(found)


def _decl_text(entry: str) -> str:
    parts = entry.split(":", 2)
    assert len(parts) == 3
    return parts[2].strip()


def _bounded_end(source: str) -> int:
    masked = mask_non_code(source)
    start = masked.find("typedef")
    assert start >= 0
    end = _end_of_declaration(masked, start)
    assert end is not None
    return end


def test_compact_function_pointer_ends_at_its_semicolon() -> None:
    source = COMPACT_FP + "\n\nclass Later { time_t now(); bool _configured; };\n"
    end = _bounded_end(source)
    assert source[end] == ";"
    assert source[: end + 1].strip() == COMPACT_FP
    names = _names(source)
    assert set(names) == {"voidFuncPtr"}
    assert "time_t" not in _decl_text(names["voidFuncPtr"][0])
    assert "_configured" not in names
    assert _time_aliases(source) == {}


def test_conventional_spacing_function_pointer() -> None:
    source = SPACED_FP + "\nint _configured;\n"
    names = _names(source)
    assert set(names) == {"voidFuncPtr"}
    assert alias_from_declaration(SPACED_FP) == "voidFuncPtr"
    assert _time_aliases(source) == {}


def test_multiline_function_pointer() -> None:
    source = MULTILINE_FP + "\nbool _configured;\n"
    names = _names(source)
    assert set(names) == {"voidFuncPtr"}
    assert "bool" not in _decl_text(names["voidFuncPtr"][0])
    assert _time_aliases(source) == {}


def test_comments_inside_and_around_function_pointer() -> None:
    source = COMMENTED_FP + "\n/* time_t */ bool _configured;\n"
    names = _names(source)
    assert set(names) == {"voidFuncPtr"}
    assert "_configured" not in names
    assert _time_aliases(source) == {}


def test_adjacent_typedefs_stay_separate() -> None:
    names = _names(ADJACENT)
    assert set(names) == {"voidFuncPtr", "epoch_t"}
    assert _decl_text(names["voidFuncPtr"][0]).endswith("voidFuncPtr)(void);")
    assert "epoch_t" not in _decl_text(names["voidFuncPtr"][0])
    assert set(_time_aliases(ADJACENT)) == {"epoch_t"}


def test_legitimate_multiline_time_t_alias() -> None:
    aliases = _time_aliases(MULTILINE_TIME_ALIAS)
    assert set(aliases) == {"epoch_t"}
    assert "typedef" in _decl_text(aliases["epoch_t"][0])
    assert "epoch_t" in _decl_text(aliases["epoch_t"][0])


def test_time_related_function_pointer_is_promoted() -> None:
    """Return-type ``time_t`` in a function-pointer typedef is time-related."""
    names = _names(TIME_FP)
    assert set(names) == {"time_source_fn"}
    assert set(_time_aliases(TIME_FP)) == {"time_source_fn"}


def test_function_pointer_parameter_time_t_follows_existing_policy() -> None:
    """Promotion is whole-word seed presence, including parameter types."""
    names = _names(TIME_FP_PARAM)
    assert set(names) == {"time_sink_fn"}
    assert set(_time_aliases(TIME_FP_PARAM)) == {"time_sink_fn"}


def test_non_time_function_pointer_is_not_promoted() -> None:
    assert set(_names(COMPACT_FP)) == {"voidFuncPtr"}
    assert _time_aliases(COMPACT_FP) == {}


def test_anonymous_struct_with_internal_semicolons() -> None:
    names = _names(ANON_STRUCT)
    assert set(names) == {"record_t"}
    assert "timestamp" not in names
    assert "field" not in names
    assert set(_time_aliases(ANON_STRUCT)) == {"record_t"}


def test_named_struct_union_enum() -> None:
    assert set(_names(NAMED_STRUCT)) == {"stamp_t"}
    assert set(_time_aliases(NAMED_STRUCT)) == {"stamp_t"}
    assert set(_names(NAMED_UNION)) == {"clock_bits_t"}
    assert set(_time_aliases(NAMED_UNION)) == {"clock_bits_t"}
    assert set(_names(NAMED_ENUM)) == {"mode_t"}
    assert _time_aliases(NAMED_ENUM) == {}


def test_string_and_character_literals_do_not_end_or_invent_typedefs() -> None:
    names = _names(LITERAL_SEMICOLONS)
    assert set(names) == {"delim_t"}
    assert "_configured" not in names
    assert "evil_t" not in names
    assert _time_aliases(LITERAL_SEMICOLONS) == {}


def test_later_cpp_class_does_not_supply_the_alias() -> None:
    names = _names(EXAMPLE_CLOCK)
    assert set(names) == {"voidFuncPtr"}
    assert "_configured" not in names
    aliases = _time_aliases(EXAMPLE_CLOCK)
    assert "_configured" not in aliases
    assert "voidFuncPtr" not in aliases


def test_c_function_pointer_overconsumption_is_also_prevented() -> None:
    source = (
        "typedef void(*voidFuncPtr)(void);\n"
        "time_t now(void);\n"
        "static int _configured;\n"
    )
    names = _names(source, "sample.c")
    assert set(names) == {"voidFuncPtr"}
    assert "_configured" not in names
    assert _time_aliases(source, "sample.c") == {}


def test_malformed_incomplete_typedef_fails_closed() -> None:
    names = _names(INCOMPLETE)
    assert names == {}
    assert _end_of_declaration(mask_non_code(INCOMPLETE), 0) is None
    assert _time_aliases(INCOMPLETE) == {}
    # A later valid typedef must still be found; the incomplete one must not
    # swallow the rest of the translation unit.
    source = INCOMPLETE + "\ntypedef time_t epoch_t;\n"
    found = _names(source)
    assert set(found) == {"epoch_t"}
    assert "_configured" not in found
    assert "voidFuncPtr" not in found


def test_unbalanced_braces_fail_closed_without_later_members() -> None:
    source = "typedef struct {\n    time_t timestamp;\n    bool _configured;\n"
    assert _names(source) == {}
    assert _time_aliases(source) == {}


def _run_pipeline(root: Path) -> Tuple[Dict[str, Any], Path]:
    session = root / "session"
    pipeline = ScanningPipeline(
        scanner_path=str(SCANNER),
        llm_type="none",
        model="none",
        function_first=True,
        enable_pass1=False,
        enable_io_analysis=False,
        enable_discovery=True,
    )
    results = pipeline.scan(
        root_path=str(root),
        rules_path=str(RULES),
        include_patterns=list(DEFAULT_INCLUDE_PATTERNS),
        exclude_patterns=[],
        min_risk="low",
        session_dir=str(session),
    )
    out = root / "findings.json"
    pipeline.save_results(results, str(out))
    return json.loads(out.read_text(encoding="utf-8")), session


def test_example_clock_pipeline_omits_configured_at_every_layer(tmp_path: Path) -> None:
    root = tmp_path / "clock"
    root.mkdir()
    (root / "ExampleClock.hpp").write_text(EXAMPLE_CLOCK, encoding="utf-8")
    (root / "ExampleClock.cpp").write_text(
        '#include "ExampleClock.hpp"\n'
        "time_t ExampleClock::now() const { return 0; }\n"
        "bool ExampleClock::ready() const { return _configured; }\n",
        encoding="utf-8",
    )

    data, session = _run_pipeline(root)
    report_path = session / "prescan" / "discovery_report.json"
    assert report_path.is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))

    alias_keys = set(report.get("typedef_aliases") or {})
    scoped = report.get("scoped_typedef_aliases") or {}
    scoped_names = {
        name
        for file_aliases in scoped.values()
        for name in file_aliases
    }
    assert "_configured" not in alias_keys
    assert "voidFuncPtr" not in alias_keys
    assert "_configured" not in scoped_names
    assert report["discovery_summary"]["typedef_aliases_count"] == 0

    rules_path = session / "prescan" / "rules_with_discoveries.json"
    discovered_symbols = []
    if rules_path.is_file():
        rules_payload = json.loads(rules_path.read_text(encoding="utf-8"))
        discovered_symbols = [
            r.get("symbol")
            for r in rules_payload
            if r.get("discovered")
        ]
    assert "_configured" not in discovered_symbols
    assert "voidFuncPtr" not in discovered_symbols

    candidates = data.get("candidates") or []
    configured = [c for c in candidates if c.get("symbol") == "_configured"]
    assert configured == []
    time_hits = [c for c in candidates if c.get("symbol") == "time_t"]
    assert time_hits, "legitimate time_t references must remain detectable"
    assert all(c.get("rule_id") == "TACS-RULE-0192" for c in time_hits)

    findings = data.get("findings") or []
    assert all(
        "_configured" not in ((f.get("source_snippet") or "") + (f.get("symbol") or ""))
        or f.get("symbol") != "_configured"
        for f in findings
    )
    assert not any(f.get("symbol") == "_configured" for f in findings)


def test_example_clock_discovered_rules_are_not_emitted(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    (root / "clock.hpp").write_text(EXAMPLE_CLOCK, encoding="utf-8")
    mgr = DiscoveryManager()
    per_file = mgr.typedef_scanner.scan_directory(
        str(root), list(DEFAULT_INCLUDE_PATTERNS), []
    )
    all_names = {name for mapping in per_file.values() for name in mapping}
    assert "_configured" not in all_names
    assert "voidFuncPtr" in all_names

    aliases, _macros = mgr.discover_time_aliases(
        str(root), list(DEFAULT_INCLUDE_PATTERNS), []
    )
    flat_names = {name for mapping in aliases.values() for name in mapping}
    assert "_configured" not in flat_names
    assert "voidFuncPtr" not in flat_names

    out_dir = tmp_path / "prescan"
    mgr.update_rules_with_discoveries(
        str(RULES),
        aliases,
        {},
        output_dir=str(out_dir),
        root_path=str(root),
    )
    payload = json.loads((out_dir / "rules_with_discoveries.json").read_text())
    discovered = [r for r in payload if r.get("discovered")]
    assert all(r.get("symbol") != "_configured" for r in discovered)


def test_translation_unit_scope_unchanged_with_cpp_and_c(tmp_path: Path) -> None:
    root = tmp_path / "scope"
    root.mkdir()
    (root / "owner.c").write_text(
        "#include <time.h>\n"
        "typedef time_t isolated_time_t;\n"
        "void owner(void) { isolated_time_t t = 0; (void)t; }\n",
        encoding="utf-8",
    )
    (root / "other.cpp").write_text(
        "typedef void(*voidFuncPtr)(void);\n"
        "class ExampleClock {\n"
        "public:\n"
        "    time_t now() const;\n"
        "private:\n"
        "    bool _configured;\n"
        "};\n"
        "int isolated_time_t = 0;\n"
        "void other(void) { (void)isolated_time_t; (void)_configured; }\n",
        encoding="utf-8",
    )
    data, session = _run_pipeline(root)
    report = json.loads((session / "prescan" / "discovery_report.json").read_text())
    assert "isolated_time_t" in (report.get("typedef_aliases") or {})
    assert "_configured" not in (report.get("typedef_aliases") or {})

    other_alias_hits = [
        c
        for c in data.get("candidates") or []
        if Path(str(c.get("file") or "")).name == "other.cpp"
        and c.get("symbol") == "isolated_time_t"
    ]
    assert other_alias_hits == []
    owner_hits = [
        c
        for c in data.get("candidates") or []
        if c.get("symbol") == "isolated_time_t"
    ]
    assert owner_hits
    assert all(Path(str(c["file"])).name == "owner.c" for c in owner_hits)
    assert not any(c.get("symbol") == "_configured" for c in data.get("candidates") or [])
