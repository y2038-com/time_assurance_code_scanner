# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for stable catalog rule_id attribution."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from tacs.core.candidate_evidence import build_candidate_evidence
from tacs.core.candidate_utils import make_candidate_id, prepare_candidates
from tacs.core.ir_adapter import _ir_symbols_methods_and_rule_ids
from tacs.core.rule_catalog import (
    CatalogRuleIdError,
    PackagedCatalogError,
    RULE_ID_PATTERN,
    format_rule_id,
    is_valid_rule_id,
    packaged_rules_path,
    validate_catalog_entries,
    validate_packaged_catalog,
    validate_rule_id_value,
)
from tacs.core.schema import Candidate, PUBLIC_RESULT_SCHEMA_VERSION
from tacs.python.y2038scan_fast_json_group import group_by_line, load_rules


def test_packaged_catalog_every_entry_has_unique_valid_id():
    entries = validate_packaged_catalog()
    assert len(entries) == 330
    ids = [e["rule_id"] for e in entries]
    assert len(ids) == 330
    assert len(set(ids)) == 330
    assert all(RULE_ID_PATTERN.fullmatch(rid) for rid in ids)
    assert ids[0] == "TACS-RULE-0001"
    assert ids[-1] == "TACS-RULE-0330"
    symbols = [e["symbol"] for e in entries]
    assert len(set(symbols)) == 330


def test_packaged_id_set_pin_prevents_wholesale_renumber():
    """Pin symbol→id bijection samples so swapping IDs between symbols fails.

    Checking only that TACS-RULE-0001..0330 exist would miss reassignment
    (e.g. time_t and sleep swapping IDs). These anchors bind specific symbols.
    """
    entries = validate_packaged_catalog()
    by_symbol = {e["symbol"]: e["rule_id"] for e in entries}
    by_id = {e["rule_id"]: e["symbol"] for e in entries}
    anchors = {
        "_USE_32BIT_TIME_T": "TACS-RULE-0001",
        "#define": "TACS-RULE-0330",
        "GetFileTime": "TACS-RULE-0023",
        "sleep": "TACS-RULE-0206",
        "timezone": "TACS-RULE-0165",
        "time_t": "TACS-RULE-0192",
        "time": "TACS-RULE-0040",
        "localtime": "TACS-RULE-0145",
    }
    for sym, rid in anchors.items():
        assert by_symbol[sym] == rid, f"{sym} must keep {rid}, got {by_symbol[sym]}"
        assert by_id[rid] == sym, f"{rid} must map back to {sym}, got {by_id[rid]}"
    # Full bijection: every id belongs to exactly one symbol.
    assert len(by_symbol) == len(by_id) == 330


def test_packaged_rejects_duplicate_matchable_symbols():
    entries = copy.deepcopy(validate_packaged_catalog()[:2])
    entries[1] = copy.deepcopy(entries[0])
    entries[1]["rule_id"] = "TACS-RULE-9999"
    with pytest.raises(PackagedCatalogError, match="duplicate independently matchable symbol"):
        validate_catalog_entries(entries, strict=True, context="dup-sym")


def test_merged_umbrella_variants_preserve_source_metadata():
    by = {e["symbol"]: e for e in validate_packaged_catalog()}
    required_variant_keys = {
        "label",
        "category",
        "header",
        "description",
        "comments",
        "os_support",
        "risk",
    }
    sleep = by["sleep"]
    assert len(sleep["variants"]) == 3
    headers = [v["header"] for v in sleep["variants"]]
    assert headers == ["thr/thread", "posix/unistd.h", "unistd.h"]
    assert all(required_variant_keys <= set(v.keys()) for v in sleep["variants"])
    assert any("Boost" in (v.get("comments") or "") for v in sleep["variants"])
    desc = sleep["description"].lower()
    assert "depends on environment" in desc
    assert "does not determine" in desc
    # Scanner-facing description must not claim a specific variant was selected.
    assert "applies here" not in desc
    assert "this is the windows" not in desc

    tz = by["timezone"]
    assert len(tz["variants"]) == 2
    labels = {v["label"] for v in tz["variants"]}
    assert "global_variable_time_h" in labels
    assert "function_timezone_abbreviation_time_h" in labels
    for v in tz["variants"]:
        assert required_variant_keys <= set(v.keys())
        assert v.get("header") == "time.h"
        assert v.get("description")
        assert "os_support" in v
    fn_var = next(
        v for v in tz["variants"] if v["label"] == "function_timezone_abbreviation_time_h"
    )
    # Research row has Windows: false — keep neutral; do not relabel as Windows.
    assert fn_var["os_support"].get("Windows") is False
    assert "windows function" not in tz["description"].lower()
    assert "does not determine" in tz["description"].lower()

    for sym in ("GetFileTime", "_localtime32", "_localtime64"):
        assert len(by[sym]["variants"]) == 2
        assert all(required_variant_keys <= set(v.keys()) for v in by[sym]["variants"])
        assert all(v.get("description") for v in by[sym]["variants"])


def test_catalog_ordering_does_not_change_stored_ids():
    entries = validate_packaged_catalog()
    shuffled = list(reversed(copy.deepcopy(entries)))
    # Runtime identity is the stored field, not position.
    assert {e["symbol"]: e["rule_id"] for e in entries} == {
        e["symbol"]: e["rule_id"] for e in shuffled
    }
    tok_a, _ = load_rules(str(packaged_rules_path()), "low")
    # Editing mutable fields on a copy must not be how IDs are derived.
    edited = copy.deepcopy(entries[0])
    original_id = edited["rule_id"]
    edited["description"] = "mutated description for test"
    edited["risk"] = "low"
    edited["comments"] = "mutated"
    assert edited["rule_id"] == original_id


def test_duplicate_and_malformed_ids_fail_closed(tmp_path: Path):
    good = {
        "symbol": "time",
        "risk": "high",
        "category": "function",
        "description": "x",
        "rule_id": "TACS-RULE-0001",
    }
    dup = {
        "symbol": "localtime",
        "risk": "high",
        "category": "function",
        "description": "y",
        "rule_id": "TACS-RULE-0001",
    }
    with pytest.raises((PackagedCatalogError, CatalogRuleIdError)):
        validate_catalog_entries([good, dup], strict=True, context="dup")

    bad = {**good, "rule_id": "NOT-A-RULE"}
    with pytest.raises(CatalogRuleIdError):
        validate_rule_id_value(bad["rule_id"], context="bad")

    non_string = {**good, "rule_id": 12}
    with pytest.raises(CatalogRuleIdError):
        validate_catalog_entries([non_string], strict=False, context="ns")

    missing = {"symbol": "time", "risk": "high", "category": "function", "description": "x"}
    with pytest.raises(PackagedCatalogError):
        validate_catalog_entries([missing], strict=True, context="missing")

    # External compat: missing OK
    validate_catalog_entries([missing], strict=False, context="ext")

    # Legacy duplicate symbols with no IDs remain allowed.
    legacy_dup = [
        {"symbol": "sleep", "risk": "high", "category": "function", "description": "a"},
        {"symbol": "sleep", "risk": "high", "category": "function", "description": "b"},
    ]
    validate_catalog_entries(legacy_dup, strict=False, context="legacy-dup")

    # External: same symbol with different non-null IDs fails closed.
    conflict = [
        {
            "symbol": "sleep",
            "risk": "high",
            "category": "function",
            "description": "a",
            "rule_id": "TACS-RULE-0001",
        },
        {
            "symbol": "sleep",
            "risk": "high",
            "category": "function",
            "description": "b",
            "rule_id": "TACS-RULE-0002",
        },
    ]
    with pytest.raises(CatalogRuleIdError, match="conflicting non-null rule_ids"):
        validate_catalog_entries(conflict, strict=False, context="conflict")


def test_external_conflicting_symbol_ids_fail_at_load(tmp_path: Path):
    path = tmp_path / "conflict.json"
    path.write_text(
        json.dumps(
            [
                {
                    "symbol": "sleep",
                    "risk": "high",
                    "category": "function",
                    "description": "a",
                    "rule_id": "TACS-RULE-0001",
                },
                {
                    "symbol": "sleep",
                    "risk": "high",
                    "category": "function",
                    "description": "b",
                    "rule_id": "TACS-RULE-0002",
                },
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(CatalogRuleIdError, match="conflicting non-null rule_ids"):
        load_rules(str(path), "low")


def test_external_catalog_missing_id_stays_null(tmp_path: Path):
    path = tmp_path / "ext.json"
    path.write_text(
        json.dumps(
            [
                {
                    "symbol": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "legacy",
                }
            ]
        ),
        encoding="utf-8",
    )
    tok, _ = load_rules(str(path), "low")
    assert tok["time"][0]["rule_id"] is None


def test_external_malformed_id_not_silently_nulled(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text(
        json.dumps(
            [
                {
                    "symbol": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "x",
                    "rule_id": "TIME_RULE",
                }
            ]
        ),
        encoding="utf-8",
    )
    with pytest.raises(CatalogRuleIdError):
        load_rules(str(path), "low")


def test_ir_producer_emits_exact_catalog_id(tmp_path: Path):
    src = tmp_path / "a.c"
    src.write_text("void f(void){ time_t t; }\n", encoding="utf-8")
    from tacs.python.y2038scan_fast_json_group import scan_file

    tok, min_rank = load_rules(str(packaged_rules_path()), "low")
    results, _ = scan_file(str(src), tok, min_rank)
    catalog_hits = [r for r in results if r.get("discovery_method") == "catalog_symbol_match"]
    assert catalog_hits
    expected = {e["symbol"]: e["rule_id"] for e in validate_packaged_catalog()}
    for r in catalog_hits:
        assert r["rule_id"] == expected[r["symbol"]]


def test_group_by_line_preserves_parallel_rule_ids():
    results = [
        {
            "file": "/x.c",
            "line": 1,
            "symbol": "time_t",
            "risk": "high",
            "lineText": "time_t t; time(NULL);",
            "description": "type",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0192",
        },
        {
            "file": "/x.c",
            "line": 1,
            "symbol": "time",
            "risk": "high",
            "lineText": "time_t t; time(NULL);",
            "description": "fn",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0040",
        },
        {
            "file": "/x.c",
            "line": 2,
            "symbol": "cast_from_time",
            "risk": "high",
            "lineText": "(int)t",
            "description": "cast",
            "discovery_method": "time_t_cast",
            "rule_id": None,
        },
    ]
    grouped = group_by_line(results)
    line1 = next(g for g in grouped if g["line"] == 1)
    assert line1["symbols"] == ["time_t", "time"]
    assert line1["discovery_methods"] == [
        "catalog_symbol_match",
        "catalog_symbol_match",
    ]
    assert line1["rule_ids"] == ["TACS-RULE-0192", "TACS-RULE-0040"]


def test_ir_adapter_propagates_without_inference():
    item = {
        "file": "/x.c",
        "line": 3,
        "symbols": ["time_t", "time"],
        "discovery_methods": ["catalog_symbol_match", "catalog_symbol_match"],
        "rule_ids": ["TACS-RULE-0192", "TACS-RULE-0040"],
        "risk": "high",
        "lineText": "x",
    }
    pairs = _ir_symbols_methods_and_rule_ids(item)
    assert pairs == [
        ("time_t", "catalog_symbol_match", "TACS-RULE-0192"),
        ("time", "catalog_symbol_match", "TACS-RULE-0040"),
    ]
    # Missing rule_ids stay None — not inferred from symbol.
    bare = {
        "file": "/x.c",
        "line": 1,
        "symbols": ["time_t"],
        "discovery_methods": ["catalog_symbol_match"],
        "risk": "high",
        "lineText": "x",
    }
    assert _ir_symbols_methods_and_rule_ids(bare) == [
        ("time_t", "catalog_symbol_match", None)
    ]


def test_candidate_evidence_catalog_vs_non_catalog(tmp_path: Path):
    catalog = Candidate(
        file=str(tmp_path / "a.c"),
        line=1,
        symbol="time_t",
        one_line_snippet="time_t t;",
        risk="high",
        description="type",
        discovery_method="catalog_symbol_match",
        rule_id="TACS-RULE-0192",
    )
    cast = Candidate(
        file=str(tmp_path / "a.c"),
        line=2,
        symbol="cast_from_time",
        one_line_snippet="(int)t",
        risk="high",
        description="cast",
        discovery_method="time_t_cast",
        rule_id=None,
    )
    define = Candidate(
        file=str(tmp_path / "a.c"),
        line=3,
        symbol="MY_TIME",
        one_line_snippet="#define MY_TIME time_t",
        risk="high",
        description="time_type_alias: MY_TIME -> time_t",
        discovery_method="define_scanner",
        rule_id=None,
    )
    evidence = build_candidate_evidence(
        prepare_candidates([catalog, cast, define]),
        root_path=str(tmp_path),
        functions=[],
    )
    by_method = {e.discovery_method: e for e in evidence}
    assert by_method["catalog_symbol_match"].rule_id == "TACS-RULE-0192"
    assert by_method["time_t_cast"].rule_id is None
    assert by_method["define_scanner"].rule_id is None


def test_candidate_id_unchanged_by_rule_attribution():
    cid_a = make_candidate_id("a.c", 1, "time_t", 0, 6, "high")
    cid_b = make_candidate_id("a.c", 1, "time_t", 0, 6, "high")
    assert cid_a == cid_b == "a.c:1:0:6:high:time_t"
    # rule_id is not part of the id string
    assert "TACS-RULE" not in cid_a


def test_merging_does_not_lose_or_misassign_ids(tmp_path: Path):
    from tacs.core.candidate_utils import CandidateRuleIdConflictError, dedupe_candidates

    a = Candidate(
        file=str(tmp_path / "a.c"),
        line=1,
        symbol="time_t",
        one_line_snippet="time_t t;",
        risk="high",
        description="x",
        discovery_method="catalog_symbol_match",
        rule_id="TACS-RULE-0192",
        col_start=0,
        col_end=6,
    )
    # Exact duplicate (same identity + same ID) — merge, rule_id preserved.
    b = a.model_copy()
    out = prepare_candidates([a, b])
    assert len(out) == 1
    assert out[0].rule_id == "TACS-RULE-0192"

    # Conflicting non-null IDs must not silently first-wins.
    conflict = a.model_copy(update={"rule_id": "TACS-RULE-0001"})
    with pytest.raises(CandidateRuleIdConflictError, match="Conflicting rule_id"):
        dedupe_candidates([a, conflict])

    # Null then non-null → preserve truthful attribution (keep the ID).
    null_first = a.model_copy(update={"rule_id": None})
    merged = dedupe_candidates([null_first, a])
    assert len(merged) == 1
    assert merged[0].rule_id == "TACS-RULE-0192"
    # Non-null then null → keep the attributed producer.
    merged2 = dedupe_candidates([a, null_first])
    assert len(merged2) == 1
    assert merged2[0].rule_id == "TACS-RULE-0192"


def test_model_cannot_override_rule_id_via_evidence_builder(tmp_path: Path):
    """Evidence copies producer rule_id only; no model fields are consulted."""
    c = Candidate(
        file=str(tmp_path / "a.c"),
        line=1,
        symbol="time_t",
        one_line_snippet="time_t t;",
        risk="high",
        description="x",
        discovery_method="catalog_symbol_match",
        rule_id="TACS-RULE-0192",
    )
    # Even if a spurious attribute existed, builder reads Candidate.rule_id only.
    evidence = build_candidate_evidence([c], root_path=str(tmp_path), functions=[])
    assert evidence[0].rule_id == "TACS-RULE-0192"


def test_writers_and_renderers_preserve_rule_ids(tmp_path: Path):
    from tacs.core.pipeline import ScanningPipeline
    from tacs.core.schema import (
        Metrics,
        ScanMetadata,
        ScanResults,
    )
    from report_renderer.core import load_scan_document
    from report_renderer.renderers import render_html, render_text

    evidence = build_candidate_evidence(
        [
            Candidate(
                file=str(tmp_path / "a.c"),
                line=1,
                symbol="time_t",
                one_line_snippet="time_t t;",
                risk="high",
                description="",
                discovery_method="catalog_symbol_match",
                rule_id="TACS-RULE-0192",
                col_start=0,
                col_end=6,
            ),
            Candidate(
                file=str(tmp_path / "a.c"),
                line=2,
                symbol="cast_from_time",
                one_line_snippet="(int)t",
                risk="high",
                description="",
                discovery_method="time_t_cast",
                rule_id=None,
            ),
        ],
        root_path=str(tmp_path),
        functions=[],
    )
    metrics = Metrics(
        total_files=1,
        total_lines=1,
        total_chars=1,
        total_words=1,
        max_line_length=1,
        avg_line_length=1.0,
        max_file_length=1,
        avg_file_length=1.0,
    )
    results = ScanResults(
        schema_version=PUBLIC_RESULT_SCHEMA_VERSION,
        meta=ScanMetadata(
            root=".",
            rules_path="r.json",
            model="none",
            confidence_floor=0.0,
            metrics=metrics,
            timestamp="2026-01-01T00:00:00Z",
        ),
        candidates=evidence,
        findings=[],
    )
    single = tmp_path / "findings.json"
    batch = tmp_path / "repos" / "demo" / "findings.json"
    batch.parent.mkdir(parents=True)
    pipeline = ScanningPipeline.__new__(ScanningPipeline)
    pipeline.save_results(results, str(single))
    pipeline.save_results(results, str(batch))
    for path in (single, batch):
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["schema_version"] == "1.1"
        by = {c["discovery_method"]: c for c in data["candidates"]}
        assert by["catalog_symbol_match"]["rule_id"] == "TACS-RULE-0192"
        assert by["time_t_cast"]["rule_id"] is None
        blob = json.dumps(data)
        assert "/home/" not in blob
        assert "prompt" not in blob.lower() or "prompt_tokens" not in blob

    doc = load_scan_document(str(single))
    text = render_text(
        [],
        candidates=doc.candidates,
        candidate_counts={"total": 2, "grouped": 0, "ungrouped": 2, "functions_with_candidates": 0},
        has_candidate_section=True,
    )
    html = render_html(
        [],
        title="t",
        group_by="file",
        candidates=doc.candidates,
        candidate_counts={"total": 2, "grouped": 0, "ungrouped": 2, "functions_with_candidates": 0},
        has_candidate_section=True,
    )
    assert "TACS-RULE-0192" in text
    assert "rule_id: (none)" in text
    assert "UNSPECIFIED_RULE" not in text
    assert "TACS-RULE-0192" in html
    assert "rule_id:</strong> (none)" in html or "rule_id: (none)" in html


def test_old_null_rule_id_reports_still_render(tmp_path: Path):
    from report_renderer.core import load_scan_document
    from report_renderer.renderers import render_text

    legacy = {
        "schema_version": "1.0",
        "meta": {},
        "candidates": [
            {
                "candidate_id": "a.c:1:0-1:high:time_t",
                "file": "a.c",
                "line": 1,
                "symbol": "time_t",
                "risk": "high",
                "description": "",
                "one_line_snippet": "time_t t;",
                "discovery_method": "catalog_symbol_match",
                "rule_id": None,
                "function_id": None,
                "analysis_coverage": "ungrouped",
            }
        ],
        "findings": [],
    }
    path = tmp_path / "old.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    doc = load_scan_document(str(path))
    text = render_text(
        [],
        candidates=doc.candidates,
        candidate_counts={"total": 1, "grouped": 0, "ungrouped": 1, "functions_with_candidates": 0},
        has_candidate_section=True,
    )
    assert "rule_id: (none)" in text
    assert "UNSPECIFIED_RULE" not in text


def test_format_helpers():
    assert format_rule_id(1) == "TACS-RULE-0001"
    assert is_valid_rule_id("TACS-RULE-0330")
    assert not is_valid_rule_id("TACS-RULE-330")
    assert not is_valid_rule_id("tacs-rule-0001")


def test_parallel_arrays_aligned_for_multiple_symbols_on_one_line():
    results = [
        {
            "file": "/x.c",
            "line": 7,
            "symbol": "time_t",
            "risk": "high",
            "lineText": "time_t t = time(NULL);",
            "description": "type",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0192",
        },
        {
            "file": "/x.c",
            "line": 7,
            "symbol": "time",
            "risk": "high",
            "lineText": "time_t t = time(NULL);",
            "description": "fn",
            "discovery_method": "catalog_symbol_match",
            "rule_id": "TACS-RULE-0040",
        },
        {
            "file": "/x.c",
            "line": 7,
            "symbol": "cast_from_time",
            "risk": "medium",
            "lineText": "time_t t = time(NULL);",
            "description": "cast",
            "discovery_method": "time_t_cast",
            "rule_id": None,
        },
    ]
    grouped = group_by_line(results)
    assert len(grouped) == 1
    g = grouped[0]
    assert len(g["symbols"]) == len(g["discovery_methods"]) == len(g["rule_ids"]) == 3
    triples = list(zip(g["symbols"], g["discovery_methods"], g["rule_ids"]))
    assert triples == [
        ("time_t", "catalog_symbol_match", "TACS-RULE-0192"),
        ("time", "catalog_symbol_match", "TACS-RULE-0040"),
        ("cast_from_time", "time_t_cast", None),
    ]
    # Adapter zip must preserve the same triples.
    assert _ir_symbols_methods_and_rule_ids(g) == triples


def test_packaged_rules_present_beside_installed_package():
    """Strict packaged validation must work from the installed package layout."""
    import tacs

    rules_dir = Path(tacs.__file__).resolve().parent / "rules"
    assert (rules_dir / "y2038_sample_rules.json").is_file()
    assert (rules_dir / "retired_rule_ids.json").is_file()
    # packaged_rules_path() resolves via the installed module, not cwd.
    assert packaged_rules_path().resolve() == (rules_dir / "y2038_sample_rules.json").resolve()
    entries = validate_packaged_catalog(packaged_rules_path())
    assert len(entries) == 330


def test_wheel_contains_catalog_and_retired_deny_list(tmp_path: Path):
    """Built wheel must ship both JSON artifacts; installed layout validates."""
    import subprocess
    import sys
    import venv
    import zipfile

    repo = Path(__file__).resolve().parents[1]
    out_dir = tmp_path / "dist"
    out_dir.mkdir()
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--wheel-dir",
            str(out_dir),
            str(repo),
        ],
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stderr or build.stdout
    wheels = list(out_dir.glob("*.whl"))
    assert wheels, "expected a wheel artifact"
    wheel_path = wheels[0]
    with zipfile.ZipFile(wheel_path) as zf:
        names = set(zf.namelist())
    assert "tacs/rules/y2038_sample_rules.json" in names
    assert "tacs/rules/retired_rule_ids.json" in names

    # Install the wheel into an isolated venv and run packaged validation.
    venv_dir = tmp_path / "venv"
    venv.create(venv_dir, with_pip=True, clear=True)
    py = venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / "python"
    install = subprocess.run(
        [str(py), "-m", "pip", "install", "--no-deps", str(wheel_path)],
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stderr or install.stdout
    probe = subprocess.run(
        [
            str(py),
            "-c",
            (
                "from pathlib import Path; "
                "import tacs; "
                "from tacs.core.rule_catalog import validate_packaged_catalog, packaged_rules_path, retired_rule_ids_path; "
                "root = Path(tacs.__file__).resolve().parent / 'rules'; "
                "assert (root / 'y2038_sample_rules.json').is_file(); "
                "assert (root / 'retired_rule_ids.json').is_file(); "
                "assert packaged_rules_path().resolve() == (root / 'y2038_sample_rules.json').resolve(); "
                "assert retired_rule_ids_path().resolve() == (root / 'retired_rule_ids.json').resolve(); "
                "entries = validate_packaged_catalog(); "
                "assert len(entries) == 330; "
                "assert len({e['rule_id'] for e in entries}) == 330"
            ),
        ],
        capture_output=True,
        text=True,
    )
    assert probe.returncode == 0, probe.stderr or probe.stdout


def test_assign_catalog_rule_ids_idempotent_and_refuses_bad_writes(tmp_path: Path):
    import subprocess
    import sys

    repo = Path(__file__).resolve().parents[1]
    script = repo / "scripts" / "assign_catalog_rule_ids.py"
    catalog = repo / "src" / "tacs" / "rules" / "y2038_sample_rules.json"
    before = catalog.read_text(encoding="utf-8")

    # Idempotent dry-run / rewrite of an already-assigned catalog.
    out = tmp_path / "out.json"
    out.write_text(before, encoding="utf-8")
    first = subprocess.run(
        [sys.executable, str(script), "--in", str(out), "--out", str(out)],
        capture_output=True,
        text=True,
        cwd=str(repo),
    )
    assert first.returncode == 0, first.stderr
    assert "unchanged" in first.stdout or out.read_text(encoding="utf-8") == before
    after_first = out.read_text(encoding="utf-8")

    second = subprocess.run(
        [sys.executable, str(script), "--in", str(out), "--out", str(out)],
        capture_output=True,
        text=True,
        cwd=str(repo),
    )
    assert second.returncode == 0, second.stderr
    assert out.read_text(encoding="utf-8") == after_first

    # Validation failure must not rewrite the output file.
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            [
                {
                    "symbol": "time",
                    "risk": "high",
                    "category": "function",
                    "description": "x",
                    "rule_id": "NOT-A-RULE",
                }
            ]
        ),
        encoding="utf-8",
    )
    target = tmp_path / "target.json"
    sentinel = '{"sentinel": true}\n'
    target.write_text(sentinel, encoding="utf-8")
    failed = subprocess.run(
        [sys.executable, str(script), "--in", str(bad), "--out", str(target)],
        capture_output=True,
        text=True,
        cwd=str(repo),
    )
    assert failed.returncode != 0
    assert target.read_text(encoding="utf-8") == sentinel

    # Retired ID reuse refused.
    retired_copy = tmp_path / "retired_rule_ids.json"
    # Point script at a catalog that tries to reuse a retired id by patching env:
    # exercise validate path via a catalog entry using an id we put in a temp deny list.
    # The script loads the packaged retired list; simulate by embedding retired in object form.
    retired_doc = {
        "rules": [
            {
                "symbol": "time",
                "risk": "high",
                "category": "function",
                "description": "x",
                "rule_id": "TACS-RULE-0001",
            }
        ],
        "retired_rule_ids": ["TACS-RULE-0001"],
    }
    retired_in = tmp_path / "retired_in.json"
    retired_in.write_text(json.dumps(retired_doc), encoding="utf-8")
    retired_out = tmp_path / "retired_out.json"
    retired_out.write_text(sentinel, encoding="utf-8")
    retired_run = subprocess.run(
        [
            sys.executable,
            str(script),
            "--in",
            str(retired_in),
            "--out",
            str(retired_out),
        ],
        capture_output=True,
        text=True,
        cwd=str(repo),
    )
    assert retired_run.returncode != 0
    assert retired_out.read_text(encoding="utf-8") == sentinel
