# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

import json
import re
from pathlib import Path

import pytest

from report_renderer.core import load_findings_json, normalize_findings, sort_findings
from report_renderer.renderers import render_html, render_text


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_render_text_contains_marker_and_headers():
    _meta, findings = load_findings_json(str(FIXTURES / "typical.json"))
    normalized = normalize_findings(findings).findings
    text = render_text(normalized[:1], list_mode=False)
    assert "Finding 1 of 1" in text
    assert "Rule: TIME_T_TRUNCATION" in text
    assert ">>>" in text


def test_render_html_contains_controls_and_cards():
    _meta, findings = load_findings_json(str(FIXTURES / "typical.json"))
    normalized = normalize_findings(findings).findings
    html = render_html(normalized, title="Test Report", group_by="file")
    assert "<!doctype html>" in html.lower()
    assert 'id="q"' in html
    assert "Finding 1:" in html


def test_snippet_line_numbers_use_function_id_start():
    # If source_snippet is the full function body, its first line is at the
    # function_id start line, not necessarily region.start_line (focus line).
    raw = {
        "findings": [
            {
                "file": "file.c",
                "region": {"start_line": 102, "end_line": 102},
                "lines": [102],
                "function_id": "file.c@fn:100-105",
                "source_snippet": "L1\nL2\nL3\nL4\nL5\nL6\n",
                "y2038_issue": "yes",
                "severity": "medium",
                "confidence": 0.8,
                "reason": "test",
            }
        ]
    }

    from report_renderer.core import normalize_findings

    normalized = normalize_findings(raw["findings"]).findings[0]
    assert normalized.snippet_lines[0].line_no == 100
    assert normalized.snippet_lines[2].line_no == 102
    assert normalized.snippet_lines[2].is_affected


# --- cards and their data must describe the same finding --------------------


def _mixed_findings():
    """Findings whose file, rule, confidence and line orders all disagree.

    Sorting by file gives a, b, c; by confidence b, c, a; by line c, b, a; and
    grouping by rule gives b, c, a. Any combination that pairs cards with data
    by position therefore has a chance to pair the wrong ones.
    """
    raw = [
        {
            "file": "a.c",
            "region": {"start_line": 30, "end_line": 30},
            "lines": [30],
            "rule_id": "ZZZ_RULE",
            "source_snippet": "time_t a;\n",
            "y2038_issue": "no",
            "severity": "low",
            "confidence": 0.20,
            "reason": "a reason",
        },
        {
            "file": "b.c",
            "region": {"start_line": 20, "end_line": 20},
            "lines": [20],
            "rule_id": "AAA_RULE",
            "source_snippet": "time_t b;\n",
            "y2038_issue": "yes",
            "severity": "high",
            "confidence": 0.90,
            "reason": "b reason",
        },
        {
            "file": "c.c",
            "region": {"start_line": 10, "end_line": 10},
            "lines": [10],
            "rule_id": "MMM_RULE",
            "source_snippet": "time_t c;\n",
            "y2038_issue": "abstain",
            "severity": "medium",
            "confidence": 0.50,
            "reason": "c reason",
        },
    ]
    return normalize_findings(raw).findings


def _cards_and_data(html_text: str):
    """The finding index on each card, in page order, and the embedded data."""
    card_indexes = [
        int(m) for m in re.findall(r'data-finding-index="(\d+)"', html_text)
    ]
    payload = re.search(
        r'<script id="findings-data" type="application/json">(.*?)</script>',
        html_text,
        re.DOTALL,
    )
    assert payload is not None, "findings data element missing"
    return card_indexes, json.loads(payload.group(1))


@pytest.mark.parametrize("sort_key", ["file", "confidence", "risk", "line"])
@pytest.mark.parametrize("group_by", ["file", "rule", "none"])
def test_every_card_is_paired_with_its_own_finding(sort_key, group_by):
    """Grouping reorders cards; the filter must still act on the right one.

    With --sort confidence --group-by file, or any grouping by rule, the
    rendered order differs from the sorted order. Pairing card and data by
    position there filters the wrong findings in and out of view.
    """
    findings = sort_findings(_mixed_findings(), sort_key)
    html_text = render_html(findings, title="Order", group_by=group_by)

    card_indexes, data = _cards_and_data(html_text)
    by_index = {f["index"]: f for f in data}

    assert len(card_indexes) == len(findings)
    assert set(card_indexes) == set(by_index), "a card names a finding not in the data"

    # Each card's summary carries the file and rule of the finding it claims.
    cards = re.findall(r'data-finding-index="\d+".*?</details>', html_text, re.DOTALL)
    for index, card_html in zip(card_indexes, cards):
        finding = by_index[int(index)]
        assert finding["file_path"] in card_html
        assert finding["rule_id"] in card_html


@pytest.mark.parametrize("sort_key", ["file", "confidence", "line"])
@pytest.mark.parametrize("group_by", ["file", "rule", "none"])
def test_data_array_follows_the_rendered_order(sort_key, group_by):
    """Keep the array in card order so position and index cannot disagree."""
    findings = sort_findings(_mixed_findings(), sort_key)
    html_text = render_html(findings, title="Order", group_by=group_by)

    card_indexes, data = _cards_and_data(html_text)

    assert [f["index"] for f in data] == card_indexes


def test_filter_script_looks_findings_up_by_index():
    """Position pairing is the bug this guards; keep the lookup explicit."""
    findings = sort_findings(_mixed_findings(), "confidence")
    html_text = render_html(findings, title="Order", group_by="rule")

    assert "byIndex.get(Number(card.dataset.findingIndex))" in html_text
    assert "const f = data[i]" not in html_text
