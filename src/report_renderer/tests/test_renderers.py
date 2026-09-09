from pathlib import Path

from report_renderer.core import load_findings_json, normalize_findings
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
