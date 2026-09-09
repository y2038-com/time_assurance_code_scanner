from pathlib import Path

from report_renderer.core import FindingsLoadError, apply_filters, load_findings_json, normalize_findings, sort_findings


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_load_typical_json():
    meta, findings = load_findings_json(str(FIXTURES / "typical.json"))
    assert isinstance(meta, dict)
    assert len(findings) == 2


def test_normalize_issue_type_from_issues_array():
    result = normalize_findings(
        [
            {
                "file": "a.c",
                "lines": [102],
                "region": {"start_line": 102, "end_line": 102},
                "function_id": "a.c@fn:100-105",
                "y2038_issue": "yes",
                "issues": [
                    {
                        "type": "narrowing_pattern",
                        "line": 102,
                        "description": "narrowing cast",
                    }
                ],
                "source_snippet": "L1\nL2\nL3\nL4\nL5\nL6\n",
            }
        ]
    )
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "NARROWING_PATTERN"
    assert finding.affected_lines == [102]
    assert finding.snippet_lines[0].line_no == 100
    assert finding.snippet_lines[2].line_no == 102
    assert finding.snippet_lines[2].is_affected
    assert not finding.snippet_lines[0].is_affected


def test_normalize_missing_fields():
    _meta, findings = load_findings_json(str(FIXTURES / "missing-fields.json"))
    result = normalize_findings(findings)
    assert len(result.findings) == 2
    assert result.findings[0].rule_id == "UNSPECIFIED_RULE"


def test_malformed_tolerant_vs_strict():
    _meta, findings = load_findings_json(str(FIXTURES / "malformed.json"))
    tolerant = normalize_findings(findings, strict=False)
    assert len(tolerant.findings) == 2
    assert tolerant.warnings

    try:
        normalize_findings(findings, strict=True)
    except FindingsLoadError:
        pass
    else:  # pragma: no cover - safety
        raise AssertionError("Expected strict mode to raise")


def test_filter_and_sort():
    _meta, findings = load_findings_json(str(FIXTURES / "typical.json"))
    result = normalize_findings(findings)
    only_yes = apply_filters(result.findings, only="yes", min_confidence=None, file_globs=[], rules=[])
    assert len(only_yes) == 2
    by_conf = apply_filters(result.findings, only=None, min_confidence=0.9, file_globs=[], rules=[])
    assert len(by_conf) == 1
    sorted_items = sort_findings(result.findings, "confidence")
    assert sorted_items[0].confidence >= sorted_items[1].confidence
