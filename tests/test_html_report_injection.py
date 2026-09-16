# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for untrusted content embedded in HTML reports.

A findings file describes a repository TACS did not write: file paths, rule ids,
and model-written reasons all originate outside the tool. The HTML report embeds
some of those values in a script element for its filter UI, where JSON escaping
alone does not neutralize ``</script>`` -- it ends the element early and the rest
of the value is parsed as markup. These tests open the generated report the way a
browser would and assert nothing escapes the data block.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from report_renderer.core import normalize_findings
from report_renderer.renderers import render_html
from tacs.cli import app

BREAKOUT = "</script><script>alert('xss')</script>"


def _finding(**overrides) -> dict:
    finding = {
        "file": "src/time_helpers.c",
        "region": {"start_line": 10, "end_line": 20},
        "lines": [12],
        "symbol": "convert_stamp",
        "confidence": 0.9,
        "reason": "time_t assigned to a 32-bit int",
        "rule_id": "TIME_T_TRUNCATION",
        "y2038_issue": "yes",
    }
    finding.update(overrides)
    return finding


def _render(*findings: dict) -> str:
    return render_html(
        normalize_findings(list(findings)).findings, title="t", group_by="none"
    )


def _data_island(document: str) -> list[dict]:
    """Parse the report's embedded findings data the way the page itself does."""
    match = re.search(
        r'<script id="findings-data" type="application/json">(.*?)</script>',
        document,
        re.S,
    )
    assert match, "report must carry its findings in a JSON data element"
    return json.loads(match.group(1))


@pytest.mark.parametrize(
    "field",
    ["file", "reason"],
)
def test_breakout_payload_cannot_close_the_script_element(field: str) -> None:
    """A literal </script> in untrusted input must not end the data block."""
    document = _render(_finding(**{field: f"payload{BREAKOUT}"}))

    # One executable script (the report's own) plus one JSON data element. The
    # payload text still appears, escaped, as data -- it just cannot run.
    assert document.count("<script>") == 1
    assert document.count("</script>") == 2
    assert "<script>alert(" not in document


def test_breakout_payload_survives_as_data() -> None:
    """Escaping must not corrupt the value the filter UI reads."""
    hostile_path = f"src/evil{BREAKOUT}.c"
    hostile_reason = f"looks unsafe {BREAKOUT}"
    document = _render(_finding(file=hostile_path, reason=hostile_reason))

    data = _data_island(document)
    assert data[0]["file_path"] == hostile_path
    assert data[0]["reason_short"] == hostile_reason
    assert "</script>" in data[0]["reason_short"]


def test_angle_brackets_and_ampersands_are_escaped_in_the_payload() -> None:
    """The raw characters that can start markup never reach the document."""
    document = _render(_finding(file="a<b>&c.c", reason="x < y && y > z"))

    island = re.search(
        r'<script id="findings-data" type="application/json">(.*?)</script>',
        document,
        re.S,
    ).group(1)
    for char in ("<", ">", "&"):
        assert char not in island, f"unescaped {char!r} in embedded JSON"
    assert "\\u003c" in island

    data = json.loads(island)
    assert data[0]["file_path"] == "a<b>&c.c"
    assert data[0]["reason_short"] == "x < y && y > z"


def test_html_comment_payload_cannot_open_a_comment() -> None:
    """<!-- inside a script element would swallow the code that follows it."""
    document = _render(_finding(reason="<!--"))

    island = re.search(
        r'<script id="findings-data" type="application/json">(.*?)</script>',
        document,
        re.S,
    ).group(1)
    assert "<!--" not in island


def test_visible_report_body_escapes_untrusted_values() -> None:
    """The rendered cards escape the same values they display."""
    document = _render(_finding(file=f"src/evil{BREAKOUT}.c", reason=f"bad {BREAKOUT}"))

    body = document.split('<script id="findings-data"', 1)[0]
    assert "<script>" not in body
    assert "&lt;/script&gt;" in body


def test_rendered_html_file_is_not_injectable(tmp_path: Path) -> None:
    """End to end through tacs render: a hostile findings file stays inert."""
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(
        json.dumps(
            {
                "meta": {"root": str(tmp_path)},
                "findings": [
                    _finding(file=f"src/evil{BREAKOUT}.c", reason=f"bad {BREAKOUT}")
                ],
            }
        ),
        encoding="utf-8",
    )
    report = tmp_path / "report.html"

    result = CliRunner().invoke(
        app,
        ["render", str(findings_file), "--format", "html", "--out", str(report)],
    )
    assert result.exit_code == 0, result.output

    document = report.read_text(encoding="utf-8")
    assert document.count("<script>") == 1
    assert "<script>alert(" not in document
    assert _data_island(document)[0]["file_path"] == f"src/evil{BREAKOUT}.c"
