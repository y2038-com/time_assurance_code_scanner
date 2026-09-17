# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

import sys
from pathlib import Path

# Ensure repo root is on import path for `scanner.*`
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tacs.core.pipeline import ScanningPipeline
from tacs.core.schema import Finding, Y2038Issue


def _mk_finding(*, y2038_issue: Y2038Issue, y2106_issue=None) -> Finding:
    return Finding(
        file="src/foo.c",
        region={"start_line": 10, "end_line": 10},
        lines=[10],
        symbol="fn",
        confidence=0.9,
        reason="test reason",
        source_snippet="int x = 0;",
        y2038_issue=y2038_issue,
        needs_more_context=False,
        y2106_issue=y2106_issue,
    )


def test_excludes_no_by_default():
    dummy = SimpleNamespace(include_no_findings=False, detect_y2106=False)
    f_yes = _mk_finding(y2038_issue=Y2038Issue.YES)
    f_no = _mk_finding(y2038_issue=Y2038Issue.NO)

    kept = ScanningPipeline._filter_findings_for_output(dummy, [f_yes, f_no])
    assert len(kept) == 1
    assert kept[0].y2038_issue == Y2038Issue.YES


def test_includes_no_when_flag_set():
    dummy = SimpleNamespace(include_no_findings=True, detect_y2106=False)
    f_yes = _mk_finding(y2038_issue=Y2038Issue.YES)
    f_no = _mk_finding(y2038_issue=Y2038Issue.NO)

    kept = ScanningPipeline._filter_findings_for_output(dummy, [f_yes, f_no])
    assert len(kept) == 2


def test_keep_y2106_yes_even_if_y2038_no():
    dummy = SimpleNamespace(include_no_findings=False, detect_y2106=True)
    f_issue = _mk_finding(y2038_issue=Y2038Issue.NO, y2106_issue=Y2038Issue.YES)
    f_safe = _mk_finding(y2038_issue=Y2038Issue.NO, y2106_issue=Y2038Issue.NO)

    kept = ScanningPipeline._filter_findings_for_output(dummy, [f_issue, f_safe])
    assert len(kept) == 1
    assert kept[0].y2038_issue == Y2038Issue.NO
    assert kept[0].y2106_issue == Y2038Issue.YES

