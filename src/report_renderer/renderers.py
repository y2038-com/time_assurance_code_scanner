# Copyright (c) 2026 Y2038.com LLC
# SPDX-License-Identifier: Apache-2.0

"""Output renderers for normalized findings."""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Sequence

from report_renderer.core import (
    NormalizedFinding,
    format_candidate_preservation_message,
)

# Report-level only (not repeated per finding).
_ASSURANCE_DISCLAIMER = (
    "TACS findings are review candidates, not a certification of time safety. "
    "Absence of findings does not establish absence of rollover risk."
)

_CANDIDATE_EVIDENCE_NOTE = (
    "Deterministic candidate evidence records discovery hits; they are not "
    "confirmed defects. Model assessments and compatibility findings below are "
    "separate layers."
)

_ASSESSMENT_NOTE = (
    "Model assessments record execution status and, when completed, a model "
    "verdict for each analyzed function. They do not validate or erase "
    "deterministic candidates. Compatibility findings may still use abstain "
    "for operational analysis errors; that is a legacy projection, not the "
    "assessment truth."
)


def render_text(
    findings: list[NormalizedFinding],
    *,
    list_mode: bool = False,
    candidates: Sequence[dict[str, Any]] | None = None,
    candidate_counts: dict[str, int] | None = None,
    assessments: Sequence[dict[str, Any]] | None = None,
    assessment_counts: dict[str, Any] | None = None,
    has_candidate_section: bool = False,
    has_assessment_section: bool = False,
) -> str:
    """Render findings (and optional candidates/assessments) as readable CLI text."""
    candidates = list(candidates or [])
    assessments = list(assessments or [])
    counts = candidate_counts or {}
    a_counts = assessment_counts or {}
    candidate_total = int(counts.get("total", len(candidates)))
    ungrouped = int(counts.get("ungrouped", 0))
    header_lines = [_ASSURANCE_DISCLAIMER, ""]

    if has_candidate_section:
        header_lines.append(_CANDIDATE_EVIDENCE_NOTE)
        header_lines.append(
            f"Deterministic candidates: {candidate_total} "
            f"(grouped {counts.get('grouped', 0)}, ungrouped {ungrouped}; "
            f"functions with candidates {counts.get('functions_with_candidates', 0)})"
        )
        header_lines.append("")
        msg = format_candidate_preservation_message(
            candidate_total=candidate_total,
            ungrouped=ungrouped,
            findings_shown=len(findings),
            has_candidate_section=True,
        )
        if msg:
            header_lines.append(msg)
            header_lines.append("")
        if candidates:
            header_lines.append("## Deterministic candidate evidence")
            header_lines.append("")
            for i, cand in enumerate(candidates, start=1):
                header_lines.extend(
                    _render_text_candidate(cand, index=i, total=len(candidates))
                )
                header_lines.append("")

    if has_assessment_section:
        header_lines.append(_ASSESSMENT_NOTE)
        status = a_counts.get("analysis_status") or "unknown"
        header_lines.append(
            f"Model analysis status: {status}; assessments: {a_counts.get('total', len(assessments))} "
            f"(completed {a_counts.get('completed', 0)}: "
            f"yes {a_counts.get('yes', 0)}, no {a_counts.get('no', 0)}, "
            f"abstain {a_counts.get('abstain', 0)}; "
            f"analysis_errors {a_counts.get('analysis_errors', 0)})"
        )
        header_lines.append("")
        header_lines.append("## Model assessments")
        header_lines.append("")
        if assessments:
            for i, row in enumerate(assessments, start=1):
                header_lines.extend(
                    _render_text_assessment(row, index=i, total=len(assessments))
                )
                header_lines.append("")
        else:
            header_lines.append(
                "No per-function model assessments "
                "(analysis not requested, or no eligible analysis units)."
            )
            header_lines.append("")
        header_lines.append("## Model-retained findings")
        header_lines.append("")
    elif has_candidate_section and candidates:
        header_lines.append("## Model-retained findings")
        header_lines.append("")

    if not findings:
        if has_candidate_section or has_assessment_section:
            return "\n".join(header_lines).rstrip() + "\n"
        return f"{_ASSURANCE_DISCLAIMER}\n\nNo findings match the selected filters."

    total = len(findings)
    if list_mode:
        lines = list(header_lines)
        for f in findings:
            issue_display = _display_issue_class(f)
            confidence = f"{f.confidence:.2f}" if f.confidence is not None else "N/A"
            line_range = (
                f"{f.start_line}-{f.end_line}"
                if f.start_line is not None
                and f.end_line is not None
                and f.start_line != f.end_line
                else str(f.start_line or "N/A")
            )
            lines.append(
                f"[{f.index:>3}] {issue_display:>11} {f.risk:>8} {confidence:>5} "
                f"{f.file_path}:{line_range} {f.rule_id}"
            )
        return "\n".join(lines)

    finding_blocks = [_render_text_finding(f, total=total) for f in findings]
    if has_candidate_section or has_assessment_section:
        return "\n".join(header_lines).rstrip() + "\n\n" + "\n\n".join(finding_blocks)
    return "\n\n".join([_ASSURANCE_DISCLAIMER] + finding_blocks)


def _render_text_assessment(
    row: dict[str, Any], *, index: int, total: int
) -> list[str]:
    verdict = row.get("verdict")
    verdict_display = verdict if isinstance(verdict, str) and verdict.strip() else "(none)"
    conf = row.get("confidence")
    conf_display = f"{float(conf):.2f}" if isinstance(conf, (int, float)) else "N/A"
    ids = row.get("candidate_ids") or []
    if isinstance(ids, list):
        ids_display = ", ".join(str(x) for x in ids) if ids else "(none)"
    else:
        ids_display = str(ids)
    return [
        f"Assessment {index} of {total}",
        f"assessment_id: {row.get('assessment_id') or ''}",
        f"function_id: {row.get('function_id') or ''}",
        f"execution_status: {row.get('execution_status') or ''}",
        f"verdict: {verdict_display}",
        f"confidence: {conf_display}",
        f"candidate_ids: {ids_display}",
        f"reason: {row.get('reason') or ''}",
    ]


def _render_text_candidate(
    cand: dict[str, Any], *, index: int, total: int
) -> list[str]:
    rule_id = cand.get("rule_id")
    rule_display = rule_id if isinstance(rule_id, str) and rule_id.strip() else "(none)"
    discovery = cand.get("discovery_method") or "unknown"
    coverage = cand.get("analysis_coverage") or "ungrouped"
    function_id = cand.get("function_id") or "(ungrouped)"
    snippet = str(cand.get("one_line_snippet") or "").replace("\n", " ")
    return [
        f"Candidate {index} of {total}",
        f"candidate_id: {cand.get('candidate_id') or ''}",
        f"discovery_method: {discovery}",
        f"rule_id: {rule_display}",
        f"risk: {cand.get('risk') or ''}",
        f"symbol: {cand.get('symbol') or ''}",
        f"file: {cand.get('file') or ''}",
        f"line: {cand.get('line') or ''}",
        f"analysis_coverage: {coverage}",
        f"function_id: {function_id}",
        f"snippet: {snippet}",
    ]


def _json_for_script(data: object) -> str:
    """
    Serialize data for embedding inside an HTML ``<script>`` element.

    A findings file describes an untrusted repository: file paths, rule ids, and
    model-written reasons all originate outside TACS. JSON escaping alone does
    not neutralize ``</script>``, which would end the element early and let the
    rest of the string be parsed as markup. HTML entities are no help either,
    since a script element's content is raw text and entities are not decoded
    there. ``<``, ``>``, and ``&`` are therefore written as JSON ``\\u`` escapes,
    which parse back to exactly the same string.
    """
    return (
        json.dumps(data)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def render_html(
    findings: list[NormalizedFinding],
    *,
    title: str,
    group_by: str,
    candidates: Sequence[dict[str, Any]] | None = None,
    candidate_counts: dict[str, int] | None = None,
    assessments: Sequence[dict[str, Any]] | None = None,
    assessment_counts: dict[str, Any] | None = None,
    has_candidate_section: bool = False,
    has_assessment_section: bool = False,
) -> str:
    """Render findings (and optional candidates/assessments) as a standalone HTML report."""
    candidates = list(candidates or [])
    assessments = list(assessments or [])
    counts = candidate_counts or {}
    a_counts = assessment_counts or {}
    candidate_total = int(counts.get("total", len(candidates)))
    ungrouped = int(counts.get("ungrouped", 0))
    grouped = int(counts.get("grouped", 0))
    functions_with = int(counts.get("functions_with_candidates", 0))

    stats = Counter(f.issue_class for f in findings)
    risk_stats = Counter(f.risk for f in findings)
    grouped_findings = _group_findings(findings, group_by)

    sections = []
    rendered: list[NormalizedFinding] = []
    for group_name, group_items in grouped_findings:
        cards = []
        for f in group_items:
            rendered.append(f)
            cards.append(_render_finding_card(f))
        sections.append(
            f"""
            <section class="group">
              <h2>{html.escape(group_name)}</h2>
              {''.join(cards)}
            </section>
            """
        )
    payload = _json_for_script([_finding_to_json(f) for f in rendered])
    candidates_script = ""
    if has_candidate_section:
        candidates_payload = _json_for_script(candidates)
        candidates_script = (
            f'<script id="candidates-data" type="application/json">'
            f"{candidates_payload}</script>\n"
        )
    assessments_script = ""
    if has_assessment_section:
        assessments_payload = _json_for_script(assessments)
        assessments_script = (
            f'<script id="assessments-data" type="application/json">'
            f"{assessments_payload}</script>\n"
        )

    preservation = ""
    candidate_summary_html = ""
    assessment_summary_html = ""
    candidate_section_html = ""
    assessment_section_html = ""
    findings_closing = ""
    if has_candidate_section:
        msg = format_candidate_preservation_message(
            candidate_total=candidate_total,
            ungrouped=ungrouped,
            findings_shown=len(findings),
            has_candidate_section=True,
        )
        if msg:
            preservation = (
                f'<div class="meta" style="max-width: 52rem; margin-top: 6px;">'
                f"{html.escape(msg)}</div>"
            )
        candidate_summary_html = f"""
      <div class="pill">candidates: {candidate_total}</div>
      <div class="pill">grouped: {grouped}</div>
      <div class="pill">ungrouped: {ungrouped}</div>
      <div class="pill">functions w/ candidates: {functions_with}</div>
"""
        candidate_cards = "".join(
            _render_candidate_card(c, i) for i, c in enumerate(candidates, start=1)
        )
        candidate_section_html = f"""
  <section class="group" id="deterministic-candidates">
    <h2>Deterministic candidate evidence</h2>
    <p class="meta">{html.escape(_CANDIDATE_EVIDENCE_NOTE)}</p>
    {candidate_cards or '<p class="meta">No deterministic candidates were found.</p>'}
  </section>
"""

    if has_assessment_section:
        status = str(a_counts.get("analysis_status") or "unknown")
        assessment_summary_html = f"""
      <div class="pill">analysis: {html.escape(status)}</div>
      <div class="pill">assessments: {int(a_counts.get('total', len(assessments)))}</div>
      <div class="pill">model yes: {int(a_counts.get('yes', 0))}</div>
      <div class="pill">model no: {int(a_counts.get('no', 0))}</div>
      <div class="pill">model abstain: {int(a_counts.get('abstain', 0))}</div>
      <div class="pill">analysis_errors: {int(a_counts.get('analysis_errors', 0))}</div>
"""
        assessment_cards = "".join(
            _render_assessment_card(a, i) for i, a in enumerate(assessments, start=1)
        )
        assessment_section_html = f"""
  <section class="group" id="model-assessments">
    <h2>Model assessments</h2>
    <p class="meta">{html.escape(_ASSESSMENT_NOTE)}</p>
    {assessment_cards or '<p class="meta">No per-function model assessments.</p>'}
  </section>
"""

    if has_candidate_section or has_assessment_section:
        findings_closing = "</section>"
        findings_open = """
  <section class="group">
    <h2>Model-retained findings</h2>
"""
    else:
        findings_open = ""

    empty_findings_note = ""
    if not findings and (has_candidate_section or has_assessment_section):
        empty_findings_note = (
            '<p class="meta">No model-retained findings in this view.</p>'
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{html.escape(title)}</title>
  <style>
    :root {{
      --bg: #0b1220;
      --panel: #101827;
      --muted: #9ca3af;
      --text: #e5e7eb;
      --accent: #60a5fa;
      --danger: #ef4444;
      --warn: #f59e0b;
      --ok: #10b981;
      --border: #1f2937;
      --code: #111827;
    }}
    body {{ margin: 0; background: var(--bg); color: var(--text); font: 14px/1.4 ui-sans-serif, system-ui, sans-serif; }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 18px; }}
    .top {{ display: flex; justify-content: space-between; align-items: end; gap: 12px; flex-wrap: wrap; }}
    .stats {{ display: flex; gap: 10px; flex-wrap: wrap; }}
    .pill {{ background: var(--panel); border: 1px solid var(--border); padding: 8px 10px; border-radius: 8px; }}
    .controls {{ margin: 14px 0; display: flex; gap: 8px; flex-wrap: wrap; }}
    input, select {{ background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 6px 8px; }}
    .group {{ margin: 18px 0; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 10px; overflow: hidden; }}
    .card summary {{ list-style: none; cursor: pointer; padding: 10px 12px; display: flex; justify-content: space-between; gap: 10px; }}
    .meta {{ color: var(--muted); }}
    .badge {{ border-radius: 999px; padding: 2px 8px; font-size: 12px; border: 1px solid var(--border); }}
    .badge.yes {{ background: rgba(239, 68, 68, 0.12); color: #fca5a5; }}
    .badge.no {{ background: rgba(16, 185, 129, 0.12); color: #6ee7b7; }}
    .badge.abstain {{ background: rgba(245, 158, 11, 0.12); color: #fcd34d; }}
    .badge.candidate {{ background: rgba(96, 165, 250, 0.12); color: #93c5fd; }}
    .body {{ padding: 0 12px 12px 12px; }}
    pre {{ margin: 0; background: var(--code); border: 1px solid var(--border); border-radius: 8px; padding: 10px; overflow: auto; }}
    .line {{ display: block; white-space: pre; }}
    .line.aff {{ background: rgba(96, 165, 250, 0.15); }}
    .ln {{ color: var(--muted); display: inline-block; width: 54px; }}
    .marker {{ color: var(--accent); font-weight: 700; display: inline-block; width: 24px; }}
    .nav {{ display: flex; gap: 8px; margin-top: 10px; }}
    button {{ background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 6px 8px; cursor: pointer; }}
  </style>
</head>
<body>
<main>
  <div class="top">
    <div>
      <h1 style="margin: 0;">{html.escape(title)}</h1>
      <div class="meta">Total finding records: {len(findings)}</div>
      <div class="meta" style="max-width: 52rem; margin-top: 6px;">{html.escape(_ASSURANCE_DISCLAIMER)}</div>
      {preservation}
    </div>
    <div class="stats">
      {candidate_summary_html}
      {assessment_summary_html}
      <div class="pill">yes: {stats.get('yes', 0)}</div>
      <div class="pill">no: {stats.get('no', 0)}</div>
      <div class="pill">abstain: {stats.get('abstain', 0)}</div>
      <div class="pill">high risk: {risk_stats.get('high', 0)}</div>
    </div>
  </div>
  <div class="controls">
    <input id="q" placeholder="Search file, rule, reason"/>
    <select id="issue">
      <option value="">All issue classes</option>
      <option value="yes">yes</option>
      <option value="no">no</option>
      <option value="abstain">abstain</option>
      <option value="unknown">unknown</option>
    </select>
    <input id="minConf" type="number" min="0" max="1" step="0.01" placeholder="Min confidence"/>
  </div>
  <div class="nav">
    <button id="prevBtn" type="button">Previous</button>
    <button id="nextBtn" type="button">Next</button>
  </div>
  <div id="report">
    {candidate_section_html}
    {assessment_section_html}
    {findings_open}
    {''.join(sections)}
    {empty_findings_note}
    {findings_closing}
  </div>
</main>
<script id="findings-data" type="application/json">{payload}</script>
{candidates_script}{assessments_script}<script>
// Findings data is held in a non-executable element and parsed, so the report
// never evaluates values that came from the scanned repository.
const data = JSON.parse(document.getElementById('findings-data').textContent);
// Each card names its own finding. Grouping reorders the cards, so pairing them
// with the data by position would filter the wrong findings.
const byIndex = new Map(data.map(f => [f.index, f]));
const cards = [...document.querySelectorAll('.card[data-finding-index]')];
let currentIdx = 0;
function applyFilter() {{
  const q = document.getElementById('q').value.toLowerCase();
  const issue = document.getElementById('issue').value;
  const minConfRaw = document.getElementById('minConf').value;
  const minConf = minConfRaw === '' ? null : Number(minConfRaw);
  cards.forEach(card => {{
    const f = byIndex.get(Number(card.dataset.findingIndex));
    // An unidentifiable card stays visible: hiding a finding the user cannot
    // see the reason for is worse than showing one the filter did not match.
    if (!f) {{ card.style.display = ''; return; }}
    const hay = (f.file_path + ' ' + f.rule_id + ' ' + f.reason_short).toLowerCase();
    const qOk = !q || hay.includes(q);
    const issueOk = !issue || f.issue_class === issue;
    const confOk = minConf == null || (f.confidence != null && f.confidence >= minConf);
    card.style.display = (qOk && issueOk && confOk) ? '' : 'none';
  }});
}}
function visibleCards() {{
  return cards.filter(c => c.style.display !== 'none');
}}
function focusAt(delta) {{
  const vis = visibleCards();
  if (!vis.length) return;
  currentIdx = (currentIdx + delta + vis.length) % vis.length;
  vis[currentIdx].scrollIntoView({{behavior: 'smooth', block: 'center'}});
  vis[currentIdx].open = true;
}}
document.getElementById('q').addEventListener('input', applyFilter);
document.getElementById('issue').addEventListener('change', applyFilter);
document.getElementById('minConf').addEventListener('input', applyFilter);
document.getElementById('prevBtn').addEventListener('click', () => focusAt(-1));
document.getElementById('nextBtn').addEventListener('click', () => focusAt(1));
applyFilter();
</script>
</body>
</html>
"""


def write_html_file(html_content: str, output_path: str) -> Path:
    path = Path(output_path)
    path.write_text(html_content, encoding="utf-8")
    return path


def _render_assessment_card(row: dict[str, Any], index: int) -> str:
    verdict = row.get("verdict")
    verdict_display = verdict if isinstance(verdict, str) and verdict.strip() else "(none)"
    status = str(row.get("execution_status") or "")
    function_id = str(row.get("function_id") or "")
    reason = str(row.get("reason") or "")
    conf = row.get("confidence")
    conf_display = f"{float(conf):.2f}" if isinstance(conf, (int, float)) else "N/A"
    ids = row.get("candidate_ids") or []
    ids_display = ", ".join(str(x) for x in ids) if isinstance(ids, list) and ids else "(none)"
    aid = str(row.get("assessment_id") or "")
    return f"""
      <details class="card" id="assessment-{index}">
        <summary>
          <span>
            <span class="badge candidate">assessment</span>
            Assessment {index}: {html.escape(status)} / {html.escape(verdict_display)}
          </span>
          <span class="meta">{html.escape(function_id)} | conf {html.escape(conf_display)}</span>
        </summary>
        <div class="body">
          <p><strong>assessment_id:</strong> {html.escape(aid)}</p>
          <p><strong>candidate_ids:</strong> {html.escape(ids_display)}</p>
          <p><strong>reason:</strong> {html.escape(reason)}</p>
        </div>
      </details>
    """


def _render_candidate_card(cand: dict[str, Any], index: int) -> str:
    rule_id = cand.get("rule_id")
    rule_display = rule_id if isinstance(rule_id, str) and rule_id.strip() else "(none)"
    discovery = str(cand.get("discovery_method") or "unknown")
    coverage = str(cand.get("analysis_coverage") or "ungrouped")
    function_id = str(cand.get("function_id") or "(ungrouped)")
    snippet = str(cand.get("one_line_snippet") or "")
    file_path = str(cand.get("file") or "")
    line = cand.get("line")
    symbol = str(cand.get("symbol") or "")
    risk = str(cand.get("risk") or "")
    cid = str(cand.get("candidate_id") or "")
    return f"""
      <details class="card" id="candidate-{index}">
        <summary>
          <span>
            <span class="badge candidate">candidate</span>
            Candidate {index}: {html.escape(discovery)}
          </span>
          <span class="meta">{html.escape(file_path)}:{html.escape(str(line or ''))} | {html.escape(symbol)} | {html.escape(risk)} | {html.escape(coverage)}</span>
        </summary>
        <div class="body">
          <p><strong>candidate_id:</strong> {html.escape(cid)}</p>
          <p><strong>discovery_method:</strong> {html.escape(discovery)} &nbsp; <strong>rule_id:</strong> {html.escape(rule_display)}</p>
          <p><strong>function_id:</strong> {html.escape(function_id)}</p>
          <pre>{html.escape(snippet)}</pre>
        </div>
      </details>
    """


def _render_text_finding(f: NormalizedFinding, *, total: int) -> str:
    issue_display = _display_issue_class(f)
    line_label = "Line"
    line_value = "N/A"
    if f.start_line is not None:
        line_value = str(f.start_line)
        if f.end_line is not None and f.end_line != f.start_line:
            line_label = "Lines"
            line_value = f"{f.start_line}-{f.end_line}"
    confidence = f"{f.confidence:.2f}" if f.confidence is not None else "N/A"

    lines = [
        f"Finding {f.index} of {total}",
        f"Rule: {f.rule_id}",
        f"Risk: {f.risk.title()}",
        f"File: {f.file_path}",
        f"{line_label}: {line_value}",
        f"Confidence: {confidence}",
        "",
    ]
    # Keep issue details grouped with other metadata (above the snippet).
    lines.extend(
        [
            f"Issue: {issue_display} classification for this candidate.",
            f"Why flagged: {f.why_flagged}",
            "",
        ]
    )
    for sl in f.snippet_lines:
        ln = str(sl.line_no) if sl.line_no is not None else "?"
        marker = ">>> " if sl.is_affected else "    "
        lines.append(f"{ln:>5} | {marker}{sl.text}")
    return "\n".join(lines)


def _group_findings(
    findings: list[NormalizedFinding], group_by: str
) -> list[tuple[str, list[NormalizedFinding]]]:
    if group_by == "none":
        return [("All Findings", findings)]
    buckets: dict[str, list[NormalizedFinding]] = defaultdict(list)
    for f in findings:
        key = f.rule_id if group_by == "rule" else f.file_path
        buckets[key].append(f)
    return sorted(buckets.items(), key=lambda kv: kv[0])


def _render_finding_card(f: NormalizedFinding) -> str:
    issue_display = _display_issue_class(f)
    conf = f"{f.confidence:.2f}" if f.confidence is not None else "N/A"
    lines = []
    for sl in f.snippet_lines:
        cls = "line aff" if sl.is_affected else "line"
        ln = str(sl.line_no) if sl.line_no is not None else "?"
        marker = "&gt;&gt;&gt;" if sl.is_affected else "&nbsp;&nbsp;&nbsp;"
        lines.append(
            f'<span class="{cls}"><span class="ln">{html.escape(ln)}</span>'
            f'<span class="marker">{marker}</span>{html.escape(sl.text)}</span>'
        )

    return f"""
      <details class="card" id="finding-{f.index}" data-finding-index="{f.index}">
        <summary>
          <span>
            <span class="badge {html.escape(f.issue_class)}">{html.escape(issue_display)}</span>
            Finding {f.index}: {html.escape(f.rule_id)}
          </span>
          <span class="meta">{html.escape(f.file_path)} | risk {html.escape(f.risk)} | conf {conf}</span>
        </summary>
        <div class="body">
          <p><strong>Why flagged:</strong> {html.escape(f.why_flagged)}</p>
          <pre>{''.join(lines)}</pre>
        </div>
      </details>
    """


def _finding_to_json(f: NormalizedFinding) -> dict[str, object]:
    return {
        "index": f.index,
        "file_path": f.file_path,
        "rule_id": f.rule_id,
        "reason_short": f.reason_short,
        "issue_class": _display_issue_class(f),
        "confidence": f.confidence,
    }


def _display_issue_class(f: NormalizedFinding) -> str:
    y2106_issue = f.raw.get("y2106_issue")
    if f.issue_class == "yes":
        return "yes"
    if isinstance(y2106_issue, str) and y2106_issue.strip().lower() == "yes":
        return "yes(y2106)"
    return f.issue_class
