"""Output renderers for normalized findings."""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict
from pathlib import Path

from report_renderer.core import NormalizedFinding


def render_text(findings: list[NormalizedFinding], *, list_mode: bool = False) -> str:
    """Render findings as readable CLI text."""
    if not findings:
        return "No findings match the selected filters."

    total = len(findings)
    if list_mode:
        lines = []
        for f in findings:
            issue_display = _display_issue_class(f)
            confidence = f"{f.confidence:.2f}" if f.confidence is not None else "N/A"
            line_range = (
                f"{f.start_line}-{f.end_line}"
                if f.start_line is not None and f.end_line is not None and f.start_line != f.end_line
                else str(f.start_line or "N/A")
            )
            lines.append(
                f"[{f.index:>3}] {issue_display:>11} {f.risk:>8} {confidence:>5} "
                f"{f.file_path}:{line_range} {f.rule_id}"
            )
        return "\n".join(lines)

    blocks = [_render_text_finding(f, total=total) for f in findings]
    return "\n\n".join(blocks)


def render_html(findings: list[NormalizedFinding], *, title: str, group_by: str) -> str:
    """Render findings as a standalone HTML report."""
    stats = Counter(f.issue_class for f in findings)
    risk_stats = Counter(f.risk for f in findings)
    grouped = _group_findings(findings, group_by)
    payload = json.dumps([_finding_to_json(f) for f in findings])

    sections = []
    for group_name, group_items in grouped:
        cards = []
        for f in group_items:
            cards.append(_render_finding_card(f))
        sections.append(
            f"""
            <section class="group">
              <h2>{html.escape(group_name)}</h2>
              {''.join(cards)}
            </section>
            """
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
      <div class="meta">Total findings: {len(findings)}</div>
    </div>
    <div class="stats">
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
    {''.join(sections)}
  </div>
</main>
<script>
const data = {payload};
const cards = [...document.querySelectorAll('.card')];
let currentIdx = 0;
function applyFilter() {{
  const q = document.getElementById('q').value.toLowerCase();
  const issue = document.getElementById('issue').value;
  const minConfRaw = document.getElementById('minConf').value;
  const minConf = minConfRaw === '' ? null : Number(minConfRaw);
  cards.forEach((card, i) => {{
    const f = data[i];
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


def _group_findings(findings: list[NormalizedFinding], group_by: str) -> list[tuple[str, list[NormalizedFinding]]]:
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
      <details class="card" id="finding-{f.index}">
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
