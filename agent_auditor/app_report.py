"""HTML report generation for app-mode audit results."""
from __future__ import annotations

import html
from pathlib import Path

from .app_scanner import AppAuditReport, AppFinding

# ── Shared CSS ────────────────────────────────────────────────────────────────
_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
.container { max-width: 960px; margin: 0 auto; padding: 2rem; }
h1 { font-size: 1.8rem; color: #fff; margin-bottom: 0.25rem; }
h2 { font-size: 1.2rem; color: #fff; margin: 2rem 0 0.75rem; border-bottom: 1px solid #2a2a2a; padding-bottom: 0.5rem; }
h3 { font-size: 0.95rem; color: #c8956c; margin: 1rem 0 0.5rem; }
.subtitle { color: #888; margin-bottom: 1.5rem; font-size: 0.9rem; }
.brand { font-size: 0.75rem; color: #c8956c; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 0.5rem; }
.brand a { color: inherit; text-decoration: none; font-weight: 600; }

.page-nav { display: flex; gap: 0; margin-bottom: 2rem; border: 1px solid #2a2a2a; border-radius: 8px; overflow: hidden; }
.page-nav a { flex: 1; text-align: center; padding: 0.6rem 0.5rem; font-size: 0.8rem; text-decoration: none; color: #888; background: #111; border-right: 1px solid #2a2a2a; transition: background 0.15s; }
.page-nav a:last-child { border-right: none; }
.page-nav a.active { background: #1e1612; color: #c8956c; font-weight: 600; }
.page-nav a:hover:not(.active) { background: #151515; color: #ccc; }
.page-nav .step-num { display: block; font-size: 0.65rem; color: #555; margin-bottom: 1px; }
.page-nav a.active .step-num { color: #7a5c40; }

.hero-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
@media (max-width: 768px) { .hero-stats { grid-template-columns: 1fr 1fr; } }
.hero-stat { background: #151515; border: 1px solid #2a2a2a; border-radius: 12px; padding: 1.25rem; text-align: center; }
.hero-stat .value { font-size: 2rem; font-weight: 800; }
.hero-stat .label { font-size: 0.75rem; color: #888; margin-top: 0.25rem; }
.green { color: #4ade80; }
.yellow { color: #eab308; }
.red { color: #ef4444; }
.muted { color: #666; }

.card { background: #111; border: 1px solid #2a2a2a; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; }
.card.good { border-color: #1a3a2a; background: #0d1f16; }
.card.warn { border-color: #3a2f10; background: #1f1a08; }
.card.bad { border-color: #3a1515; background: #1f0d0d; }
.card.info-card { border-color: #1a2a3a; background: #0d1520; }

.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; font-family: monospace; margin-right: 6px; }
.badge-critical { background: rgba(239,68,68,0.2); color: #ef4444; }
.badge-high { background: rgba(251,146,60,0.2); color: #fb923c; }
.badge-medium { background: rgba(234,179,8,0.2); color: #eab308; }
.badge-low { background: rgba(96,165,250,0.2); color: #60a5fa; }
.badge-info { background: rgba(148,163,184,0.2); color: #94a3b8; }
.badge-py { background: rgba(59,130,246,0.15); color: #60a5fa; }
.badge-ts { background: rgba(49,196,141,0.15); color: #31c48d; }
.badge-mixed { background: rgba(200,149,108,0.15); color: #c8956c; }

table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-bottom: 1rem; }
th { text-align: left; padding: 0.5rem 0.75rem; color: #666; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.5px; border-bottom: 1px solid #2a2a2a; }
td { padding: 0.6rem 0.75rem; border-bottom: 1px solid #1a1a1a; vertical-align: top; color: #ccc; }
td:first-child { color: #e0e0e0; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #131313; }

pre { background: #0d0d0d; border: 1px solid #222; border-radius: 6px; padding: 0.75rem 1rem; font-size: 0.78rem; font-family: 'Consolas', 'Monaco', monospace; color: #a0a0a0; overflow-x: auto; margin: 0.5rem 0; white-space: pre; }
pre .hl { color: #ef4444; font-weight: bold; }
code { font-family: 'Consolas', 'Monaco', monospace; background: #161616; padding: 1px 5px; border-radius: 3px; font-size: 0.82em; color: #c8956c; }

.finding { border: 1px solid #2a2a2a; border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; background: #0f0f0f; }
.finding.critical { border-left: 3px solid #ef4444; }
.finding.high { border-left: 3px solid #fb923c; }
.finding.medium { border-left: 3px solid #eab308; }
.finding.low { border-left: 3px solid #60a5fa; }
.finding.info { border-left: 3px solid #555; }
.finding-title { font-weight: 600; color: #e0e0e0; font-size: 0.9rem; margin-bottom: 0.3rem; }
.finding-meta { font-size: 0.75rem; color: #666; margin-bottom: 0.5rem; font-family: monospace; }
.finding-msg { font-size: 0.85rem; color: #aaa; margin-bottom: 0.5rem; }
.finding-fix { font-size: 0.82rem; color: #4ade80; margin-top: 0.4rem; }
.finding-fix::before { content: "Fix: "; color: #555; }

details { margin: 0.4rem 0; }
details summary { cursor: pointer; font-size: 0.78rem; color: #555; user-select: none; }
details summary:hover { color: #888; }
details[open] summary { color: #888; }

.rec { background: #111; border: 1px solid #2a2a2a; border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }
.rec h3 { margin-top: 0; font-size: 1rem; color: #fff; }
.rec p { font-size: 0.87rem; color: #aaa; margin-top: 0.4rem; }
.priority-p0 { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; font-family: monospace; }
.priority-p1 { background: rgba(251,146,60,0.15); color: #fb923c; border: 1px solid rgba(251,146,60,0.3); padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; font-family: monospace; }
.priority-p2 { background: rgba(96,165,250,0.15); color: #60a5fa; border: 1px solid rgba(96,165,250,0.3); padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; font-family: monospace; }

.score-bar { height: 8px; background: #1a1a1a; border-radius: 4px; margin: 0.5rem 0; overflow: hidden; }
.score-fill { height: 100%; border-radius: 4px; transition: width 0.3s; }

.file-list { font-family: monospace; font-size: 0.78rem; color: #666; }
.file-list span { display: block; padding: 2px 0; }
.file-list span:hover { color: #aaa; }

.cta-card { background: linear-gradient(135deg, #1a1510 0%, #151515 100%); border: 1px solid rgba(200,149,108,0.3); border-radius: 12px; padding: 1.5rem; margin-top: 2rem; }
.cta-card h3 { color: #c8956c; margin-top: 0; }
.cta-card p { font-size: 0.9rem; margin-top: 0.5rem; }
.cta-btn { display: inline-block; background: #c8956c; color: #0c0c0c; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 700; font-size: 0.85rem; margin-top: 1rem; margin-right: 0.5rem; }
.cta-btn.outline { background: transparent; border: 1px solid #c8956c; color: #c8956c; }

.proj-row { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 0; border-bottom: 1px solid #1a1a1a; }
.proj-row:last-child { border-bottom: none; }
.proj-before { color: #ef4444; font-size: 1.1rem; font-weight: 700; min-width: 60px; text-align: center; }
.proj-arrow { color: #555; font-size: 1.2rem; }
.proj-after { color: #4ade80; font-size: 1.1rem; font-weight: 700; min-width: 60px; text-align: center; }
.proj-label { font-size: 0.85rem; color: #bbb; flex: 1; }
.proj-gain { font-size: 0.72rem; color: #4ade80; margin-top: 0.1rem; }

.kw-strip { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 1rem 0; }
.kw-strip a { font-size: 0.75rem; padding: 3px 10px; border: 1px solid #2a2a2a; border-radius: 20px; color: #888; text-decoration: none; background: #111; }
.kw-strip a:hover { border-color: #c8956c; color: #c8956c; }
.footer { text-align: center; padding: 2rem 0 1rem; border-top: 1px solid #2a2a2a; margin-top: 2rem; font-size: 0.8rem; color: #666; }
.footer a { color: #c8956c; text-decoration: none; }
.mode-badge { display: inline-block; background: rgba(200,149,108,0.15); color: #c8956c; border: 1px solid rgba(200,149,108,0.3); padding: 2px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; font-family: monospace; margin-left: 0.5rem; }
"""

_NAV = """<div class="page-nav">
  <a href="audit.html" class="{c1}"><span class="step-num">Step 1</span>Current State</a>
  <a href="recommendations.html" class="{c2}"><span class="step-num">Step 2</span>Recommendations</a>
  <a href="after.html" class="{c3}"><span class="step-num">Step 3</span>Projected Results</a>
</div>"""

_KW = """<div class="kw-strip">
<a href="https://oakenai.tech/ai-systems" target="_blank">Claude SDK Audit</a>
<a href="https://oakenai.tech/tools/claude-agent-auditor" target="_blank">Agent Auditor</a>
<a href="https://oakenai.tech/ai-consulting" target="_blank">AI Consulting</a>
<a href="https://oakenai.tech/ai-infrastructure" target="_blank">AI Infrastructure</a>
<a href="https://oakenai.tech/ai-advisory" target="_blank">AI Advisory</a>
</div>"""

_FOOTER = """<div class="footer">
  Generated by <a href="https://oakenai.tech/tools/claude-agent-auditor">Oaken AI Agent Auditor</a> &nbsp;&middot;&nbsp;
  <a href="https://oakenai.tech">Oaken AI</a> &nbsp;&middot;&nbsp;
  <a href="https://oakenai.tech/ai-readiness">Free AI Assessment</a>
</div>"""


def _score_color(score: int) -> str:
    if score >= 80:
        return "green"
    if score >= 50:
        return "yellow"
    return "red"


def _sev_badge(sev: str) -> str:
    return f'<span class="badge badge-{sev}">{sev.upper()}</span>'


def _priority_badge(p: str) -> str:
    cls = {"P0": "priority-p0", "P1": "priority-p1"}.get(p, "priority-p2")
    return f'<span class="{cls}">{p}</span>'


def _lang_badge(lang: str) -> str:
    cls = {"python": "badge-py", "typescript": "badge-ts"}.get(lang, "badge-mixed")
    labels = {"python": "Python", "typescript": "TypeScript/JS", "mixed": "Python + TS/JS"}
    return f'<span class="badge {cls}">{labels.get(lang, lang)}</span>'


def _render_finding(f: AppFinding) -> str:
    file_label = html.escape(Path(f.file).name)
    line_label = f" &nbsp;·&nbsp; line {f.line}" if f.line else ""
    snippet_html = ""
    if f.snippet:
        escaped = html.escape(f.snippet)
        snippet_html = f'<details><summary>show snippet</summary><pre>{escaped}</pre></details>'
    fix_html = f'<div class="finding-fix">{html.escape(f.fix)}</div>' if f.fix else ""
    return f"""<div class="finding {f.severity}">
  <div class="finding-title">{_sev_badge(f.severity)}{html.escape(f.title)}</div>
  <div class="finding-meta">{file_label}{line_label}</div>
  <div class="finding-msg">{html.escape(f.message)}</div>
  {snippet_html}
  {fix_html}
</div>"""


def _page_head(title: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)} — Oaken AI Agent Auditor</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
<div class="brand"><a href="https://oakenai.tech/tools/claude-agent-auditor">Oaken AI Agent Auditor</a></div>"""


def _page_tail() -> str:
    return f"{_KW}{_FOOTER}</div></body></html>"


# ── Page 1: Current State ─────────────────────────────────────────────────────

def _render_audit(report: AppAuditReport, date_str: str) -> str:
    sc = report.score
    color = _score_color(sc)

    by_severity: dict[str, list[AppFinding]] = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        found = [f for f in report.findings if f.severity == sev]
        if found:
            by_severity[sev] = found

    critical_count = len([f for f in report.findings if f.severity == "critical"])
    high_count = len([f for f in report.findings if f.severity == "high"])
    api_calls = report.api_call_count

    score_bar_color = "#4ade80" if sc >= 80 else "#eab308" if sc >= 50 else "#ef4444"

    sdk_files_html = "".join(
        f'<span>{html.escape(Path(f).name)}</span>'
        for f in report.sdk_files[:20]
    )
    if len(report.sdk_files) > 20:
        sdk_files_html += f'<span style="color:#555">... and {len(report.sdk_files)-20} more</span>'

    findings_html = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        group = by_severity.get(sev, [])
        if not group:
            continue
        findings_html += f'<h3>{sev.title()} ({len(group)})</h3>'
        for f in group:
            findings_html += _render_finding(f)

    if not findings_html:
        findings_html = '<div class="card good"><p style="color:#4ade80">No issues detected. Your Claude SDK usage looks clean.</p></div>'

    nav = _NAV.format(c1="active", c2="", c3="")

    return f"""{_page_head("App Audit — Current State")}
<h1>Claude SDK Audit <span class="mode-badge">APP MODE</span></h1>
<p class="subtitle">Generated {date_str} &nbsp;&middot;&nbsp; {html.escape(report.project_path)}</p>
{nav}
<div class="hero-stats">
  <div class="hero-stat"><div class="value {color}">{sc}</div><div class="label">App Score (0-100)</div></div>
  <div class="hero-stat"><div class="value {'red' if critical_count else 'green'}">{critical_count}</div><div class="label">Critical Issues</div></div>
  <div class="hero-stat"><div class="value {'yellow' if high_count else 'green'}">{high_count}</div><div class="label">High Issues</div></div>
  <div class="hero-stat"><div class="value muted">{api_calls}</div><div class="label">API Calls Found</div></div>
</div>

<h2>Project Info</h2>
<div class="card">
  <table>
    <tr><td>Language</td><td>{_lang_badge(report.language)}</td></tr>
    <tr><td>SDK files</td><td>{len(report.sdk_files)}</td></tr>
    <tr><td>API calls detected</td><td>{report.api_call_count}</td></tr>
    <tr><td>Tool definitions</td><td>{report.tool_definition_count or '<span style="color:#888">None detected</span>'}</td></tr>
    <tr><td>Retry logic</td><td>{'<span style="color:#4ade80">&#x2713; Detected</span>' if report.has_retry_logic else '<span style="color:#ef4444">&#x2717; Not found</span>'}</td></tr>
    <tr><td>Streaming used</td><td>{'<span style="color:#4ade80">&#x2713; Yes</span>' if report.has_streaming else '<span style="color:#888">No</span>'}</td></tr>
    <tr><td>Models referenced</td><td>{'<code>' + '</code>, <code>'.join(html.escape(m) for m in report.hardcoded_models[:5]) + '</code>' if report.hardcoded_models else '<span style="color:#888">None (good)</span>'}</td></tr>
  </table>
</div>

<h2>Files Using Claude SDK</h2>
<div class="card"><div class="file-list">{sdk_files_html}</div></div>

<h2>Findings ({len(report.findings)})</h2>
{findings_html}

<div class="cta-card">
  <h3>Ready to fix this?</h3>
  <p>See the prioritized action plan with code snippets, then the projected results after all fixes are applied.</p>
  <a href="recommendations.html" class="cta-btn">See Recommendations &rarr;</a>
  <a href="https://oakenai.tech/intro-call" class="cta-btn outline" target="_blank">Book a Strategy Call</a>
</div>
{_page_tail()}"""


# ── Page 2: Recommendations ───────────────────────────────────────────────────

def _render_recommendations(report: AppAuditReport, date_str: str) -> str:
    nav = _NAV.format(c1="", c2="active", c3="")

    recs_html = ""
    for rec in report.recommendations:
        p = rec.get("priority", "P2")
        snippets_html = ""
        for snip in rec.get("fix_snippets", []):
            snippets_html += f'<pre>{html.escape(snip)}</pre>'
        recs_html += f"""<div class="rec">
  <h3>{_priority_badge(p)} &nbsp;{html.escape(rec['title'])}</h3>
  <p>{html.escape(rec['description'])}</p>
  {snippets_html}
  <p style="font-size:0.78rem;color:#555;margin-top:0.5rem;">
    Est. time: {html.escape(rec.get('estimated_time',''))} &nbsp;&middot;&nbsp;
    Impact: {html.escape(rec.get('impact',''))}
  </p>
</div>"""

    if not recs_html:
        recs_html = '<div class="card good"><p style="color:#4ade80">No recommendations — your Claude SDK usage looks solid.</p></div>'

    return f"""{_page_head("App Audit — Recommendations")}
<h1>Recommendations <span class="mode-badge">APP MODE</span></h1>
<p class="subtitle">Generated {date_str} &nbsp;&middot;&nbsp; {html.escape(report.project_path)}</p>
{nav}
<p style="font-size:0.85rem;color:#888;margin-bottom:1.5rem;">
  {len(report.recommendations)} recommendation(s) prioritized by impact.
  P0 = fix before production. P1 = fix soon. P2 = quality improvement.
</p>
{recs_html}
<div class="cta-card">
  <h3>Want help implementing these?</h3>
  <p>Book a strategy call to walk through the fixes and get a production-ready Claude integration.</p>
  <a href="https://oakenai.tech/intro-call" class="cta-btn" target="_blank">Book a Strategy Call</a>
  <a href="after.html" class="cta-btn outline">See Projected Results &rarr;</a>
</div>
{_page_tail()}"""


# ── Page 3: Projected After ───────────────────────────────────────────────────

def _projected_score(report: AppAuditReport) -> int:
    """Estimate score after applying all recommendations."""
    from .app_scanner import SEVERITY_PENALTIES, MAX_PENALTY_PER_CHECK
    # Calculate what the score would be with only info/low findings remaining
    remaining = [f for f in report.findings if f.severity in ("info", "low")]
    from .app_scanner import _compute_score
    return _compute_score(remaining)


def _render_after(report: AppAuditReport, date_str: str) -> str:
    nav = _NAV.format(c1="", c2="", c3="active")
    projected = _projected_score(report)
    current = report.score
    gain = projected - current

    metrics = [
        ("Score", str(current), str(projected), f"+{gain} pts" if gain > 0 else "already clean"),
        ("Critical issues", str(len([f for f in report.findings if f.severity == "critical"])), "0", "all resolved"),
        ("High issues", str(len([f for f in report.findings if f.severity == "high"])), "0", "all resolved"),
        ("Error handling", "Missing on some calls" if any(f.title == "API call without error handling" for f in report.findings) else "OK", "All calls protected", "resilient"),
        ("Retry logic", "None" if not report.has_retry_logic else "Present", "Implemented", "auto-recovery from 429s"),
        ("Hardcoded models", str(len(report.hardcoded_models)) if report.hardcoded_models else "None", "Config-driven", "single env var to upgrade"),
    ]

    rows_html = "".join(f"""<div class="proj-row">
  <div class="proj-before">{html.escape(before)}</div>
  <div class="proj-arrow">&rarr;</div>
  <div class="proj-after">{html.escape(after)}</div>
  <div class="proj-label">{html.escape(label)}<div class="proj-gain">{html.escape(gain_label)}</div></div>
</div>""" for label, before, after, gain_label in metrics)

    score_color = _score_color(projected)

    return f"""{_page_head("App Audit — Projected Results")}
<h1>Projected Results <span class="mode-badge">APP MODE</span></h1>
<p class="subtitle">After applying all recommendations &nbsp;&middot;&nbsp; {date_str}</p>
{nav}
<div class="hero-stats">
  <div class="hero-stat"><div class="value muted">{current}</div><div class="label">Current Score</div></div>
  <div class="hero-stat"><div class="value {score_color}">{projected}</div><div class="label">Projected Score</div></div>
  <div class="hero-stat"><div class="value green">+{gain}</div><div class="label">Points Gained</div></div>
  <div class="hero-stat"><div class="value green">{len(report.recommendations)}</div><div class="label">Fixes to Apply</div></div>
</div>

<h2>Before vs After</h2>
<div class="card">{rows_html}</div>

<div class="cta-card">
  <h3>Need help getting there?</h3>
  <p>Book a strategy call to walk through the implementation and get your Claude integration production-ready.</p>
  <a href="https://oakenai.tech/intro-call" class="cta-btn" target="_blank">Book a Strategy Call</a>
  <a href="audit.html" class="cta-btn outline">&larr; Back to Findings</a>
</div>
{_page_tail()}"""


# ── Entry point ───────────────────────────────────────────────────────────────

def generate_app_reports(report: AppAuditReport) -> dict[str, str]:
    """Return {before, recommendations, after} HTML strings."""
    from datetime import date
    date_str = date.today().strftime("%B %d, %Y")

    return {
        "before": _render_audit(report, date_str),
        "recommendations": _render_recommendations(report, date_str),
        "after": _render_after(report, date_str),
    }
