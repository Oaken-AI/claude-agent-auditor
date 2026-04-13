"""HTML report generator for agent architecture audit results — 3-page flow."""
import html
from datetime import datetime

from . import __version__
from .scanner import AgentPatternReport, HookCoverage

# ── Backlinks ─────────────────────────────────────────────────────────────────
BL = {
    "header":    '<a href="https://oakenai.tech/tools/claude-agent-auditor" style="color:#c8956c;text-decoration:none;font-weight:600;">Oaken AI Agent Auditor</a>',
    "optimizer": '<a href="https://oakenai.tech/tools/claude-workspace-optimizer" style="color:#c8956c;text-decoration:none;">Workspace Optimizer</a>',
    "consulting":'<a href="https://oakenai.tech" style="color:#c8956c;text-decoration:none;">Oaken AI</a>',
    "tools":     '<a href="https://oakenai.tech/tools" style="color:#c8956c;text-decoration:none;">AI Tools</a>',
    "assessment":'<a href="https://oakenai.tech/ai-readiness" style="color:#c8956c;text-decoration:none;">Free AI Assessment</a>',
    "services":  '<a href="https://oakenai.tech/ai-systems" style="color:#c8956c;text-decoration:none;">AI automation services</a>',
    "contact":   '<a href="https://oakenai.tech/intro-call" style="color:#c8956c;text-decoration:none;">Book a free strategy call</a>',
    "advisory":  '<a href="https://oakenai.tech/ai-advisory" style="color:#c8956c;text-decoration:none;">AI advisory</a>',
    "infra":     '<a href="https://oakenai.tech/ai-infrastructure" style="color:#c8956c;text-decoration:none;">AI infrastructure</a>',
    "agent_page":'<a href="https://oakenai.tech/tools/claude-agent-auditor" style="color:#c8956c;text-decoration:none;">claude-agent-auditor</a>',
    "lp_agents": '<a href="https://oakenai.tech/ai-systems" style="color:#c8956c;text-decoration:none;">multi-agent systems</a>',
    "lp_claude": '<a href="https://oakenai.tech/tools" style="color:#c8956c;text-decoration:none;">Claude Code tools</a>',
    "lp_consult":'<a href="https://oakenai.tech/ai-consulting" style="color:#c8956c;text-decoration:none;">AI consulting</a>',
}

# ── Shared CSS ────────────────────────────────────────────────────────────────
BASE_CSS = """
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
.container { max-width: 960px; margin: 0 auto; padding: 2rem; }
h1 { font-size: 1.8rem; color: #fff; margin-bottom: 0.25rem; }
h2 { font-size: 1.2rem; color: #fff; margin: 2rem 0 0.75rem; border-bottom: 1px solid #2a2a2a; padding-bottom: 0.5rem; }
h3 { font-size: 0.95rem; color: #c8956c; margin: 1rem 0 0.5rem; }
.subtitle { color: #888; margin-bottom: 1.5rem; font-size: 0.9rem; }
.brand { font-size: 0.75rem; color: #c8956c; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 0.5rem; }

/* Page nav */
.page-nav { display: flex; gap: 0; margin-bottom: 2rem; border: 1px solid #2a2a2a; border-radius: 8px; overflow: hidden; }
.page-nav a { flex: 1; text-align: center; padding: 0.6rem 0.5rem; font-size: 0.8rem; text-decoration: none; color: #888; background: #111; border-right: 1px solid #2a2a2a; transition: background 0.15s; }
.page-nav a:last-child { border-right: none; }
.page-nav a.active { background: #1e1612; color: #c8956c; font-weight: 600; }
.page-nav a:hover:not(.active) { background: #151515; color: #ccc; }
.page-nav .step-num { display: block; font-size: 0.65rem; color: #555; margin-bottom: 1px; }
.page-nav a.active .step-num { color: #7a5c40; }

/* Hero stats */
.hero-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }
@media (max-width: 768px) { .hero-stats { grid-template-columns: 1fr 1fr; } }
.hero-stat { background: #151515; border: 1px solid #2a2a2a; border-radius: 12px; padding: 1.25rem; text-align: center; }
.hero-stat .value { font-size: 2rem; font-weight: 800; }
.hero-stat .value.green { color: #4ade80; }
.hero-stat .value.red { color: #ef4444; }
.hero-stat .value.yellow { color: #eab308; }
.hero-stat .value.copper { color: #c8956c; }
.hero-stat .label { font-size: 0.75rem; color: #888; margin-top: 0.25rem; }
.hero-stat .delta { font-size: 0.7rem; margin-top: 0.2rem; color: #4ade80; font-weight: 600; }
.hero-stat .delta.none { color: #555; }

/* Cards */
.card { background: #151515; border: 1px solid #2a2a2a; border-radius: 12px; padding: 1.25rem; margin-bottom: 1rem; }
.card.critical { border-color: rgba(239,68,68,0.4); }
.card.warning { border-color: rgba(234,179,8,0.3); }
.card.info { border-color: rgba(96,165,250,0.3); }
.card.good { border-color: rgba(74,222,128,0.3); }
.card.copper { border-color: rgba(200,149,108,0.3); }

/* Badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; text-transform: uppercase; margin-right: 0.4rem; }
.badge-critical { background: rgba(239,68,68,0.15); color: #ef4444; }
.badge-warning { background: rgba(234,179,8,0.15); color: #eab308; }
.badge-info { background: rgba(96,165,250,0.15); color: #60a5fa; }
.badge-good { background: rgba(74,222,128,0.15); color: #4ade80; }
.badge-high { background: rgba(239,68,68,0.15); color: #ef4444; }
.badge-medium { background: rgba(234,179,8,0.15); color: #eab308; }
.badge-low { background: rgba(74,222,128,0.15); color: #4ade80; }

/* Tables */
table { width: 100%; border-collapse: collapse; margin: 0.75rem 0; }
th { text-align: left; padding: 0.5rem 0.75rem; color: #888; font-size: 0.72rem; text-transform: uppercase; border-bottom: 1px solid #2a2a2a; }
td { padding: 0.6rem 0.75rem; font-size: 0.85rem; border-bottom: 1px solid #1a1a1a; vertical-align: middle; }
tr:last-child td { border-bottom: none; }
code { background: #1e1e1e; padding: 1px 6px; border-radius: 3px; font-size: 0.82rem; color: #c8956c; font-family: 'Consolas', monospace; }
pre { background: #111; border: 1px solid #2a2a2a; border-radius: 6px; padding: 1rem; font-size: 0.78rem; color: #c8956c; font-family: 'Consolas', monospace; overflow-x: auto; margin: 0.75rem 0; white-space: pre-wrap; }

/* Hook status */
.hook-present { color: #4ade80; font-weight: 600; }
.hook-missing { color: #ef4444; font-weight: 600; }
.priority-critical { color: #ef4444; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }
.priority-important { color: #eab308; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }
.priority-useful { color: #60a5fa; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }

/* Problem coverage matrix */
.problem-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin: 0.75rem 0; }
@media (max-width: 600px) { .problem-grid { grid-template-columns: 1fr; } }
.problem-card { padding: 1rem; border-radius: 8px; border: 1px solid; }
.problem-card.covered { background: rgba(74,222,128,0.05); border-color: rgba(74,222,128,0.25); }
.problem-card.uncovered { background: rgba(239,68,68,0.05); border-color: rgba(239,68,68,0.25); }
.problem-card.projected { background: rgba(74,222,128,0.05); border-color: rgba(74,222,128,0.25); opacity: 0.8; }
.problem-label { font-weight: 600; font-size: 0.9rem; margin-bottom: 0.25rem; }
.problem-desc { font-size: 0.78rem; color: #888; margin-bottom: 0.5rem; }
.problem-status { font-size: 0.75rem; font-weight: 700; }
.problem-card.covered .problem-status, .problem-card.projected .problem-status { color: #4ade80; }
.problem-card.uncovered .problem-status { color: #ef4444; }
.problem-rules { font-size: 0.72rem; color: #666; margin-top: 0.4rem; }

/* Progress bar */
.bar { height: 8px; background: #1e1e1e; border-radius: 4px; margin-top: 0.5rem; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s ease; }

/* Recommendations */
.rec { padding: 1rem 1.25rem; border-left: 3px solid; margin-bottom: 0.75rem; background: #151515; border-radius: 0 8px 8px 0; }
.rec.p0 { border-color: #ef4444; }
.rec.p1 { border-color: #eab308; }
.rec.p2 { border-color: #60a5fa; }
.rec-title { font-weight: 600; color: #fff; margin-bottom: 0.3rem; }
.rec-body { font-size: 0.85rem; color: #bbb; }
.rec-meta { font-size: 0.75rem; color: #666; margin-top: 0.5rem; }
.rec-impl { font-size: 0.82rem; color: #999; margin-top: 0.75rem; border-top: 1px solid #222; padding-top: 0.75rem; }
.rec-impl strong { color: #c8956c; }

/* Mode badge */
.mode-badge { padding: 3px 10px; border-radius: 4px; font-size: 0.78rem; font-weight: 700; font-family: 'Consolas', monospace; }
.mode-bypass { background: rgba(239,68,68,0.2); color: #ef4444; }
.mode-dontask { background: rgba(234,179,8,0.2); color: #eab308; }
.mode-default { background: rgba(74,222,128,0.2); color: #4ade80; }
.mode-plan { background: rgba(96,165,250,0.2); color: #60a5fa; }
.mode-other { background: rgba(200,149,108,0.2); color: #c8956c; }

/* Overlap */
.overlap-pct { font-weight: 700; color: #eab308; }
.shared-kws { font-size: 0.75rem; color: #666; }

/* CTA card */
.cta-card { background: linear-gradient(135deg, #1a1510 0%, #151515 100%); border: 1px solid rgba(200,149,108,0.3); border-radius: 12px; padding: 1.5rem; margin-top: 2rem; }
.cta-card h3 { color: #c8956c; margin-top: 0; }
.cta-card p { font-size: 0.9rem; margin-top: 0.5rem; line-height: 1.7; }
.cta-btn { display: inline-block; background: #c8956c; color: #0c0c0c; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-weight: 700; font-size: 0.85rem; margin-top: 1rem; margin-right: 0.5rem; }
.cta-btn.outline { background: transparent; border: 1px solid #c8956c; color: #c8956c; }

/* Footer */
.footer { text-align: center; padding: 2rem 0 1rem; border-top: 1px solid #2a2a2a; margin-top: 2rem; font-size: 0.8rem; color: #666; }
.footer a { color: #c8956c; text-decoration: none; }

/* Also-run callout */
.also-run { background: #111; border: 1px solid #2a2a2a; border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1.5rem; font-size: 0.83rem; color: #888; }
.also-run strong { color: #c8956c; }

/* Keyword link strip */
.kw-strip { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 1rem 0; }
.kw-strip a { font-size: 0.75rem; padding: 3px 10px; border: 1px solid #2a2a2a; border-radius: 20px; color: #888; text-decoration: none; background: #111; }
.kw-strip a:hover { border-color: #c8956c; color: #c8956c; }

/* Projection rows */
.proj-row { display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem 0; border-bottom: 1px solid #1a1a1a; }
.proj-row:last-child { border-bottom: none; }
.proj-before { color: #ef4444; font-size: 1.1rem; font-weight: 700; min-width: 60px; text-align: center; }
.proj-arrow { color: #555; font-size: 1.2rem; }
.proj-after { color: #4ade80; font-size: 1.1rem; font-weight: 700; min-width: 60px; text-align: center; }
.proj-label { font-size: 0.85rem; color: #bbb; flex: 1; }
.proj-gain { font-size: 0.72rem; color: #4ade80; margin-top: 0.1rem; }
"""

# ── Helpers ───────────────────────────────────────────────────────────────────
def _score_color(score: int) -> str:
    if score >= 80: return "green"
    elif score >= 60: return "yellow"
    elif score >= 40: return "copper"
    return "red"

def _risk_color(risk: str) -> str:
    return {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red"}.get(risk, "copper")

def _severity_badge(severity: str) -> str:
    return f'<span class="badge badge-{html.escape(severity)}">{severity.upper()}</span>'

def _mode_badge(mode: str) -> str:
    css = {
        "bypassPermissions": "mode-bypass",
        "dontAsk": "mode-dontask",
        "default": "mode-default",
        "plan": "mode-plan",
    }.get(mode, "mode-other")
    return f'<span class="mode-badge {css}">{html.escape(mode)}</span>'

def _hook_row(h: HookCoverage) -> str:
    status = (
        '<span class="hook-present">&#x2713; Present</span>'
        if h.present else
        '<span class="hook-missing">&#x2717; Missing</span>'
    )
    priority_cls = f"priority-{h.priority.lower()}"
    event_str = h.event + (f":{h.matcher}" if h.matcher else "")
    return f"""
    <tr>
        <td><strong>{html.escape(h.name)}</strong><br>
            <span style="font-size:0.75rem;color:#666;">{html.escape(h.purpose)}</span></td>
        <td><code>{html.escape(event_str)}</code></td>
        <td><span class="{priority_cls}">{h.priority}</span></td>
        <td>{status}</td>
    </tr>"""

def _nav(active: str) -> str:
    pages = [
        ("before", "1", "Current State",    "audit.html"),
        ("recs",   "2", "Recommendations",  "recommendations.html"),
        ("after",  "3", "Projected Results","after.html"),
    ]
    links = ""
    for key, num, label, fname in pages:
        cls = "active" if key == active else ""
        links += f'<a href="{fname}" class="{cls}"><span class="step-num">Step {num}</span>{label}</a>'
    return f'<div class="page-nav">{links}</div>'

def _kw_strip() -> str:
    links = [
        ("Multi-Agent Systems",   "https://oakenai.tech/ai-systems"),
        ("Claude Code Tools",     "https://oakenai.tech/tools"),
        ("AI Consulting",         "https://oakenai.tech/ai-consulting"),
        ("AI Infrastructure",     "https://oakenai.tech/ai-infrastructure"),
        ("AI Advisory",           "https://oakenai.tech/ai-advisory"),
        ("Free AI Assessment",    "https://oakenai.tech/ai-readiness"),
        ("Agent Architecture",    "https://oakenai.tech/ai-systems"),
        ("LLM Automation",        "https://oakenai.tech/ai-consulting"),
    ]
    inner = "".join(f'<a href="{u}" target="_blank">{t}</a>' for t, u in links)
    return f'<div class="kw-strip">{inner}</div>'

def _footer(now: str) -> str:
    return f"""
    <div class="footer">
        Generated by {BL["header"]} v{__version__} &nbsp;&middot;&nbsp; {now}<br>
        {BL["consulting"]} &nbsp;&middot;&nbsp; {BL["assessment"]} &nbsp;&middot;&nbsp; {BL["tools"]}
    </div>"""

def _page(title: str, body: str, now: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)} — Oaken AI Agent Auditor</title>
<style>{BASE_CSS}</style>
</head>
<body>
<div class="container">
{body}
{_footer(now)}
</div>
</body>
</html>"""

# ── Page 1: Before (Current State) ───────────────────────────────────────────
def _build_before(report: AgentPatternReport, now: str) -> str:
    score_color = _score_color(report.architecture_score)
    obs_pct = report.observability.coverage_pct if report.observability else 0
    obs_color = _score_color(int(obs_pct))
    prob_covered = report.rule_arch.covered_count if report.rule_arch else 0
    prob_color = "green" if prob_covered == 4 else "yellow" if prob_covered >= 2 else "red"
    risk = report.autonomy.risk_level if report.autonomy else "UNKNOWN"
    risk_color = _risk_color(risk)

    hero = f"""
    <div class="hero-stats">
        <div class="hero-stat">
            <div class="value {score_color}">{report.architecture_score}</div>
            <div class="label">Architecture Score (0-100)</div>
        </div>
        <div class="hero-stat">
            <div class="value {risk_color}">{risk}</div>
            <div class="label">Autonomy Risk</div>
        </div>
        <div class="hero-stat">
            <div class="value {obs_color}">{obs_pct:.0f}%</div>
            <div class="label">Observability Coverage</div>
        </div>
        <div class="hero-stat">
            <div class="value {prob_color}">{prob_covered}/4</div>
            <div class="label">Problem Types Covered</div>
        </div>
    </div>"""

    issues_html = ""
    for issue in report.issues:
        sev = issue.get("severity", "info")
        issues_html += f"""
        <div class="card {html.escape(sev)}">
            {_severity_badge(sev)}
            <strong>{html.escape(issue['message'])}</strong>
            <span style="font-size:0.75rem;color:#888;margin-left:0.5rem;">{html.escape(issue.get('impact', ''))}</span>
        </div>"""

    autonomy_html = ""
    if report.autonomy:
        a = report.autonomy
        broad_rows = "".join(
            f"<tr><td><code>{html.escape(r)}</code></td><td>No path/command filter</td></tr>"
            for r in a.broad_allow_patterns
        )
        broad_section = f"""
            <h3>Overly Broad Allow Rules</h3>
            <table><tr><th>Rule</th><th>Risk</th></tr>{broad_rows}</table>
        """ if broad_rows else ""
        card_class = "critical" if a.risk_level == "HIGH" else "warning" if a.risk_level == "MEDIUM" else "good"
        autonomy_html = f"""
        <div class="card {card_class}">
            <table>
                <tr><td>Default mode</td><td>{_mode_badge(a.default_mode)}</td></tr>
                <tr><td>Allow rules</td><td>{a.allow_count}</td></tr>
                <tr><td>Deny rules</td><td>{"<strong style='color:#ef4444'>0 &mdash; no operations blocked</strong>" if not a.deny_count else str(a.deny_count)}</td></tr>
                <tr><td>Ask rules (approval gates)</td><td>{"<strong style='color:#ef4444'>0 &mdash; no confirmations required</strong>" if not a.ask_count else str(a.ask_count)}</td></tr>
                <tr><td>Autonomy risk</td><td><span class="badge badge-{html.escape(a.risk_level.lower())}">{html.escape(a.risk_level)}</span></td></tr>
            </table>
            {broad_section}
        </div>"""

    obs_html = ""
    if report.observability:
        obs = report.observability
        hook_rows = "".join(_hook_row(h) for h in obs.hooks)
        bar_color = "#4ade80" if obs.coverage_pct >= 80 else "#eab308" if obs.coverage_pct >= 50 else "#ef4444"
        card_class = "good" if obs.coverage_pct >= 80 else "warning" if obs.coverage_pct >= 50 else "critical"
        obs_html = f"""
        <div class="card {card_class}">
            <p style="font-size:0.85rem;color:#bbb;margin-bottom:0.75rem;">
                {obs.critical_present}/{obs.critical_total} critical &nbsp;&middot;&nbsp;
                {obs.important_present}/{obs.important_total} important &nbsp;&middot;&nbsp;
                {obs.total_hooks_configured} hooks configured
            </p>
            <div class="bar"><div class="bar-fill" style="width:{obs.coverage_pct}%;background:{bar_color}"></div></div>
            <p style="font-size:0.75rem;color:#888;margin-top:0.25rem;">{obs.coverage_pct:.0f}% weighted coverage</p>
            <table style="margin-top:1rem;">
                <tr><th>Hook</th><th>Event</th><th>Priority</th><th>Status</th></tr>
                {hook_rows}
            </table>
        </div>"""

    rule_arch_html = ""
    if report.rule_arch:
        ra = report.rule_arch
        problem_cards = ""
        for pc in ra.problem_coverage:
            css = "covered" if pc.covered else "uncovered"
            status = "&#x2713; Covered" if pc.covered else "&#x2717; No coverage"
            rules_list = f'<div class="problem-rules">Rules: {html.escape(", ".join(pc.covering_rules[:3]))}</div>' if pc.covering_rules else ""
            problem_cards += f"""
            <div class="problem-card {css}">
                <div class="problem-label">{html.escape(pc.label)}</div>
                <div class="problem-desc">{html.escape(pc.description)}</div>
                <div class="problem-status">{status}</div>
                {rules_list}
            </div>"""

        overlap_section = ""
        if ra.overlapping_pairs:
            overlap_rows = "".join(
                f"<tr><td><code>{html.escape(p.rule_a)}</code></td>"
                f"<td><code>{html.escape(p.rule_b)}</code></td>"
                f"<td class='overlap-pct'>{p.overlap_pct}%</td>"
                f"<td class='shared-kws'>{html.escape(', '.join(p.shared_keywords[:5]))}</td></tr>"
                for p in ra.overlapping_pairs[:6]
            )
            overlap_section = f"""
            <h3>Overlapping Rule Pairs</h3>
            <p style="font-size:0.85rem;color:#bbb;margin-bottom:0.5rem;">These files share significant vocabulary and may issue conflicting instructions.</p>
            <table><tr><th>Rule A</th><th>Rule B</th><th>Overlap</th><th>Shared terms</th></tr>{overlap_rows}</table>"""

        card_class = "warning" if ra.uncovered_count >= 2 else "info" if ra.uncovered_count == 1 else "good"
        rule_arch_html = f"""
        <div class="card {card_class}">
            <p style="font-size:0.85rem;color:#bbb;margin-bottom:0.75rem;">Every LLM technique solves one of four problems. Your rules should cover all four.</p>
            <div class="problem-grid">{problem_cards}</div>
            {overlap_section}
        </div>"""

    agent_setup_html = ""
    if report.agent_setup:
        ag = report.agent_setup
        agents_str = html.escape(", ".join(ag.agent_types_found)) if ag.agent_types_found else "None detected"
        agent_setup_html = f"""
        <div class="card {'good' if ag.has_memory_system else 'info'}">
            <table>
                <tr><td>Memory / RAG system</td><td>{"<span class='hook-present'>&#x2713; Present</span>" if ag.has_memory_system else "<span class='hook-missing'>&#x2717; Not detected</span>"}</td></tr>
                <tr><td>Recall script</td><td>{"<span class='hook-present'>&#x2713; Present</span>" if ag.has_recall_script else "<span style='color:#888'>Not detected</span>"}</td></tr>
                <tr><td>Spawner / skills library</td><td>{"<span class='hook-present'>&#x2713; Present</span>" if ag.has_spawner_skills else "<span style='color:#888'>Not detected</span>"}</td></tr>
                <tr><td>Specialized agents</td><td>{"<span class='hook-present'>&#x2713; " + agents_str + "</span>" if ag.has_specialized_agents else "<span style='color:#888'>None detected</span>"}</td></tr>
                <tr><td>Orchestrator pattern</td><td>{"<span class='hook-present'>&#x2713; Delegation pattern found</span>" if ag.has_orchestrator_pattern else "<span style='color:#888'>Not detected</span>"}</td></tr>
                <tr><td>Memory entries</td><td>{ag.memory_entry_count} lines</td></tr>
            </table>
        </div>"""

    also_run = f"""
    <div class="also-run">
        <strong>Also check:</strong> For context efficiency (memory visibility, rule bloat, token budget),
        run the {BL["optimizer"]} &mdash; <code>pip install claude-workspace-optimizer</code>
    </div>"""

    body = f"""
    <div class="brand">{BL["header"]}</div>
    <h1>Agent Architecture Audit</h1>
    <p class="subtitle">Generated {now} &nbsp;&middot;&nbsp; {html.escape(report.workspace_path)}</p>

    {_nav("before")}
    {also_run}
    {hero}

    <h2>Issues Found</h2>
    <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
        Address P0 issues before running agents autonomously. Need help implementing fixes?
        {BL["lp_consult"]} is available.
    </p>
    {issues_html if issues_html else '<div class="card good"><span class="badge badge-good">CLEAN</span> No critical issues detected.</div>'}

    <h2>Autonomy &amp; Permissions</h2>
    <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
        {BL["lp_agents"]} without deny rules can delete files, push code, and send messages
        without confirmation. Start constrained, earn autonomy incrementally.
    </p>
    {autonomy_html}

    <h2>Observability &amp; Tracing</h2>
    <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
        If you don't have traces, you can't debug your system. Every multi-step agent
        needs PostToolUse hooks and session logging or failures are invisible.
    </p>
    {obs_html}

    <h2>Rule Architecture</h2>
    <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
        Every LLM technique solves one of four problems: domain gaps, context limits,
        hallucinations, or control. Gaps here mean Claude can silently fail in those modes.
    </p>
    {rule_arch_html}

    <h2>Agent Setup</h2>
    <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
        Production {BL["lp_agents"]} use specialized agents, RAG memory, and explicit
        orchestration rules rather than a generalist single-agent loop.
    </p>
    {agent_setup_html}

    {_kw_strip()}

    <div class="cta-card">
        <h3>Ready to fix this?</h3>
        <p>See the prioritized action plan with implementation snippets, then the projected
        results after all recommendations are applied.</p>
        <a href="recommendations.html" class="cta-btn">See Recommendations &rarr;</a>
        <a href="https://oakenai.tech/intro-call" class="cta-btn outline" target="_blank">Book a Strategy Call</a>
    </div>"""

    return _page("Current State - Agent Architecture Audit", body, now)

# ── Page 2: Recommendations ───────────────────────────────────────────────────
_HOOK_SNIPPETS = {
    "Agent Tracing": """{
  "PostToolUse": [{
    "matcher": "Task",
    "hooks": [{
      "type": "command",
      "command": "jq -r '[now | strftime(\"%Y-%m-%dT%H:%M:%SZ\")] + \" [AGENT] \" + .tool_name' >> ~/.claude/agent-trace.log"
    }]
  }]
}""",
    "Session Logging": """{
  "Stop": [{
    "hooks": [{
      "type": "command",
      "command": "echo \"$(date -Iseconds) session-end\" >> ~/.claude/session-log.txt"
    }]
  }]
}""",
    "Memory Preservation": """{
  "PreCompact": [{
    "hooks": [{
      "type": "prompt",
      "prompt": "Before compacting, identify the 3 most important decisions or solutions from this session. Output them as a JSON array with decision and rationale fields so they can be preserved in memory."
    }]
  }]
}""",
    "Session Init": """{
  "SessionStart": [{
    "hooks": [{
      "type": "command",
      "command": "echo \"$(date -Iseconds) session-start\" >> ~/.claude/session-log.txt"
    }]
  }]
}""",
    "File Change Audit": """{
  "PostToolUse": [{
    "matcher": "Write|Edit",
    "hooks": [{
      "type": "command",
      "command": "jq -r '\"[FILE] \" + (.tool_input.file_path // .tool_response.filePath // \"unknown\")' >> ~/.claude/file-changes.log"
    }]
  }]
}""",
    "Command Logging": """{
  "PostToolUse": [{
    "matcher": "Bash",
    "hooks": [{
      "type": "command",
      "command": "jq -r '\"[CMD] \" + .tool_input.command' >> ~/.claude/bash-log.txt"
    }]
  }]
}""",
}

def _build_recommendations(report: AgentPatternReport, now: str) -> str:
    recs_html = ""
    for rec in report.recommendations:
        p = rec["priority"].lower()
        badge_sev = "critical" if p == "p0" else "warning" if p == "p1" else "info"

        impl_section = ""
        title_lower = rec["title"].lower()
        for hook_name, snippet in _HOOK_SNIPPETS.items():
            if hook_name.lower().split()[0] in title_lower or hook_name.lower() in title_lower:
                impl_section = f"""
                <div class="rec-impl">
                    <strong>Implementation snippet</strong> &mdash; add to <code>~/.claude/settings.json</code> hooks section:<br>
                    <pre>{html.escape(snippet)}</pre>
                </div>"""
                break

        if not impl_section and "deny" in title_lower:
            impl_section = """
            <div class="rec-impl">
                <strong>Implementation</strong> &mdash; add to <code>~/.claude/settings.json</code>:<br>
                <pre>{"permissions": {"deny": ["Bash(rm -rf:*)", "Bash(git push --force:*)"], "ask": ["Bash(git push:*)", "Bash(git commit:*)"]}}</pre>
            </div>"""

        recs_html += f"""
        <div class="rec {html.escape(p)}">
            <div class="rec-title"><span class="badge badge-{badge_sev}">{rec['priority']}</span>{html.escape(rec['title'])}</div>
            <div class="rec-body">{html.escape(rec['description'])}</div>
            <div class="rec-meta">Time: {rec.get('estimated_time', '?')} &nbsp;&middot;&nbsp; Impact: {html.escape(rec.get('impact', ''))}</div>
            {impl_section}
        </div>"""

    missing_hooks_html = ""
    if report.observability:
        missing = [h for h in report.observability.hooks if not h.present]
        if missing:
            missing_hooks_html = f"""
            <h2>Missing Hooks &mdash; Implementation Guide</h2>
            <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
                Add these to <code>~/.claude/settings.json</code>. These {BL["lp_claude"]} hooks
                give you production-grade observability with zero runtime cost.
            </p>"""
            for h in missing:
                snippet = _HOOK_SNIPPETS.get(h.name, "# See documentation")
                priority_cls = f"priority-{h.priority.lower()}"
                event_str = h.event + (f":{h.matcher}" if h.matcher else "")
                card_class = "critical" if h.priority == "CRITICAL" else "warning" if h.priority == "IMPORTANT" else "info"
                missing_hooks_html += f"""
                <div class="card {card_class}">
                    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.5rem;">
                        <strong>{html.escape(h.name)}</strong>
                        <span class="{priority_cls}">{h.priority}</span>
                        <code>{html.escape(event_str)}</code>
                    </div>
                    <p style="font-size:0.83rem;color:#999;margin-bottom:0.5rem;">{html.escape(h.purpose)}</p>
                    <pre>{html.escape(snippet)}</pre>
                </div>"""

    uncovered_html = ""
    if report.rule_arch:
        uncovered = [pc for pc in report.rule_arch.problem_coverage if not pc.covered]
        if uncovered:
            templates = {
                "Domain Knowledge Gaps": ("domain-gap.md",
                    "# Domain Knowledge Rules\n\n## When to Use External Context\n- Verify claims against retrieved documents before asserting facts\n- If domain knowledge is uncertain, retrieve before responding\n- Prefer RAG context over training-time knowledge for time-sensitive facts"),
                "Context Window Limits": ("context-limits.md",
                    "# Context Management Rules\n\n## Long Session Handling\n- Summarize key decisions when conversation exceeds 50 turns\n- Use MEMORY.md to persist critical facts across sessions\n- Invoke PreCompact preservation before long multi-step operations"),
                "Hallucinations":        ("hallucination-prevention.md",
                    "# Hallucination Prevention Rules\n\n## Verification Before Action\n- Never assert a file exists without reading it first\n- Verify API endpoints before calling them\n- If uncertain, say so explicitly — do not fabricate plausible-sounding answers"),
                "Difficulty of Control": ("control.md",
                    "# Agent Control Rules\n\n## Scope Limits\n- Only modify files in the project directory unless explicitly authorized\n- Do not push to remote without explicit user confirmation\n- Do not send external messages (Slack, email, webhooks) without approval"),
            }
            uncovered_html = f"""
            <h2>Rule Gaps &mdash; Starter Templates</h2>
            <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
                Create a <code>.claude/rules/</code> file for each uncovered problem type.
                These rules make {BL["lp_agents"]} more reliable by giving Claude explicit
                guidance for every class of LLM failure.
            </p>"""
            for pc in uncovered:
                filename, template = templates.get(pc.label, ("rule.md", "# Rule\n\n## Guidelines\n- ..."))
                uncovered_html += f"""
                <div class="card critical">
                    <div style="margin-bottom:0.5rem;">
                        <strong>{html.escape(pc.label)}</strong>
                        <span style="font-size:0.78rem;color:#888;margin-left:0.5rem;">{html.escape(pc.description)}</span>
                    </div>
                    <p style="font-size:0.83rem;color:#999;margin-bottom:0.5rem;">Create: <code>.claude/rules/{filename}</code></p>
                    <pre>{html.escape(template)}</pre>
                </div>"""

    body = f"""
    <div class="brand">{BL["header"]}</div>
    <h1>Recommendations</h1>
    <p class="subtitle">Prioritized action plan &nbsp;&middot;&nbsp; P0 = fix before running agents autonomously</p>

    {_nav("recs")}

    <h2>Prioritized Actions</h2>
    <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
        {len(report.recommendations)} recommendations total. P0 items are blockers for safe autonomous operation.
        Not sure where to start? {BL["assessment"]} helps map priorities to your specific setup.
    </p>
    {recs_html if recs_html else '<div class="card good">No immediate optimizations needed.</div>'}

    {missing_hooks_html}
    {uncovered_html}

    {_kw_strip()}

    <div class="cta-card">
        <h3>Want this implemented for you?</h3>
        <p>
            {BL["lp_consult"]} from {BL["consulting"]} covers agent architecture, observability hooks,
            rule design, and {BL["infra"]} &mdash; everything in this report, built for your specific stack.
        </p>
        <a href="after.html" class="cta-btn">See Projected Results &rarr;</a>
        <a href="https://oakenai.tech/intro-call" class="cta-btn outline" target="_blank">Book a Strategy Call</a>
    </div>"""

    return _page("Recommendations - Agent Architecture Audit", body, now)

# ── Page 3: After (Projected Results) ────────────────────────────────────────
def _build_after(report: AgentPatternReport, now: str) -> str:
    obs_pct_now = report.observability.coverage_pct if report.observability else 0
    prob_covered_now = report.rule_arch.covered_count if report.rule_arch else 0
    risk_now = report.autonomy.risk_level if report.autonomy else "UNKNOWN"
    score_now = report.architecture_score

    score_proj = min(95, score_now + len(report.recommendations) * 8)
    score_color_proj = _score_color(score_proj)

    proj_data = [
        ("Architecture Score",    str(score_now),         str(score_proj),     f"+{score_proj - score_now} points after all recommendations"),
        ("Autonomy Risk",         risk_now,               "LOW",               "Deny + ask rules prevent unintended destructive actions"),
        ("Observability",         f"{obs_pct_now:.0f}%",  "100%",              "All 6 hooks configured — full session traceability"),
        ("Problem Coverage",      f"{prob_covered_now}/4","4/4",               "Rules covering all four LLM failure modes"),
    ]

    proj_html = '<div class="card copper">'
    for label, before, after, gain in proj_data:
        proj_html += f"""
        <div class="proj-row">
            <div class="proj-before">{html.escape(before)}</div>
            <div class="proj-arrow">&rarr;</div>
            <div class="proj-after">{html.escape(after)}</div>
            <div>
                <div class="proj-label">{html.escape(label)}</div>
                <div class="proj-gain">{html.escape(gain)}</div>
            </div>
        </div>"""
    proj_html += "</div>"

    hero = f"""
    <div class="hero-stats">
        <div class="hero-stat">
            <div class="value {score_color_proj}">{score_proj}</div>
            <div class="label">Projected Score</div>
            <div class="delta">+{score_proj - score_now} from {score_now}</div>
        </div>
        <div class="hero-stat">
            <div class="value green">LOW</div>
            <div class="label">Autonomy Risk</div>
            <div class="delta {'none' if risk_now == 'LOW' else ''}">{'Already low' if risk_now == 'LOW' else html.escape(f'Reduced from {risk_now}')}</div>
        </div>
        <div class="hero-stat">
            <div class="value green">100%</div>
            <div class="label">Observability</div>
            <div class="delta">+{100 - int(obs_pct_now)}% coverage gained</div>
        </div>
        <div class="hero-stat">
            <div class="value green">4/4</div>
            <div class="label">Problem Types</div>
            <div class="delta">{'Already covered' if prob_covered_now == 4 else f'+{4 - prob_covered_now} types added'}</div>
        </div>
    </div>"""

    prob_cards = ""
    if report.rule_arch:
        for pc in report.rule_arch.problem_coverage:
            prob_cards += f"""
            <div class="problem-card projected">
                <div class="problem-label">{html.escape(pc.label)}</div>
                <div class="problem-desc">{html.escape(pc.description)}</div>
                <div class="problem-status">&#x2713; Covered</div>
            </div>"""

    proj_obs_html = ""
    if report.observability:
        hook_rows = ""
        for h in report.observability.hooks:
            priority_cls = f"priority-{h.priority.lower()}"
            event_str = h.event + (f":{h.matcher}" if h.matcher else "")
            hook_rows += f"""
            <tr>
                <td><strong>{html.escape(h.name)}</strong></td>
                <td><code>{html.escape(event_str)}</code></td>
                <td><span class="{priority_cls}">{h.priority}</span></td>
                <td><span class="hook-present">&#x2713; Present</span></td>
            </tr>"""
        proj_obs_html = f"""
        <div class="card good">
            <div class="bar"><div class="bar-fill" style="width:100%;background:#4ade80"></div></div>
            <p style="font-size:0.75rem;color:#888;margin-top:0.25rem;">100% weighted coverage</p>
            <table style="margin-top:1rem;">
                <tr><th>Hook</th><th>Event</th><th>Priority</th><th>Status</th></tr>
                {hook_rows}
            </table>
        </div>"""

    body = f"""
    <div class="brand">{BL["header"]}</div>
    <h1>Projected Results</h1>
    <p class="subtitle">Estimated state after implementing all recommendations &nbsp;&middot;&nbsp; {now}</p>

    {_nav("after")}

    <p style="font-size:0.85rem;color:#888;margin-bottom:1.5rem;">
        Projections assume all recommended hooks, rules, and permission changes are implemented.
        {BL["lp_consult"]} from {BL["consulting"]} can implement these in a single session.
    </p>

    {hero}

    <h2>Metric Improvements</h2>
    {proj_html}

    <h2>Observability After</h2>
    <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
        With all 6 hooks in place, every agent sub-task, file change, bash command, and
        session boundary is logged. This is the baseline for production-grade {BL["lp_agents"]}.
    </p>
    {proj_obs_html}

    <h2>Problem Coverage After</h2>
    <p style="font-size:0.85rem;color:#888;margin-bottom:1rem;">
        With rules covering all four problem types, Claude has explicit guidance for every
        class of LLM failure &mdash; domain gaps, context overflows, hallucinations, and control.
    </p>
    <div class="problem-grid">{prob_cards}</div>

    {_kw_strip()}

    <div class="cta-card">
        <h3>Get to this state faster</h3>
        <p>
            {BL["consulting"]} builds production {BL["lp_agents"]} for businesses &mdash;
            architecture, hooks, rules, RAG memory, and {BL["infra"]}. Everything in this
            report, built for your stack.
        </p>
        <p style="margin-top:0.5rem;font-size:0.85rem;color:#999;">
            Or start with a {BL["assessment"]} &mdash; we map your current AI automation stack
            and show you exactly where to invest next.
        </p>
        <a href="https://oakenai.tech/intro-call" class="cta-btn" target="_blank">Book a Free Strategy Call &rarr;</a>
        <a href="https://oakenai.tech/ai-readiness" class="cta-btn outline" target="_blank">Free AI Assessment</a>
    </div>"""

    return _page("Projected Results - Agent Architecture Audit", body, now)

# ── Public API ────────────────────────────────────────────────────────────────
def generate_reports(report: AgentPatternReport) -> dict[str, str]:
    """Generate all three report pages. Returns dict with before/recommendations/after HTML."""
    now = datetime.now().strftime("%B %d, %Y")
    return {
        "before": _build_before(report, now),
        "recommendations": _build_recommendations(report, now),
        "after": _build_after(report, now),
    }

def generate_report(report: AgentPatternReport) -> str:
    """Backward-compatible single-page report (returns the before page)."""
    return generate_reports(report)["before"]
