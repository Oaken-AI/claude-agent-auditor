# Oaken AI Claude Agent Auditor

Audit your Claude Code agent architecture. Detect autonomy risks, observability gaps, and rule coverage issues before they cost you.

Built by [Oaken AI](https://oakenai.tech) based on the [Stanford CS230 guest lecture on building with LLMs](https://oakenai.tech/resources/standford-ai-training) and Claude Code's internal architecture.

[![PyPI](https://img.shields.io/pypi/v/claude-agent-auditor)](https://pypi.org/project/claude-agent-auditor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

<div align="center">

<a href="https://donate.stripe.com/6oUcN7bmr5OIfQH4O153O00">
  <img src="donate.png" alt="Buy me a coffee" width="80" />
</a>

**⚡ This tool is free and open-source.**<br>
If it saved you time, [buy me a coffee](https://donate.stripe.com/6oUcN7bmr5OIfQH4O153O00) — it fuels more free AI tools.

</div>

---

## What It Does

Scans your Claude Code workspace and generates a visual HTML report showing:

- **Architecture Score** (0-100) based on agent safety and observability patterns
- **Autonomy Risk** — LOW / MEDIUM / HIGH based on permission settings and safety controls
- **Observability Coverage** — which hooks are present vs. missing (tracing, session logging, memory preservation)
- **Problem Type Coverage** — do your rules address domain knowledge gaps, context window limits, hallucinations, and difficulty of control?
- **Rule Overlap Detection** — finds redundant rules wasting context budget
- **Agent Setup Analysis** — skills, orchestration patterns, subagent delegation

## Why This Matters

Agentic Claude Code systems can silently develop dangerous patterns: unconstrained autonomy, no tracing, overlapping rules that dilute each other, missing safeguards for hallucination or context overflow.

Common problems this tool catches:

- **Unconstrained autonomy**: `bypassPermissions` or `dontAsk` mode with no deny rules — Claude can delete files, push code, send messages without confirmation
- **No agent tracing**: Multi-step Task tool runs with no PostToolUse hooks — you can't debug what went wrong
- **Missing session logging**: No Stop hook — session decisions are lost after every conversation
- **No memory preservation**: PreCompact hook absent — important context silently dropped during long sessions
- **Rule redundancy**: Two rules with 80% keyword overlap loaded every session, canceling each other out
- **Narrow problem coverage**: Rules address hallucination control but ignore context limits — agent hits token walls silently

## Requirements

- Python 3.10+
- Zero dependencies (pure Python stdlib)
- Does NOT need to be installed inside your Claude Code workspace
- Read-only analysis. Never modifies your files.

## Install

```bash
pip install claude-agent-auditor
```

## Usage

Run from anywhere. Point it at any Claude Code project directory.

```bash
# Scan current directory
claude-agent-auditor

# Scan a specific project
claude-agent-auditor /path/to/your/project

# Generate report and open in browser
claude-agent-auditor /path/to/your/project --open

# Also export raw metrics as JSON
claude-agent-auditor --json

# Save reports to a custom directory
claude-agent-auditor --output ./my-reports/
```

The tool looks for `.claude/` in the target directory (and `~/.claude/` for global settings). It scans `settings.json`, rules, hooks, and skills. The report is saved to `agent-audit/` inside the target directory by default.

**Pro tip:** After reviewing the report, feed it to your Claude Code instance:
```
"Read agent-audit/audit.html and implement the HIGH priority recommendations"
```
Claude can self-modify your settings, rules, and hooks based on the findings. Always review the changes before accepting.

## Example Output

```
  Scanning: /home/user/my-project
  Output:   /home/user/my-project/agent-audit/

  Architecture Score:   58/100
  Autonomy Risk:        MEDIUM ⚠
  Observability:        33%
  Problem Types:        2/4 covered
  Agent Rules:          4
  Issues:               5
  Recommendations:      4
```

## What It Checks

### Autonomy & Permissions

Analyzes `settings.json` permission configuration:

| Risk | Condition |
|------|-----------|
| HIGH | `bypassPermissions` mode or `dontAsk` with no deny/ask rules |
| MEDIUM | `dontAsk` with some safety rules, or broad allows with no deny rules |
| LOW | Balanced configuration with explicit deny/ask rules |

### Observability Hooks

Checks for six hooks across three priority tiers:

| Priority | Hook | Purpose |
|----------|------|---------|
| CRITICAL | PostToolUse: Task | Trace every agent sub-task |
| CRITICAL | Stop | Log session decisions before they're lost |
| IMPORTANT | PreCompact | Preserve critical context before compaction |
| IMPORTANT | SessionStart | Initialize state and restore context |
| USEFUL | PostToolUse: Write\|Edit | Audit file changes |
| USEFUL | PostToolUse: Bash | Log all executed commands |

### Problem Type Coverage (Stanford CS230 Framework)

Checks whether your rules address the four fundamental LLM problems identified in the [Stanford CS230 guest lecture](https://oakenai.tech/resources/standford-ai-training):

- **Domain Knowledge Gaps** — Does the agent know enough? (RAG, context injection, domain rules)
- **Context Window Limits** — Does it handle long conversations? (compaction, memory, summarization)
- **Hallucinations** — Does it verify before acting? (verification, grounding, skepticism)
- **Difficulty of Control** — Can you constrain its behavior? (deny rules, ask rules, scope limits)

### Rule Architecture

- Counts total rules and identifies agent-aware rules
- Detects overlapping rule pairs using Jaccard similarity (threshold: 35%)
- Reports which overlap pairs are wasting context budget

### Agent Setup

- Whether skills directory exists and how many skills are defined
- Whether rules reference the Task tool (agent delegation)
- Whether orchestration patterns are present (spawn, delegate, dispatch)
- Whether subagent behavior rules exist

## The Patterns

This tool checks your workspace against agent architecture patterns from Claude Code's framework and the [Stanford CS230 LLM engineering principles](https://oakenai.tech/resources/standford-ai-training):

1. **Autonomy Gates** — Every permission expansion should have a corresponding safety rule
2. **Observability First** — If you don't have traces, you can't debug your agent system
3. **Problem Coverage** — Rules should explicitly address all four LLM failure modes
4. **Non-Overlapping Rules** — Redundant rules dilute each other and waste context budget
5. **Orchestration Awareness** — Multi-agent systems need explicit delegation and coordination rules

## Also Check

If you haven't optimized your workspace's context and memory yet, start there first:

```bash
pip install claude-workspace-optimizer
claude-workspace-optimizer /path/to/your/project --open
```

The [Workspace Optimizer](https://oakenai.tech/tools/claude-workspace-optimizer) handles memory visibility, context bloat, and rule tiering — foundational issues before agent architecture.

## About Oaken AI

[Oaken AI](https://oakenai.tech) builds AI automation systems for businesses. From workspace optimization to full production AI pipelines.

- [Free AI Assessment](https://oakenai.tech/ai-readiness)
- [AI Tools](https://oakenai.tech/tools)
- [Book a Strategy Call](https://oakenai.tech/intro-call)

## Disclaimer

This tool is provided as-is with no warranty. Oaken AI and its contributors accept zero responsibility for any changes made to your workspace based on this tool's output. The report contains recommendations, not instructions. Always review changes before applying them. Back up your workspace before making modifications.

## Author

Built by [Benjamin Brown](https://github.com/benjaminmbrown) at [Oaken AI](https://oakenai.tech).

## License

MIT
