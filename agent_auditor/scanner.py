"""Agent architecture scanner - analyzes Claude Code workspace for agentic pattern quality.

Checks derived from the Stanford CS230 guest lecture on building production LLM systems
mapped to detectable signals in Claude Code workspace configuration.
"""
from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Limits & thresholds ───────────────────────────────────────────────────────
MAX_FILE_SIZE = 524_288       # 512 KB per file
MAX_RULE_FILES = 200          # cap rglob results to prevent exhaustion
OVERLAP_THRESHOLD = 0.35      # Jaccard similarity to flag as overlapping
MIN_RULE_LINES = 30           # minimum lines for a rule to enter overlap analysis
MAX_OVERLAP_PAIRS = 10        # how many overlap pairs to surface in the report
MIN_SPECIALIZED_AGENTS = 2    # minimum distinct agent types to count as "specialized"

# Secret patterns to flag in workspace files
SECRET_PATTERNS: list[tuple[str, str]] = [
    (r'sk-ant-[A-Za-z0-9\-_]{20,}', "Anthropic API key"),
    (r'sk-[A-Za-z0-9]{32,}', "OpenAI-style API key"),
    (r'(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[=:]\s*["\']?[A-Za-z0-9+/\-_]{20,}', "API key or token"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub personal access token"),
    # Password pattern — requires 12+ chars to reduce false positives on short dev values
    (r'(?i)(password|passwd)\s*[=:]\s*["\']?[^\s"\']{12,}', "Plaintext password"),
]

# Strings that indicate a match is a placeholder/example rather than a real secret
_PLACEHOLDER_MARKERS = (
    "...", "xxx", "your_", "_here", "example", "placeholder",
    "replace_me", "changeme", "insert_", "fixme", "todo",
    "<api_key>", "<token>", "<secret>", "sk-ant-...", "sk-...",
)

# Words that indicate a password value is a dev/test credential
_DEV_PASSWORD_WORDS = (
    "dev", "test", "local", "example", "dummy", "fake", "demo",
    "sample", "staging", "mock", "temp", "default",
)


def _is_false_positive(line: str, match_str: str) -> bool:
    """Return True if a regex match looks like an example/placeholder rather than a real secret."""
    line_l = line.lower()
    match_l = match_str.lower()

    # Skip if the matched string itself contains placeholder markers
    for marker in _PLACEHOLDER_MARKERS:
        if marker in match_l:
            return True

    # Skip if the whole line contains placeholder indicators
    if any(m in line_l for m in ("example", "placeholder", "your_api_key", "insert_key", "replace_me")):
        return True

    # For password matches: skip if the value is a simple dev word (all lowercase, no digits, no specials)
    # e.g. POSTGRES_PASSWORD=claude_dev — clearly not a real password
    pw_match = re.search(r'(?i)(password|passwd)\s*[=:]\s*["\']?([^\s"\']+)', line)
    if pw_match:
        pw_value = pw_match.group(2).lower().strip("'\"")
        # Simple dev credential: only lowercase + underscore + digits, and contains a dev word
        if re.match(r'^[a-z0-9_]+$', pw_value):
            for dev_word in _DEV_PASSWORD_WORDS:
                if dev_word in pw_value:
                    return True

    return False


# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class AutonomyMetrics:
    default_mode: str                    # default | plan | acceptEdits | dontAsk | bypassPermissions
    allow_count: int
    deny_count: int
    ask_count: int
    has_bypass: bool                     # bypassPermissions or dontAsk with no ask rules
    broad_allow_patterns: list[str]      # allow rules with no path/tool restriction
    risk_level: str                      # LOW | MEDIUM | HIGH


@dataclass
class HookCoverage:
    name: str
    event: str
    matcher: str          # "" for lifecycle hooks (Stop, SessionStart, etc.)
    priority: str         # CRITICAL | IMPORTANT | USEFUL
    purpose: str
    why_missing_matters: str
    present: bool


@dataclass
class ObservabilityMetrics:
    total_hooks_configured: int
    critical_present: int
    critical_total: int
    important_present: int
    important_total: int
    coverage_pct: float
    hooks: list[HookCoverage]
    has_agent_tracing: bool
    has_session_logging: bool
    has_memory_preservation: bool


@dataclass
class ProblemCoverage:
    problem: str          # domain-gap | context-limit | hallucination | control
    label: str
    description: str
    covered: bool
    covering_rules: list[str]


@dataclass
class RuleOverlap:
    rule_a: str
    rule_b: str
    overlap_pct: int      # integer percentage for consistent display (e.g. 42, not 42.0)
    shared_keywords: list[str]


@dataclass
class RuleArchMetrics:
    total_rules: int
    problem_coverage: list[ProblemCoverage]
    covered_count: int
    uncovered_count: int
    overlapping_pairs: list[RuleOverlap]


@dataclass
class AgentSetupMetrics:
    has_memory_system: bool
    has_recall_script: bool
    has_spawner_skills: bool
    agent_types_found: list[str]
    has_specialized_agents: bool
    has_orchestrator_pattern: bool
    memory_entry_count: int
    has_mcp_servers: bool
    mcp_server_count: int
    mcp_server_names: list[str]


@dataclass
class AgentPatternReport:
    workspace_path: str
    claude_dir_path: str = ""
    used_fallback: bool = False
    architecture_score: int = 0
    autonomy: AutonomyMetrics | None = None
    observability: ObservabilityMetrics | None = None
    rule_arch: RuleArchMetrics | None = None
    agent_setup: AgentSetupMetrics | None = None
    secrets_exposed: list[dict[str, str]] = field(default_factory=list)
    issues: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)


# ── Hook catalog ──────────────────────────────────────────────────────────────

HOOK_CATALOG: list[tuple[str, str, str, str, str, str]] = [
    # (name, event, matcher, priority, purpose, why_missing_matters)
    (
        "Agent Tracing",
        "PostToolUse", "Task",
        "CRITICAL",
        "Records inputs, outputs, and tool calls for every spawned agent.",
        "Agent failures become black boxes. You cannot debug what you cannot observe.",
    ),
    (
        "Session Logging",
        "Stop", "",
        "CRITICAL",
        "Logs what changed when Claude finishes — file edits, commands run, decisions made.",
        "No audit trail between sessions. Silent failures go undetected until production.",
    ),
    (
        "Memory Preservation",
        "PreCompact", "",
        "IMPORTANT",
        "Captures key context before compaction so important decisions aren't silently lost.",
        "Context compaction can drop the reasoning behind architectural decisions.",
    ),
    (
        "Session Init / Auto-Recall",
        "SessionStart", "",
        "IMPORTANT",
        "Primes context at session start (e.g., auto-recall relevant learnings from memory).",
        "Every session starts cold. Prior solutions and decisions aren't surfaced automatically.",
    ),
    (
        "File Change Audit",
        "PostToolUse", "Write|Edit",
        "USEFUL",
        "Records every file write and edit for change tracking and rollback.",
        "No record of what files were changed or why during a session.",
    ),
    (
        "Command Logging",
        "PostToolUse", "Bash",
        "USEFUL",
        "Logs all Bash commands executed for debugging and security review.",
        "No record of commands run. Security and debugging both suffer.",
    ),
]


# ── Problem type keyword catalog ──────────────────────────────────────────────

PROBLEM_KEYWORDS: dict[str, list[str]] = {
    "domain-gap": [
        "memory", "recall", "knowledge", "rag", "vector", "retriev",
        "learn", "store", "embedding", "semantic", "vault", "dynamic",
        "context7", "docs", "documentation", "expertise",
    ],
    "context-limit": [
        "compact", "handoff", "truncat", "summary", "window", "compress",
        "token", "limit", "overflow", "cap", "context-limit", "resume",
        "session", "carry", "persist",
    ],
    "hallucination": [
        "verify", "verif", "check", "confirm", "claim", "validate",
        "assert", "epistemic", "fact", "grounding", "proof", "source",
        "citation", "double-check", "accurate", "correct",
    ],
    "control": [
        "hook", "permission", "allow", "deny", "approve", "gate",
        "guard", "restrict", "block", "prevent", "enforce", "policy",
        "destructive", "confirm", "safety", "secure",
    ],
}

PROBLEM_LABELS = {
    "domain-gap":    "Domain Knowledge Gaps",
    "context-limit": "Context Window Limits",
    "hallucination": "Hallucinations",
    "control":       "Difficulty of Control",
}

PROBLEM_DESCRIPTIONS = {
    "domain-gap":    "Rules that give Claude project-specific knowledge (memory, RAG, docs)",
    "context-limit": "Rules that manage what survives session boundaries (handoffs, compaction)",
    "hallucination": "Rules that enforce verification before asserting facts about the codebase",
    "control":       "Rules that gate destructive actions and enforce approval workflows",
}

# Known agent type keywords to detect in rules
AGENT_KEYWORDS = [
    "scout", "oracle", "kraken", "architect", "phoenix", "spark",
    "arbiter", "sleuth", "validator", "debug-agent", "researcher",
    "subagent", "sub-agent", "worker", "planner", "executor",
]

ORCHESTRATOR_KEYWORDS = [
    "delegat", "orchestrat", "spawn", "dispatch", "route", "coordinat",
    "sub-agent", "subagent", "parallel agent", "agent team",
]

STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "your", "have",
    "will", "are", "not", "use", "when", "should", "each", "only", "also",
    "into", "can", "all", "any", "used", "using", "more", "than", "then",
    "been", "being", "about", "before", "after", "would", "could", "their",
    "which", "what", "how", "where", "there", "here", "they", "them",
    "file", "files", "code", "tool", "tools", "claude", "always", "never",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_read(path: Path) -> str | None:
    """Read a file's text content, skipping symlinks, directories, and large files."""
    try:
        if not path.is_file():       # rejects symlinks to dirs, device nodes, etc.
            return None
        if path.stat().st_size > MAX_FILE_SIZE:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def _safe_read_settings(path: Path) -> dict[str, Any]:
    """Read and parse a JSON settings file, enforcing the size limit."""
    content = _safe_read(path)
    if content is None:
        return {}
    try:
        return json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {}


def _load_settings(claude_dir: Path) -> dict[str, Any]:
    """Load merged settings from project .claude/ and global ~/.claude/."""
    result: dict[str, Any] = {}
    for name in ("settings.json", "settings.local.json"):
        p = claude_dir / name
        if p.exists():
            result[name] = _safe_read_settings(p)

    # Also load global settings when scanning a project-local .claude/
    home_settings = Path.home() / ".claude" / "settings.json"
    if home_settings.exists() and home_settings.parent != claude_dir:
        result["~/.claude/settings.json"] = _safe_read_settings(home_settings)

    return result


def _merged_permissions(settings: dict[str, Any]) -> dict[str, Any]:
    """Merge permissions from all settings files (local takes precedence)."""
    merged: dict[str, Any] = {
        "defaultMode": "default",
        "allow": [],
        "deny": [],
        "ask": [],
    }
    # Apply in order: global → project → local
    for key in ("~/.claude/settings.json", "settings.json", "settings.local.json"):
        if key not in settings:
            continue
        perms = settings[key].get("permissions", {})
        if "defaultMode" in perms:
            merged["defaultMode"] = perms["defaultMode"]
        merged["allow"] = list(set(merged["allow"]) | set(perms.get("allow", [])))
        merged["deny"] = list(set(merged["deny"]) | set(perms.get("deny", [])))
        merged["ask"] = list(set(merged["ask"]) | set(perms.get("ask", [])))
    return merged


def _merged_hooks(settings: dict[str, Any]) -> dict[str, Any]:
    """Collect all hooks across settings files."""
    merged: dict[str, list] = defaultdict(list)
    for _key, cfg in settings.items():
        for event, entries in cfg.get("hooks", {}).items():
            if isinstance(entries, list):
                merged[event].extend(entries)
    return dict(merged)


def _hook_present(hooks: dict[str, Any], event: str, matcher: str) -> bool:
    """Check if a hook for (event, matcher) is configured."""
    entries = hooks.get(event, [])
    if not entries:
        return False
    if not matcher:  # lifecycle hook — any entry counts
        return True
    # Tool hook — check matcher strings
    matcher_parts = {m.strip().lower() for m in matcher.split("|")}
    for entry in entries:
        entry_matcher = entry.get("matcher", "").lower()
        if any(part in entry_matcher for part in matcher_parts):
            if entry.get("hooks"):  # must have actual hook definitions
                return True
    return False


def _extract_keywords(text: str) -> set[str]:
    """Extract meaningful words from rule content for overlap analysis."""
    words = re.findall(r"[a-zA-Z]{4,}", text.lower())
    return {w for w in words if w not in STOPWORDS}


def _broad_allow(rule: str) -> bool:
    """Return True if an allow rule grants unrestricted tool access."""
    bare_tools = {"Bash", "Write", "Edit", "Read", "Glob", "Grep"}
    if rule in bare_tools:
        return True
    if re.match(r"Bash\(\*", rule):
        return True
    return False


def _extract_mcp_servers(settings: dict[str, Any]) -> tuple[bool, int, list[str]]:
    """Return (has_mcp, count, names) from merged settings."""
    names: set[str] = set()
    for _key, cfg in settings.items():
        # .mcp.json style via enabledMcpjsonServers
        for name in cfg.get("enabledMcpjsonServers", []):
            if isinstance(name, str):
                names.add(name)
        # Direct mcpServers block (legacy / some configs)
        mcp_block = cfg.get("mcpServers", {})
        if isinstance(mcp_block, dict):
            names.update(mcp_block.keys())
    return bool(names), len(names), sorted(names)


def _check_secrets_in_files(claude_dir: Path, root: Path) -> list[dict[str, str]]:
    """Scan workspace files for accidentally committed secrets.

    Intentionally narrow scope: only settings files, .env files, and rules/
    (not skills/, plugins/, or other documentation directories).
    """
    findings: list[dict[str, str]] = []
    compiled = [(re.compile(pat), label) for pat, label in SECRET_PATTERNS]

    # Only scan high-risk locations — not skill/plugin docs
    scan_files = [
        root / "CLAUDE.md",
        claude_dir / "settings.json",
        claude_dir / "settings.local.json",
        root / ".env",
        root / ".env.local",
    ]
    scan_dirs = [
        claude_dir / "rules",   # project rules only, not global skills/plugins
    ]
    # Also scan project .claude/ for any stray .env files
    if claude_dir.is_dir():
        for f in claude_dir.glob("*.env"):
            scan_files.append(f)

    checked: set[Path] = set()

    def _scan_file(path: Path) -> None:
        if path in checked or not path.is_file():
            return
        checked.add(path)
        content = _safe_read(path)
        if not content:
            return
        for compiled_pat, label in compiled:
            m = compiled_pat.search(content)
            if m:
                # Check the line containing the match for false-positive markers
                line_start = content.rfind("\n", 0, m.start()) + 1
                line_end = content.find("\n", m.end())
                line = content[line_start: line_end if line_end != -1 else len(content)]
                if _is_false_positive(line, m.group(0)):
                    continue
                findings.append({
                    "file": str(path),
                    "type": label,
                })
                break  # one finding per file is enough

    for f in scan_files:
        _scan_file(f)

    for d in scan_dirs:
        if d.exists() and d.is_dir():
            for f in d.rglob("*.md"):
                _scan_file(f)
            for f in d.rglob("*.env"):
                _scan_file(f)

    return findings


# ── Analysis functions ────────────────────────────────────────────────────────

def _analyze_autonomy(settings: dict[str, Any]) -> AutonomyMetrics:
    perms = _merged_permissions(settings)
    mode: str = perms["defaultMode"]
    allow_rules: list[str] = perms["allow"]
    deny_rules: list[str] = perms["deny"]
    ask_rules: list[str] = perms["ask"]

    broad = [r for r in allow_rules if _broad_allow(r)]

    has_bypass = mode in ("bypassPermissions", "dontAsk")
    if mode == "bypassPermissions":
        risk = "HIGH"
    elif mode == "dontAsk" and not ask_rules:
        risk = "HIGH"
    elif mode == "dontAsk":
        risk = "MEDIUM"
    elif broad and not deny_rules:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return AutonomyMetrics(
        default_mode=mode,
        allow_count=len(allow_rules),
        deny_count=len(deny_rules),
        ask_count=len(ask_rules),
        has_bypass=has_bypass,
        broad_allow_patterns=broad,
        risk_level=risk,
    )


def _analyze_observability(settings: dict[str, Any]) -> ObservabilityMetrics:
    hooks = _merged_hooks(settings)
    total_configured = sum(len(v) for v in hooks.values())

    hook_results: list[HookCoverage] = []
    for name, event, matcher, priority, purpose, why_missing in HOOK_CATALOG:
        present = _hook_present(hooks, event, matcher)
        hook_results.append(HookCoverage(
            name=name,
            event=event,
            matcher=matcher,
            priority=priority,
            purpose=purpose,
            why_missing_matters=why_missing,
            present=present,
        ))

    critical = [h for h in hook_results if h.priority == "CRITICAL"]
    important = [h for h in hook_results if h.priority == "IMPORTANT"]
    weighted = sum(3 if h.priority == "CRITICAL" else 2 if h.priority == "IMPORTANT" else 1
                   for h in hook_results if h.present)
    total_weight = sum(3 if h.priority == "CRITICAL" else 2 if h.priority == "IMPORTANT" else 1
                       for h in hook_results)
    coverage_pct = round((weighted / total_weight * 100) if total_weight else 0, 1)

    return ObservabilityMetrics(
        total_hooks_configured=total_configured,
        critical_present=sum(1 for h in critical if h.present),
        critical_total=len(critical),
        important_present=sum(1 for h in important if h.present),
        important_total=len(important),
        coverage_pct=coverage_pct,
        hooks=hook_results,
        has_agent_tracing=_hook_present(hooks, "PostToolUse", "Task"),
        has_session_logging=_hook_present(hooks, "Stop", ""),
        has_memory_preservation=_hook_present(hooks, "PreCompact", ""),
    )


def _load_all_rules(claude_dir: Path, root: Path) -> list[tuple[str, str]]:
    """Return list of (label, content) for all rule files, capped at MAX_RULE_FILES."""
    rules: list[tuple[str, str]] = []

    def _add_dir(d: Path, prefix: str) -> None:
        if not d.exists() or not d.is_dir():
            return
        for f in d.rglob("*.md"):
            if len(rules) >= MAX_RULE_FILES:
                break
            content = _safe_read(f)
            if not content:
                continue
            try:
                label = f"{prefix}/{f.relative_to(d)}"
            except ValueError:
                label = f.name
            rules.append((label, content))

    _add_dir(claude_dir / "rules", ".claude/rules")

    home_rules = Path.home() / ".claude" / "rules"
    if home_rules != claude_dir / "rules":
        _add_dir(home_rules, "~/.claude/rules")

    if len(rules) < MAX_RULE_FILES:
        claude_md = root / "CLAUDE.md"
        if claude_md.exists():
            content = _safe_read(claude_md)
            if content:
                rules.append(("CLAUDE.md", content))

    return rules


def _analyze_rule_architecture(rules: list[tuple[str, str]]) -> RuleArchMetrics:
    # Problem coverage
    coverage: list[ProblemCoverage] = []
    for problem, keywords in PROBLEM_KEYWORDS.items():
        covering: list[str] = []
        for label, content in rules:
            combined = label.lower() + " " + content.lower()
            if sum(1 for kw in keywords if kw in combined) >= 2:
                covering.append(label)
        coverage.append(ProblemCoverage(
            problem=problem,
            label=PROBLEM_LABELS[problem],
            description=PROBLEM_DESCRIPTIONS[problem],
            covered=bool(covering),
            covering_rules=covering[:5],
        ))

    covered_count = sum(1 for c in coverage if c.covered)

    # Overlap detection — pairwise Jaccard on substantial rules
    substantial = [(lbl, txt) for lbl, txt in rules if len(txt.splitlines()) > MIN_RULE_LINES]
    overlapping: list[RuleOverlap] = []
    kw_cache = {lbl: _extract_keywords(txt) for lbl, txt in substantial}

    for i, (lbl_a, _) in enumerate(substantial):
        for lbl_b, _ in substantial[i + 1:]:
            kw_a = kw_cache[lbl_a]
            kw_b = kw_cache[lbl_b]
            if not kw_a or not kw_b:
                continue
            shared = kw_a & kw_b
            union = kw_a | kw_b
            jaccard = len(shared) / len(union) if union else 0.0
            if jaccard >= OVERLAP_THRESHOLD:
                overlapping.append(RuleOverlap(
                    rule_a=lbl_a,
                    rule_b=lbl_b,
                    overlap_pct=round(jaccard * 100),   # integer for consistent display
                    shared_keywords=sorted(shared)[:10],
                ))

    overlapping.sort(key=lambda x: -x.overlap_pct)

    return RuleArchMetrics(
        total_rules=len(rules),
        problem_coverage=coverage,
        covered_count=covered_count,
        uncovered_count=4 - covered_count,
        overlapping_pairs=overlapping[:MAX_OVERLAP_PAIRS],
    )


def _analyze_agent_setup(root: Path, claude_dir: Path, settings: dict[str, Any] | None = None) -> AgentSetupMetrics:
    # Memory system — check standard locations
    memory_paths = [
        Path.home() / ".claude" / "projects",
        claude_dir / "MEMORY.md",
        root / "CLAUDE.md",
    ]
    has_memory = any(p.exists() for p in memory_paths)

    # Recall script detection
    recall_candidates = [
        root / "scripts" / "core" / "recall_learnings.py",
        root / "opc" / "scripts" / "core" / "recall_learnings.py",
    ]
    has_recall = any(rc.exists() for rc in recall_candidates)

    # Find the most relevant MEMORY.md
    mem_file: Path | None = None
    auto_mem = Path.home() / ".claude" / "projects"
    if auto_mem.exists() and auto_mem.is_dir():
        try:
            for proj_dir in auto_mem.iterdir():
                mem = proj_dir / "memory" / "MEMORY.md"
                if mem.exists():
                    mem_file = mem
                    break
        except PermissionError:
            pass

    if mem_file is None and (root / "CLAUDE.md").exists():
        mem_file = root / "CLAUDE.md"

    memory_entry_count = 0
    if mem_file:
        content = _safe_read(mem_file)
        if content:
            memory_entry_count = sum(
                1 for line in content.splitlines()
                if line.strip() and not line.startswith("#")
            )

    # Spawner skills
    spawner_dir = Path.home() / ".spawner" / "skills"
    has_spawner = False
    if spawner_dir.exists() and spawner_dir.is_dir():
        try:
            has_spawner = any(spawner_dir.iterdir())
        except PermissionError:
            pass

    # Agent types found in rules
    all_rule_content = ""
    for rules_dir in (claude_dir / "rules", Path.home() / ".claude" / "rules"):
        if rules_dir.exists() and rules_dir.is_dir():
            for f in rules_dir.rglob("*.md"):
                c = _safe_read(f)
                if c:
                    all_rule_content += c.lower() + "\n"

    found_agents = [kw for kw in AGENT_KEYWORDS if kw in all_rule_content]
    has_specialized = len(found_agents) >= MIN_SPECIALIZED_AGENTS
    has_orchestrator = any(kw in all_rule_content for kw in ORCHESTRATOR_KEYWORDS)

    has_mcp, mcp_count, mcp_names = _extract_mcp_servers(settings or {})

    return AgentSetupMetrics(
        has_memory_system=has_memory,
        has_recall_script=has_recall,
        has_spawner_skills=has_spawner,
        agent_types_found=found_agents,
        has_specialized_agents=has_specialized,
        has_orchestrator_pattern=has_orchestrator,
        memory_entry_count=memory_entry_count,
        has_mcp_servers=has_mcp,
        mcp_server_count=mcp_count,
        mcp_server_names=mcp_names,
    )


def _detect_issues_and_score(report: AgentPatternReport) -> tuple[list[dict], int]:
    score = 100
    issues: list[dict[str, Any]] = list(report.issues)

    # Autonomy
    if report.autonomy:
        a = report.autonomy
        if a.risk_level == "HIGH":
            penalty = 25
            score -= penalty
            if a.default_mode == "bypassPermissions":
                issues.append({
                    "severity": "critical",
                    "category": "autonomy",
                    "message": "Permission mode is bypassPermissions — Claude operates with zero human oversight. All tool calls execute without confirmation.",
                    "impact": f"-{penalty} points",
                })
            else:
                issues.append({
                    "severity": "critical",
                    "category": "autonomy",
                    "message": f"Permission mode is '{a.default_mode}' with no ask rules defined. Agents run without any approval gates.",
                    "impact": f"-{penalty} points",
                })
        elif a.risk_level == "MEDIUM":
            penalty = 10
            score -= penalty
            issues.append({
                "severity": "warning",
                "category": "autonomy",
                "message": f"Autonomy risk is MEDIUM (mode: {a.default_mode}). Consider adding deny rules and ask rules for destructive operations.",
                "impact": f"-{penalty} points",
            })

        if a.broad_allow_patterns and not a.deny_count:
            penalty = 8
            score -= penalty
            issues.append({
                "severity": "warning",
                "category": "autonomy",
                "message": f"Broad allow rules ({', '.join(a.broad_allow_patterns[:3])}) with no deny rules. Any tool call in these categories runs unchecked.",
                "impact": f"-{penalty} points",
            })

    # Observability
    if report.observability:
        obs = report.observability
        if not obs.has_agent_tracing:
            penalty = 20
            score -= penalty
            issues.append({
                "severity": "critical",
                "category": "observability",
                "message": "No agent tracing hook (PostToolUse:Task). Every spawned agent is a black box — you cannot debug failures or audit behavior.",
                "impact": f"-{penalty} points",
            })
        if not obs.has_session_logging:
            penalty = 15
            score -= penalty
            issues.append({
                "severity": "critical",
                "category": "observability",
                "message": "No session logging hook (Stop). Silent failures and undocumented changes between sessions.",
                "impact": f"-{penalty} points",
            })
        if obs.coverage_pct < 50:
            penalty = 10
            score -= penalty
            issues.append({
                "severity": "warning",
                "category": "observability",
                "message": f"Observability coverage is {obs.coverage_pct}%. Less than half of recommended hooks are configured.",
                "impact": f"-{penalty} points",
            })

    # Rule architecture
    if report.rule_arch:
        ra = report.rule_arch
        if ra.uncovered_count >= 2:
            penalty = ra.uncovered_count * 5
            score -= penalty
            uncovered = [c.label for c in ra.problem_coverage if not c.covered]
            issues.append({
                "severity": "warning",
                "category": "rule_architecture",
                "message": f"{ra.uncovered_count} of 4 problem types have no rule coverage: {', '.join(uncovered)}.",
                "impact": f"-{penalty} points",
            })
        if ra.overlapping_pairs:
            penalty = min(10, len(ra.overlapping_pairs) * 2)
            score -= penalty
            issues.append({
                "severity": "info",
                "category": "rule_architecture",
                "message": f"{len(ra.overlapping_pairs)} rule file pairs share significant content ({ra.overlapping_pairs[0].overlap_pct}% overlap on highest pair). Consider consolidating.",
                "impact": f"-{penalty} points",
            })

    # Agent setup
    if report.agent_setup:
        ag = report.agent_setup
        if not ag.has_memory_system:
            penalty = 5
            score -= penalty
            issues.append({
                "severity": "info",
                "category": "agent_setup",
                "message": "No memory/RAG system detected. Agents rely entirely on in-context knowledge — domain gaps can't be filled dynamically.",
                "impact": f"-{penalty} points",
            })
        if ag.has_mcp_servers and report.autonomy and not report.autonomy.deny_count:
            penalty = 5
            score -= penalty
            server_list = ", ".join(ag.mcp_server_names[:3]) + ("..." if ag.mcp_server_count > 3 else "")
            issues.append({
                "severity": "warning",
                "category": "agent_setup",
                "message": f"{ag.mcp_server_count} MCP server(s) configured ({server_list}) but no deny rules. MCP tools expand Claude's action surface — add deny rules for sensitive operations.",
                "impact": f"-{penalty} points",
            })

    # Secrets exposure
    if report.secrets_exposed:
        penalty = 15
        score -= penalty
        files = ", ".join(set(s["file"].split("/")[-1] for s in report.secrets_exposed[:3]))
        issues.append({
            "severity": "critical",
            "category": "security",
            "message": f"Potential secrets detected in workspace files ({files}). API keys or tokens in .claude/ files could be committed to version control.",
            "impact": f"-{penalty} points",
        })

    return issues, max(0, min(100, score))


def _generate_recommendations(report: AgentPatternReport) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []

    if report.autonomy and report.autonomy.risk_level == "HIGH":
        recs.append({
            "priority": "P0",
            "title": "Add approval gates for destructive operations",
            "description": "Set defaultMode to 'default' and add ask rules for Bash, Write, and Delete operations. Agents should earn trust incrementally — start with human-in-the-loop for all file system changes.",
            "estimated_time": "10 minutes",
            "impact": "Prevent unreviewed destructive actions from autonomous agents",
        })

    if report.observability and not report.observability.has_agent_tracing:
        recs.append({
            "priority": "P0",
            "title": "Add a PostToolUse:Task hook for agent tracing",
            "description": "Configure a PostToolUse hook with matcher 'Task' that logs the agent type, prompt summary, and outcome to a file or database. Without this, every agent failure requires manual reconstruction of what happened.",
            "estimated_time": "20 minutes",
            "impact": "Full visibility into every agent execution",
        })

    if report.observability and not report.observability.has_session_logging:
        recs.append({
            "priority": "P0",
            "title": "Add a Stop hook for session completion logging",
            "description": "A Stop hook fires when Claude finishes (including on clear, compact, and resume). Use it to write a brief summary of what changed to a log file or your knowledge system.",
            "estimated_time": "15 minutes",
            "impact": "Audit trail of every session — what changed, what was decided",
        })

    if report.observability and not report.observability.has_memory_preservation:
        recs.append({
            "priority": "P1",
            "title": "Add a PreCompact hook to preserve key context",
            "description": "Before compaction, Claude can be prompted to extract important decisions, open threads, and architectural choices into your memory system. Without this, context compaction silently discards reasoning.",
            "estimated_time": "15 minutes",
            "impact": "No more lost context across long sessions",
        })

    if report.observability and not any(
        h.present for h in report.observability.hooks if h.event == "SessionStart"
    ):
        recs.append({
            "priority": "P1",
            "title": "Add a SessionStart hook for auto-recall",
            "description": "At session start, automatically query your memory system using git context (current branch, recent commits, cwd) to surface relevant prior learnings. Every session currently starts cold.",
            "estimated_time": "30 minutes",
            "impact": "Prior solutions and decisions surfaced automatically — no re-solving the same problems",
        })

    if report.rule_arch:
        uncovered = [c for c in report.rule_arch.problem_coverage if not c.covered]
        if uncovered:
            recs.append({
                "priority": "P1",
                "title": f"Add rules for uncovered problem types: {', '.join(c.label for c in uncovered)}",
                "description": "Every LLM technique exists to solve one of four problems: domain gaps, context limits, hallucinations, or control. You have no rules covering: " + ", ".join(c.description for c in uncovered),
                "estimated_time": "20-40 minutes",
                "impact": f"Close {len(uncovered)} architectural blind spot{'s' if len(uncovered) > 1 else ''}",
            })
        if report.rule_arch.overlapping_pairs:
            top = report.rule_arch.overlapping_pairs[0]
            recs.append({
                "priority": "P2",
                "title": "Consolidate overlapping rule files",
                "description": f"Top overlap: {top.rule_a} and {top.rule_b} share {top.overlap_pct}% of meaningful content. Duplicated instructions add noise to every session without adding clarity.",
                "estimated_time": "20-30 minutes per pair",
                "impact": "Cleaner context, less instruction conflict",
            })

    if report.secrets_exposed:
        recs.append({
            "priority": "P0",
            "title": "Remove secrets from workspace files",
            "description": f"Potential API keys or tokens were detected in {len(report.secrets_exposed)} workspace file(s). Move all secrets to environment variables or a .secrets file outside your project. Ensure .claude/settings.local.json is in .gitignore.",
            "estimated_time": "10 minutes",
            "impact": "Prevent credential exposure in version control",
        })

    if report.agent_setup and not report.agent_setup.has_recall_script:
        recs.append({
            "priority": "P2",
            "title": "Set up a semantic memory + recall system",
            "description": "A vector-backed memory system (pgvector or SQLite + embeddings) lets agents retrieve relevant past solutions at query time rather than baking all domain knowledge into always-on rules. This is the RAG pattern applied to your workflow.",
            "estimated_time": "2-4 hours to set up",
            "impact": "Domain knowledge that stays fresh and is retrievable on demand",
        })

    return recs


# ── SDK detection helper (for app-mode routing) ───────────────────────────────

def _detect_sdk_imports(root: Path) -> bool:
    """Return True if any Python or TS/JS file imports the Anthropic SDK."""
    import re as _re
    py_pats = [
        _re.compile(r'import\s+anthropic'),
        _re.compile(r'from\s+anthropic\s+import'),
        _re.compile(r'anthropic\.Anthropic\('),
        _re.compile(r'AsyncAnthropic\('),
    ]
    ts_pats = [
        _re.compile(r'from\s+["\']@anthropic-ai/sdk["\']'),
        _re.compile(r'require\(["\']@anthropic-ai/sdk["\']'),
        _re.compile(r'new\s+Anthropic\('),
    ]
    globs = list(root.rglob("*.py"))[:200] + list(root.rglob("*.ts"))[:200] + list(root.rglob("*.js"))[:200]
    for path in globs:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            pats = py_pats if path.suffix == ".py" else ts_pats
            if any(p.search(text) for p in pats):
                return True
        except OSError:
            continue
    return False


# ── Main entry point ──────────────────────────────────────────────────────────

def scan_workspace(workspace_path: str | None = None) -> AgentPatternReport:
    """Scan a Claude Code workspace for agent architecture pattern quality.

    Args:
        workspace_path: Absolute or relative path to the project root.
                        Defaults to the current working directory.

    Returns:
        AgentPatternReport with all metrics populated.
    """
    resolved = workspace_path or os.getcwd()
    root = Path(resolved).resolve()

    if not root.exists():
        report = AgentPatternReport(workspace_path=str(root))
        report.issues.append({
            "severity": "error",
            "category": "structure",
            "message": f"Path does not exist: {root}",
        })
        return report

    if not root.is_dir():
        report = AgentPatternReport(workspace_path=str(root))
        report.issues.append({
            "severity": "error",
            "category": "structure",
            "message": f"Path is not a directory: {root}",
        })
        return report

    report = AgentPatternReport(workspace_path=str(root))

    # Locate .claude/
    claude_dir = root / ".claude"
    used_fallback = False
    if not claude_dir.exists():
        # Don't fall back to global config — check if this is an SDK app instead
        from .app_scanner import scan_app, PY_SDK_PATTERNS, TS_SDK_PATTERNS
        sdk_found = _detect_sdk_imports(root)
        if sdk_found:
            # Route to app-mode scanner; caller (cli.py) handles AppAuditReport
            return scan_app(str(root))  # type: ignore[return-value]
        report.issues.append({
            "severity": "error",
            "category": "structure",
            "message": (
                "No .claude/ directory found. "
                "This does not appear to be a Claude Code workspace or Claude SDK application."
            ),
        })
        return report

    report.claude_dir_path = str(claude_dir)
    report.used_fallback = used_fallback

    settings = _load_settings(claude_dir)
    rules = _load_all_rules(claude_dir, root)

    report.autonomy = _analyze_autonomy(settings)
    report.observability = _analyze_observability(settings)
    report.rule_arch = _analyze_rule_architecture(rules)
    report.agent_setup = _analyze_agent_setup(root, claude_dir, settings)
    report.secrets_exposed = _check_secrets_in_files(claude_dir, root)

    report.issues, report.architecture_score = _detect_issues_and_score(report)
    report.recommendations = _generate_recommendations(report)

    return report
