"""App-mode scanner — audits application source code for Claude SDK usage patterns.

Detects reliability, safety, and quality issues in Python and TypeScript/JavaScript
projects that call the Anthropic Claude API directly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Limits ────────────────────────────────────────────────────────────────────
MAX_FILE_SIZE = 524_288   # 512 KB
MAX_SOURCE_FILES = 500

# ── SDK detection patterns ────────────────────────────────────────────────────
PY_SDK_PATTERNS = [
    re.compile(r'import\s+anthropic'),
    re.compile(r'from\s+anthropic\s+import'),
    re.compile(r'anthropic\.Anthropic\('),
    re.compile(r'AsyncAnthropic\('),
]

TS_SDK_PATTERNS = [
    re.compile(r'from\s+["\']@anthropic-ai/sdk["\']'),
    re.compile(r'require\(["\']@anthropic-ai/sdk["\']'),
    re.compile(r'new\s+Anthropic\('),
    re.compile(r'new\s+AnthropicVertex\('),
    re.compile(r'new\s+AnthropicBedrock\('),
]

# Known Claude model string prefixes
MODEL_PATTERN = re.compile(
    r'["\'](?:claude-(?:opus|sonnet|haiku|3|4|instant|2|claude)[^"\']{0,40})["\']'
)

# API key leak
API_KEY_PATTERN = re.compile(r'sk-ant-[A-Za-z0-9\-_]{20,}')

# Retry-related signals
RETRY_SIGNALS = re.compile(
    r'tenacity|@retry|backoff|retry_with|for\s+attempt|max_retries|RateLimitError|'
    r'status_code\s*==\s*429|exponential_backoff|retry_on_exception|withRetry|'
    r'p-retry|axios-retry|retry\(', re.IGNORECASE
)

# ── Dataclasses ───────────────────────────────────────────────────────────────

@dataclass
class AppFinding:
    severity: str          # critical | high | medium | low | info
    category: str          # security | reliability | safety | quality
    title: str
    message: str
    file: str
    line: int | None = None
    snippet: str = ""
    fix: str = ""


@dataclass
class AppAuditReport:
    project_path: str
    language: str = "unknown"           # python | typescript | mixed | unknown
    sdk_files: list[str] = field(default_factory=list)
    findings: list[AppFinding] = field(default_factory=list)
    score: int = 100
    api_call_count: int = 0
    tool_definition_count: int = 0
    has_retry_logic: bool = False
    has_streaming: bool = False
    hardcoded_models: list[str] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    is_claude_project: bool = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read(path: Path) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_SIZE:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _lines(content: str) -> list[str]:
    return content.splitlines()


def _snippet(lines: list[str], line_num: int, context: int = 2) -> str:
    """Return a code snippet around a line number (1-indexed)."""
    start = max(0, line_num - 1 - context)
    end = min(len(lines), line_num + context)
    result = []
    for i, ln in enumerate(lines[start:end], start=start + 1):
        marker = ">" if i == line_num else " "
        result.append(f"{marker} {i:4d} | {ln}")
    return "\n".join(result)


def _in_try_block(lines: list[str], call_line: int, lookback: int = 15) -> bool:
    """Heuristic: check if a call_line (1-indexed) is inside a try block."""
    start = max(0, call_line - lookback - 1)
    for ln in lines[start: call_line - 1]:
        stripped = ln.strip()
        if stripped.startswith("try:") or stripped == "try:":
            return True
        # TypeScript / JS
        if stripped.startswith("try {") or stripped == "try {":
            return True
    return False


def _has_max_tokens(lines: list[str], call_line: int, lookahead: int = 15) -> bool:
    """Check if max_tokens / maxTokens appears near an API call."""
    end = min(len(lines), call_line - 1 + lookahead)
    window = "\n".join(lines[call_line - 1: end])
    return bool(re.search(r'max_tokens|maxTokens', window))


def _call_closes_within(lines: list[str], call_line: int, lookahead: int = 20) -> int:
    """Return the line where the create() call closes (rough heuristic)."""
    depth = 0
    for i, ln in enumerate(lines[call_line - 1: call_line - 1 + lookahead], start=call_line):
        depth += ln.count("(") - ln.count(")")
        if depth <= 0 and i > call_line:
            return i
    return call_line + lookahead


# ── Python checks ─────────────────────────────────────────────────────────────

def _check_python_file(path: Path, content: str, report: AppAuditReport) -> None:
    fname = str(path)
    lines = _lines(content)

    # ── API calls ────────────────────────────────────────────────────────────
    create_pattern = re.compile(r'\.messages\.create\(|\.messages\.stream\(')
    for m in create_pattern.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        report.api_call_count += 1

        is_stream = "stream" in m.group(0)
        if is_stream:
            report.has_streaming = True

        # Error handling
        if not _in_try_block(lines, line_num):
            report.findings.append(AppFinding(
                severity="high",
                category="reliability",
                title="API call without error handling",
                message=f"messages.create() at line {line_num} is not wrapped in a try/except block. "
                        "Network errors, rate limits (429), and overloads (529) will crash your app.",
                file=fname,
                line=line_num,
                snippet=_snippet(lines, line_num),
                fix='Wrap with try/except anthropic.APIStatusError as e: handle e.status_code',
            ))

        # max_tokens
        if not is_stream and not _has_max_tokens(lines, line_num):
            report.findings.append(AppFinding(
                severity="medium",
                category="reliability",
                title="Missing max_tokens",
                message=f"messages.create() at line {line_num} has no max_tokens set. "
                        "Without it, Claude can return very long responses and exhaust your budget.",
                file=fname,
                line=line_num,
                snippet=_snippet(lines, line_num),
                fix='Add max_tokens=1024 (or appropriate limit) to every create() call.',
            ))

    # ── Hardcoded model strings ───────────────────────────────────────────────
    for m in MODEL_PATTERN.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        model_str = m.group(0).strip("'\"")
        if model_str not in report.hardcoded_models:
            report.hardcoded_models.append(model_str)
        report.findings.append(AppFinding(
            severity="low",
            category="quality",
            title="Hardcoded model string",
            message=f'Model "{model_str}" is hardcoded at line {line_num}. '
                    "When you want to upgrade models, you'll need to grep the codebase.",
            file=fname,
            line=line_num,
            snippet=_snippet(lines, line_num),
            fix='Move to a config constant: MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")',
        ))

    # ── API key in source ─────────────────────────────────────────────────────
    for m in API_KEY_PATTERN.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        report.findings.append(AppFinding(
            severity="critical",
            category="security",
            title="Anthropic API key exposed in source",
            message=f"Hardcoded API key detected at line {line_num}. "
                    "This will be committed to version control and exposed to anyone with repo access.",
            file=fname,
            line=line_num,
            snippet=_snippet(lines, line_num),
            fix='Remove the key. Use os.getenv("ANTHROPIC_API_KEY") and store in .env (gitignored).',
        ))

    # ── Prompt injection surface ──────────────────────────────────────────────
    injection_pattern = re.compile(
        r'(?:system|content|prompt)\s*=\s*f["\'].*?\{[^}]+\}|'
        r'f["\'].*?\{(?:user_input|request|query|message|text|data|payload|body)[^}]*\}',
        re.IGNORECASE
    )
    for m in injection_pattern.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        report.findings.append(AppFinding(
            severity="high",
            category="security",
            title="Potential prompt injection surface",
            message=f"User-controlled variable interpolated directly into a prompt at line {line_num}. "
                    "Without sanitization, attackers can override instructions or exfiltrate data.",
            file=fname,
            line=line_num,
            snippet=_snippet(lines, line_num),
            fix='Sanitize user input before interpolation. Use a safe template with role separation.',
        ))

    # ── Raw content access without null check ────────────────────────────────
    raw_access = re.compile(r'\.content\[0\]\.text|\.content\[0\]\[.text.\]')
    for m in raw_access.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        # Check if there's a guard nearby
        window_start = max(0, line_num - 3)
        window = "\n".join(lines[window_start: line_num])
        if "if" not in window and "content" not in window.lower().replace(m.group(0), ""):
            report.findings.append(AppFinding(
                severity="medium",
                category="reliability",
                title="Unguarded response access",
                message=f".content[0].text at line {line_num} can IndexError if the response has no content blocks "
                        "(e.g., on a tool_use stop reason or empty response).",
                file=fname,
                line=line_num,
                snippet=_snippet(lines, line_num),
                fix='Check: if response.content and response.content[0].type == "text": text = response.content[0].text',
            ))

    # ── Tool definitions without descriptions ────────────────────────────────
    tool_def_pattern = re.compile(r'"type"\s*:\s*"function"|"type"\s*:\s*"tool"', re.IGNORECASE)
    for m in tool_def_pattern.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        report.tool_definition_count += 1
        # Check for description in the surrounding JSON block (next 10 lines)
        end = min(len(lines), line_num + 10)
        block = "\n".join(lines[line_num - 1: end])
        if '"description"' not in block:
            report.findings.append(AppFinding(
                severity="low",
                category="quality",
                title="Tool definition missing description",
                message=f"Tool defined at line {line_num} has no 'description' field. "
                        "Claude uses descriptions to decide when and how to call tools.",
                file=fname,
                line=line_num,
                snippet=_snippet(lines, line_num),
                fix='Add "description": "What this tool does and when to use it" to every tool definition.',
            ))

    # ── Streaming check for large content ────────────────────────────────────
    # If file does create() calls but no streaming at all, flag as info
    if report.api_call_count > 0 and not report.has_streaming:
        # Only flag once per file if it has multiple creates
        non_streaming = list(create_pattern.finditer(content))
        if len(non_streaming) >= 2:
            report.findings.append(AppFinding(
                severity="info",
                category="quality",
                title="No streaming used",
                message=f"{fname} makes {len(non_streaming)} API calls with no streaming. "
                        "For user-facing text, streaming reduces perceived latency significantly.",
                file=fname,
                snippet="",
                fix='Use client.messages.stream() context manager for real-time output.',
            ))


# ── TypeScript/JS checks ──────────────────────────────────────────────────────

def _check_ts_file(path: Path, content: str, report: AppAuditReport) -> None:
    fname = str(path)
    lines = _lines(content)

    # ── API calls ────────────────────────────────────────────────────────────
    create_pattern = re.compile(r'\.messages\.create\(|messages\.stream\(')
    for m in create_pattern.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        report.api_call_count += 1

        is_stream = "stream" in m.group(0)
        if is_stream:
            report.has_streaming = True

        # Error handling — check for try { or .catch(
        if not _in_try_block(lines, line_num):
            window = content[max(0, m.start() - 200): m.end() + 200]
            if ".catch(" not in window and "catch (e" not in window and "catch(e" not in window:
                report.findings.append(AppFinding(
                    severity="high",
                    category="reliability",
                    title="API call without error handling",
                    message=f"messages.create() at line {line_num} has no try/catch or .catch() handler. "
                            "Rate limits and network errors will be unhandled rejections.",
                    file=fname,
                    line=line_num,
                    snippet=_snippet(lines, line_num),
                    fix='Wrap with try { ... } catch (e) { if (e instanceof Anthropic.APIError) ... }',
                ))

        # maxTokens
        if not _has_max_tokens(lines, line_num):
            report.findings.append(AppFinding(
                severity="medium",
                category="reliability",
                title="Missing maxTokens",
                message=f"messages.create() at line {line_num} has no maxTokens set.",
                file=fname,
                line=line_num,
                snippet=_snippet(lines, line_num),
                fix='Add maxTokens: 1024 (or appropriate limit) to every create() call.',
            ))

    # ── Hardcoded models ──────────────────────────────────────────────────────
    for m in MODEL_PATTERN.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        model_str = m.group(0).strip("'\"")
        if model_str not in report.hardcoded_models:
            report.hardcoded_models.append(model_str)
        report.findings.append(AppFinding(
            severity="low",
            category="quality",
            title="Hardcoded model string",
            message=f'Model "{model_str}" is hardcoded at line {line_num}.',
            file=fname,
            line=line_num,
            snippet=_snippet(lines, line_num),
            fix='const MODEL = process.env.ANTHROPIC_MODEL ?? "claude-sonnet-4-6";',
        ))

    # ── API key ───────────────────────────────────────────────────────────────
    for m in API_KEY_PATTERN.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        report.findings.append(AppFinding(
            severity="critical",
            category="security",
            title="Anthropic API key exposed in source",
            message=f"Hardcoded API key at line {line_num}.",
            file=fname,
            line=line_num,
            snippet=_snippet(lines, line_num),
            fix='Use process.env.ANTHROPIC_API_KEY and store in .env (add to .gitignore).',
        ))

    # ── Template literal injection ─────────────────────────────────────────────
    injection_pattern = re.compile(
        r'`[^`]*\$\{(?:user|input|request|query|message|body|text|data|payload)[^}]*\}[^`]*`',
        re.IGNORECASE
    )
    for m in injection_pattern.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        report.findings.append(AppFinding(
            severity="high",
            category="security",
            title="Potential prompt injection surface",
            message=f"User-controlled value interpolated into a template literal at line {line_num}.",
            file=fname,
            line=line_num,
            snippet=_snippet(lines, line_num),
            fix='Sanitize user input. Keep user content in the "user" role, not the system prompt.',
        ))


# ── Language detection ────────────────────────────────────────────────────────

def _is_sdk_file_py(content: str) -> bool:
    return any(p.search(content) for p in PY_SDK_PATTERNS)


def _is_sdk_file_ts(content: str) -> bool:
    return any(p.search(content) for p in TS_SDK_PATTERNS)


def _collect_source_files(root: Path) -> tuple[list[Path], list[Path]]:
    """Return (py_files, ts_files) excluding venvs, node_modules, etc."""
    SKIP_DIRS = {
        ".git", ".venv", "venv", "__pycache__", "node_modules", ".next",
        "dist", "build", ".nuxt", ".turbo", "coverage", ".pytest_cache",
        "site-packages", "agent-audit",
    }

    py_files: list[Path] = []
    ts_files: list[Path] = []
    count = 0

    for path in root.rglob("*"):
        if count >= MAX_SOURCE_FILES:
            break
        if any(skip in path.parts for skip in SKIP_DIRS):
            continue
        if not path.is_file():
            continue
        if path.suffix == ".py":
            py_files.append(path)
            count += 1
        elif path.suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs"):
            ts_files.append(path)
            count += 1

    return py_files, ts_files


# ── Scoring ───────────────────────────────────────────────────────────────────

SEVERITY_PENALTIES = {
    "critical": 20,
    "high": 12,
    "medium": 7,
    "low": 3,
    "info": 0,
}

# Deduplicate penalty per (category, title) — don't hammer score for same issue in many files
MAX_PENALTY_PER_CHECK = {
    "critical": 40,
    "high": 24,
    "medium": 14,
    "low": 9,
    "info": 0,
}


def _compute_score(findings: list[AppFinding]) -> int:
    score = 100
    # Track total penalty per (category, title)
    per_check: dict[str, int] = {}
    for f in findings:
        key = f"{f.severity}:{f.title}"
        current = per_check.get(key, 0)
        cap = MAX_PENALTY_PER_CHECK.get(f.severity, 0)
        penalty = SEVERITY_PENALTIES.get(f.severity, 0)
        additional = min(penalty, cap - current)
        per_check[key] = current + additional
        score -= additional
    return max(0, score)


# ── Recommendations ───────────────────────────────────────────────────────────

def _build_recommendations(report: AppAuditReport) -> list[dict[str, Any]]:
    recs: list[dict[str, Any]] = []
    categories_found = {f.category for f in report.findings}
    severities_found = {f.severity for f in report.findings}

    if "critical" in severities_found:
        criticals = [f for f in report.findings if f.severity == "critical"]
        recs.append({
            "priority": "P0",
            "title": f"Fix {len(criticals)} critical security issue(s)",
            "description": "\n".join(f"- {f.title} in {Path(f.file).name}" + (f" (line {f.line})" if f.line else "") for f in criticals),
            "fix_snippets": [f.fix for f in criticals if f.fix],
            "estimated_time": "30 minutes",
            "impact": "Prevent credential exposure and security breaches",
        })

    no_error_handling = [f for f in report.findings if f.title == "API call without error handling"]
    if no_error_handling:
        recs.append({
            "priority": "P0",
            "title": f"Add error handling to {len(no_error_handling)} API call(s)",
            "description": "Rate limits (429), overloads (529), and network errors will crash unhandled. "
                           "Wrap all messages.create() calls.",
            "fix_snippets": [
                "# Python\ntry:\n    response = client.messages.create(...)\nexcept anthropic.RateLimitError:\n    time.sleep(60); raise\nexcept anthropic.APIStatusError as e:\n    logger.error(f'API error {e.status_code}: {e.message}'); raise",
                "// TypeScript\ntry {\n  const response = await client.messages.create(...);\n} catch (e) {\n  if (e instanceof Anthropic.RateLimitError) { await sleep(60000); throw e; }\n  if (e instanceof Anthropic.APIError) { console.error(e.status, e.message); throw e; }\n}",
            ],
            "estimated_time": "1-2 hours",
            "impact": "Resilient app that handles rate limits and transient failures gracefully",
        })

    no_max_tokens = [f for f in report.findings if f.title in ("Missing max_tokens", "Missing maxTokens")]
    if no_max_tokens:
        recs.append({
            "priority": "P1",
            "title": f"Add max_tokens to {len(no_max_tokens)} API call(s)",
            "description": "Without max_tokens, Claude can return very long responses. "
                           "This burns budget and slows response time.",
            "fix_snippets": [
                "# Add to every create() call\nresponse = client.messages.create(\n    model=MODEL,\n    max_tokens=1024,  # set appropriate limit\n    messages=[...]\n)",
            ],
            "estimated_time": "30 minutes",
            "impact": "Predictable costs and response times",
        })

    if not report.has_retry_logic and report.api_call_count > 0:
        recs.append({
            "priority": "P1",
            "title": "Add retry logic for rate limits",
            "description": "No retry or backoff mechanism detected. Production apps hitting Claude at scale will encounter 429s.",
            "fix_snippets": [
                "# Python — install tenacity\nfrom tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type\n\n@retry(\n    retry=retry_if_exception_type(anthropic.RateLimitError),\n    wait=wait_exponential(min=1, max=60),\n    stop=stop_after_attempt(5),\n)\ndef call_claude(client, **kwargs):\n    return client.messages.create(**kwargs)",
            ],
            "estimated_time": "1 hour",
            "impact": "Automatic recovery from rate limits without crashing",
        })

    hardcoded_models = [f for f in report.findings if f.title == "Hardcoded model string"]
    if hardcoded_models:
        unique_models = list(dict.fromkeys(f.message.split('"')[1] for f in hardcoded_models if '"' in f.message))
        recs.append({
            "priority": "P2",
            "title": f"Move {len(hardcoded_models)} model string(s) to config",
            "description": f"Found hardcoded: {', '.join(unique_models[:5])}. "
                           "Changing models requires a grep-and-replace across the codebase.",
            "fix_snippets": [
                '# Python\nMODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")\n\n# TypeScript\nconst MODEL = process.env.ANTHROPIC_MODEL ?? "claude-sonnet-4-6";',
            ],
            "estimated_time": "20 minutes",
            "impact": "Model upgrades with a single env var change",
        })

    injection_issues = [f for f in report.findings if "injection" in f.title.lower()]
    if injection_issues:
        recs.append({
            "priority": "P0",
            "title": f"Fix {len(injection_issues)} prompt injection surface(s)",
            "description": "User-controlled input is interpolated directly into prompts without sanitization.",
            "fix_snippets": [
                '# Keep user content in the user role — never in system prompt\nmessages = [\n    {"role": "system", "content": FIXED_SYSTEM_PROMPT},\n    {"role": "user", "content": user_input}  # user input isolated here\n]',
            ],
            "estimated_time": "1-2 hours",
            "impact": "Prevent prompt injection attacks and instruction override",
        })

    if not report.has_streaming and report.api_call_count > 0:
        recs.append({
            "priority": "P2",
            "title": "Consider streaming for user-facing responses",
            "description": "All API calls use blocking mode. For chat or document UIs, streaming dramatically improves perceived responsiveness.",
            "fix_snippets": [
                "# Python streaming\nwith client.messages.stream(\n    model=MODEL,\n    max_tokens=1024,\n    messages=[...]\n) as stream:\n    for text in stream.text_stream:\n        print(text, end='', flush=True)",
            ],
            "estimated_time": "1-3 hours per endpoint",
            "impact": "Faster perceived responses for users",
        })

    return recs


# ── Main entry point ──────────────────────────────────────────────────────────

def scan_app(project_path: str) -> AppAuditReport:
    """Scan application source code for Claude SDK usage patterns and issues.

    Returns an AppAuditReport regardless of whether SDK usage is detected.
    Check report.is_claude_project to determine if any SDK usage was found.
    """
    root = Path(project_path).resolve()
    report = AppAuditReport(project_path=str(root))

    py_files, ts_files = _collect_source_files(root)

    sdk_py_files: list[Path] = []
    sdk_ts_files: list[Path] = []

    # First pass: identify SDK files and detect retry / streaming signals
    all_content_cache: dict[Path, str] = {}
    for path in py_files + ts_files:
        content = _read(path)
        if not content:
            continue
        all_content_cache[path] = content
        if path.suffix == ".py" and _is_sdk_file_py(content):
            sdk_py_files.append(path)
        elif path.suffix in (".ts", ".tsx", ".js", ".mjs", ".cjs") and _is_sdk_file_ts(content):
            sdk_ts_files.append(path)
        if RETRY_SIGNALS.search(content):
            report.has_retry_logic = True

    report.is_claude_project = bool(sdk_py_files or sdk_ts_files)
    if not report.is_claude_project:
        return report

    # Determine language
    if sdk_py_files and sdk_ts_files:
        report.language = "mixed"
    elif sdk_py_files:
        report.language = "python"
    else:
        report.language = "typescript"

    report.sdk_files = [str(f) for f in sdk_py_files + sdk_ts_files]

    # Second pass: run checks on SDK files only
    for path in sdk_py_files:
        content = all_content_cache[path]
        _check_python_file(path, content, report)

    for path in sdk_ts_files:
        content = all_content_cache[path]
        _check_ts_file(path, content, report)

    # Deduplicate findings with same title+file+line
    seen: set[tuple] = set()
    unique: list[AppFinding] = []
    for f in report.findings:
        key = (f.title, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    report.findings = unique

    report.score = _compute_score(report.findings)
    report.recommendations = _build_recommendations(report)

    return report
