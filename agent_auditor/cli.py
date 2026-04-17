"""CLI entry point for Oaken AI Claude Agent Auditor."""
import argparse
import json
import os
import webbrowser
from pathlib import Path

from . import __version__
from .app_report import generate_app_reports
from .app_scanner import AppAuditReport
from .report import generate_reports
from .scanner import scan_workspace

BANNER = f"""
   _                    _       _             _ _ _
  / \\   __ _  ___ _ __ | |_    / \\  _   _  __| (_) |_ ___  _ __
 / _ \\ / _` |/ _ \\ '_ \\| __|  / _ \\| | | |/ _` | | __/ _ \\| '__|
/ ___ \\ (_| |  __/ | | | |_  / ___ \\ |_| | (_| | | || (_) | |
/_/   \\_\\__, |\\___|_| |_|\\__| /_/   \\_\\__,_|\\__,_|_|\\__\\___/|_|
        |___/

   Claude Agent Auditor v{__version__}
   https://oakenai.tech/tools/claude-agent-auditor
"""


def main():
    parser = argparse.ArgumentParser(
        description="Oaken AI Claude Agent Auditor - Audit your Claude Code agent architecture",
        epilog="Learn more at https://oakenai.tech",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to your project root (default: current directory)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory for reports (default: ./agent-audit/)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the report in your browser after generating",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also output raw metrics as JSON",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress terminal output",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    args = parser.parse_args()

    if not args.quiet:
        print(BANNER)

    # Resolve paths
    workspace_path = os.path.abspath(args.path)
    output_dir = Path(args.output) if args.output else Path(workspace_path) / "agent-audit"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.quiet:
        print(f"  Scanning: {workspace_path}")
        print(f"  Output:   {output_dir}\n")

    # Scan
    report = scan_workspace(workspace_path)

    if isinstance(report, AppAuditReport):
        # App-mode path
        if not args.quiet:
            sev_counts: dict[str, int] = {}
            for f in report.findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            print(f"  Mode:                 APP (Claude SDK)")
            print(f"  Language:             {report.language}")
            print(f"  SDK Files:            {len(report.sdk_files)}")
            print(f"  Score:                {report.score}/100")
            print(f"  Findings:             {len(report.findings)}"
                  + (f"  (critical={sev_counts.get('critical',0)}, high={sev_counts.get('high',0)}, "
                     f"medium={sev_counts.get('medium',0)})" if report.findings else ""))
            print(f"  Recommendations:      {len(report.recommendations)}")
            print()

        pages = generate_app_reports(report)
    else:
        # Workspace-mode path
        if not args.quiet:
            autonomy_risk = report.autonomy.risk_level if report.autonomy else "UNKNOWN"
            risk_label = {
                "LOW": "LOW  [ok]",
                "MEDIUM": "MEDIUM [!]",
                "HIGH": "HIGH [!!]",
            }.get(autonomy_risk, autonomy_risk)
            obs_pct = report.observability.coverage_pct if report.observability else 0

            print(f"  Mode:                 WORKSPACE (Claude Code config)")
            print(f"  Architecture Score:   {report.architecture_score}/100")
            print(f"  Autonomy Risk:        {risk_label}")
            print(f"  Observability:        {obs_pct}%")
            if report.rule_arch:
                covered = sum(1 for c in report.rule_arch.problem_coverage if c.covered)
                print(f"  Problem Types:        {covered}/4 covered")
            if report.agent_setup:
                agent_count = len(report.agent_setup.agent_types_found)
                print(f"  Agent Types Found:    {agent_count}")
            print(f"  Issues:               {len(report.issues)}")
            print(f"  Recommendations:      {len(report.recommendations)}")
            print()

        pages = generate_reports(report)
    paths = {
        "before":          output_dir / "audit.html",
        "recommendations": output_dir / "recommendations.html",
        "after":           output_dir / "after.html",
    }
    for key, path in paths.items():
        path.write_text(pages[key], encoding="utf-8")

    report_path = paths["before"]  # default page to open

    if not args.quiet:
        print("  Reports generated:")
        print(f"    1. Current State:    {paths['before']}")
        print(f"    2. Recommendations:  {paths['recommendations']}")
        print(f"    3. Projected After:  {paths['after']}")

    # JSON output
    if args.json:
        json_path = output_dir / "metrics.json"
        if isinstance(report, AppAuditReport):
            metrics: dict = {
                "mode": "app",
                "project_path": report.project_path,
                "language": report.language,
                "sdk_files": report.sdk_files,
                "score": report.score,
                "api_call_count": report.api_call_count,
                "tool_definition_count": report.tool_definition_count,
                "has_retry_logic": report.has_retry_logic,
                "has_streaming": report.has_streaming,
                "hardcoded_models": report.hardcoded_models,
                "findings": [
                    {
                        "severity": f.severity,
                        "category": f.category,
                        "title": f.title,
                        "message": f.message,
                        "file": f.file,
                        "line": f.line,
                    }
                    for f in report.findings
                ],
                "recommendations": report.recommendations,
            }
        else:
            metrics = {
                "mode": "workspace",
                "workspace_path": report.workspace_path,
                "claude_dir_path": report.claude_dir_path,
                "used_fallback": report.used_fallback,
                "architecture_score": report.architecture_score,
                "autonomy": {
                    "risk_level": report.autonomy.risk_level,
                    "default_mode": report.autonomy.default_mode,
                    "allow_count": report.autonomy.allow_count,
                    "deny_count": report.autonomy.deny_count,
                    "ask_count": report.autonomy.ask_count,
                    "has_bypass": report.autonomy.has_bypass,
                    "broad_allow_patterns": report.autonomy.broad_allow_patterns,
                },
                "observability": {
                    "coverage_pct": report.observability.coverage_pct,
                    "total_hooks_configured": report.observability.total_hooks_configured,
                    "critical_present": report.observability.critical_present,
                    "critical_total": report.observability.critical_total,
                    "has_agent_tracing": report.observability.has_agent_tracing,
                    "has_session_logging": report.observability.has_session_logging,
                    "has_memory_preservation": report.observability.has_memory_preservation,
                },
                "rule_arch": {
                    "total_rules": report.rule_arch.total_rules if report.rule_arch else 0,
                    "covered_count": report.rule_arch.covered_count if report.rule_arch else 0,
                    "problem_coverage": [
                        {"label": c.label, "covered": c.covered, "description": c.description}
                        for c in (report.rule_arch.problem_coverage if report.rule_arch else [])
                    ],
                    "overlapping_pairs": [
                        {"rule_a": p.rule_a, "rule_b": p.rule_b, "overlap_pct": p.overlap_pct}
                        for p in (report.rule_arch.overlapping_pairs if report.rule_arch else [])
                    ],
                },
                "agent_setup": {
                    "has_memory_system": report.agent_setup.has_memory_system if report.agent_setup else False,
                    "has_recall_script": report.agent_setup.has_recall_script if report.agent_setup else False,
                    "has_spawner_skills": report.agent_setup.has_spawner_skills if report.agent_setup else False,
                    "agent_types_found": report.agent_setup.agent_types_found if report.agent_setup else [],
                    "has_specialized_agents": report.agent_setup.has_specialized_agents if report.agent_setup else False,
                    "has_orchestrator_pattern": report.agent_setup.has_orchestrator_pattern if report.agent_setup else False,
                },
                "issues": report.issues,
                "recommendations": report.recommendations,
            }
        json_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"    Metrics JSON: {json_path}")

    if not args.quiet:
        print(f"\n  Open {report_path} in your browser to view the full report.")
        print("\n  Need help optimizing? Visit https://oakenai.tech/intro-call")

    # Auto-open
    if args.open:
        webbrowser.open(f"file:///{report_path.resolve()}")


if __name__ == "__main__":
    main()
