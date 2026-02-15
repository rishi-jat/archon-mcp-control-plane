"""ARCHON Actions MCP Server — operational response execution.

Provides tools to create GitHub issues, generate structured reports,
and log actions as part of the ARCHON signal-to-action workflow.

Registered in Archestra as ``archon-actions``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from github_actions import GitHubActions, GitHubActionsError
from report_generator import build_security_report, build_operational_report

# ---------------------------------------------------------------------------
# Logging — stderr only (stdout is reserved for MCP protocol)
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("archon-actions")

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------
_github = GitHubActions(token=os.environ.get("GITHUB_TOKEN"))


def _serialize(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------
mcp = FastMCP("archon-actions")


@mcp.tool()
async def create_security_issue(
    owner: str,
    repo: str,
    title: str,
    severity: str,
    findings: str,
    recommendations: str,
) -> str:
    """Create a GitHub issue for a security finding discovered by ARCHON.

    Formats the findings into a structured Markdown body with severity
    labels, a findings summary, and recommended remediation steps.

    Args:
        owner: GitHub repository owner
        repo: Repository name
        title: Issue title (e.g. "Critical CVE found in lodash")
        severity: Finding severity — critical, high, medium, or low
        findings: JSON-encoded list of finding dicts (each with type, detail keys)
        recommendations: JSON-encoded list of recommendation strings
    """
    try:
        findings_list = json.loads(findings) if isinstance(findings, str) else findings
        recs_list = json.loads(recommendations) if isinstance(recommendations, str) else recommendations
    except json.JSONDecodeError:
        findings_list = [{"detail": findings}]
        recs_list = [recommendations]

    try:
        result = await _github.create_security_issue(
            owner=owner,
            repo=repo,
            title=title,
            severity=severity,
            findings=findings_list,
            recommendations=recs_list,
        )
        logger.info("Created security issue #%s on %s/%s", result["number"], owner, repo)
        return _serialize(result)
    except GitHubActionsError as exc:
        logger.error("Failed to create security issue: %s", exc)
        return _serialize({"error": str(exc)})


@mcp.tool()
async def create_incident_issue(
    owner: str,
    repo: str,
    title: str,
    severity: str,
    summary: str,
    affected_components: str,
    action_items: str,
) -> str:
    """Create a GitHub issue to track an operational incident.

    Generates a structured incident ticket with timeline, affected
    components, and required action items with checkboxes.

    Args:
        owner: GitHub repository owner
        repo: Repository name
        title: Incident title (e.g. "High-risk commit pattern detected")
        severity: Severity — critical, high, medium, or low
        summary: One paragraph describing the incident
        affected_components: JSON-encoded list of affected component strings
        action_items: JSON-encoded list of action item strings
    """
    try:
        components = json.loads(affected_components) if isinstance(affected_components, str) else affected_components
        items = json.loads(action_items) if isinstance(action_items, str) else action_items
    except json.JSONDecodeError:
        components = [affected_components]
        items = [action_items]

    try:
        result = await _github.create_incident_issue(
            owner=owner,
            repo=repo,
            title=title,
            severity=severity,
            summary=summary,
            affected_components=components,
            action_items=items,
        )
        logger.info("Created incident issue #%s on %s/%s", result["number"], owner, repo)
        return _serialize(result)
    except GitHubActionsError as exc:
        logger.error("Failed to create incident issue: %s", exc)
        return _serialize({"error": str(exc)})


@mcp.tool()
async def generate_security_report(
    repository: str,
    overall_risk: str,
    dependency_data: str,
    secret_data: str,
    critical_findings: str,
    recommendations: str,
) -> str:
    """Generate a comprehensive Markdown security audit report.

    Combines dependency scan results, secret scan results, and
    critical findings into a formatted, publishable report.

    Args:
        repository: Repository in "owner/repo" format
        overall_risk: Overall risk level (critical/high/medium/low)
        dependency_data: JSON-encoded dependency summary dict
        secret_data: JSON-encoded secret finding summary dict
        critical_findings: JSON-encoded list of critical finding dicts
        recommendations: JSON-encoded list of recommendation strings
    """
    try:
        dep_sum = json.loads(dependency_data) if isinstance(dependency_data, str) else dependency_data
        sec_sum = json.loads(secret_data) if isinstance(secret_data, str) else secret_data
        crit = json.loads(critical_findings) if isinstance(critical_findings, str) else critical_findings
        recs = json.loads(recommendations) if isinstance(recommendations, str) else recommendations
    except json.JSONDecodeError as exc:
        return _serialize({"error": f"Invalid JSON input: {exc}"})

    report = build_security_report(
        repository=repository,
        overall_risk=overall_risk,
        dependency_summary=dep_sum,
        secret_summary=sec_sum,
        critical_findings=crit,
        recommendations=recs,
    )
    logger.info("Generated security report %s for %s", report["report_id"], repository)
    return _serialize(report)


@mcp.tool()
async def generate_operational_report(
    repository: str,
    health_data: str,
    commit_data: str,
    pr_data: str,
    security_data: str,
    action_items: str,
) -> str:
    """Generate a full operational status report combining all ARCHON signals.

    This is the primary output of the orchestrator's correlation phase.
    It merges health, commit, PR, and security signals into a unified
    report with a prioritized action plan.

    Args:
        repository: Repository in "owner/repo" format
        health_data: JSON-encoded health analysis result
        commit_data: JSON-encoded commit analysis result
        pr_data: JSON-encoded PR analysis result
        security_data: JSON-encoded security scan result
        action_items: JSON-encoded list of prioritized action item strings
    """
    try:
        health = json.loads(health_data) if isinstance(health_data, str) else health_data
        commits = json.loads(commit_data) if isinstance(commit_data, str) else commit_data
        prs = json.loads(pr_data) if isinstance(pr_data, str) else pr_data
        security = json.loads(security_data) if isinstance(security_data, str) else security_data
        items = json.loads(action_items) if isinstance(action_items, str) else action_items
    except json.JSONDecodeError as exc:
        return _serialize({"error": f"Invalid JSON input: {exc}"})

    report = build_operational_report(
        repository=repository,
        health_score=health.get("health_score", 0),
        grade=health.get("grade", "?"),
        commit_risk=commits.get("aggregate_risk_level", "unknown"),
        pr_risk=prs.get("aggregate_risk_level", "unknown"),
        security_risk=security.get("overall_risk_level", "unknown"),
        health_details=health,
        commit_summary=commits,
        pr_summary=prs,
        security_summary=security,
        action_items=items,
    )
    logger.info("Generated operational report %s for %s", report["report_id"], repository)
    return _serialize(report)


@mcp.tool()
async def log_action(
    action_type: str,
    repository: str,
    detail: str,
    severity: str = "info",
) -> str:
    """Log an ARCHON action for audit and observability.

    Creates a structured log entry for every action taken by the system.
    These logs feed into Archestra's OTEL observability pipeline.

    Args:
        action_type: Type of action (issue_created, report_generated, alert_sent, etc.)
        repository: Repository in "owner/repo" format
        detail: Human-readable description of what was done
        severity: Log severity — info, warning, error
    """
    from datetime import datetime, timezone

    entry = {
        "action_type": action_type,
        "repository": repository,
        "detail": detail,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "archon-actions",
        "status": "logged",
    }
    logger.info("ACTION LOG | type=%s repo=%s severity=%s | %s",
                action_type, repository, severity, detail)
    return _serialize(entry)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("Starting archon-actions MCP server (stdio)")
    mcp.run(transport="stdio")
