"""GitHub issue creation for the actions MCP server.

Wraps the GitHub REST API to create well-structured issues with
consistent labeling, formatted bodies, and proper error handling.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_API_BASE = "https://api.github.com"
_TIMEOUT = 20.0

# ---------------------------------------------------------------------------
# Severity → label mapping
# ---------------------------------------------------------------------------

_SEVERITY_LABELS: dict[str, list[str]] = {
    "critical": ["priority: critical", "security", "bug"],
    "high": ["priority: high", "security"],
    "medium": ["priority: medium"],
    "low": ["priority: low"],
}


class GitHubActionsError(Exception):
    """Raised when a GitHub write operation fails."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        super().__init__(f"GitHub API {status_code}: {detail}")


class GitHubActions:
    """Async client for GitHub write operations (issue creation)."""

    def __init__(self, token: str | None = None) -> None:
        self._token = token or os.environ.get("GITHUB_TOKEN")
        if not self._token:
            logger.warning(
                "GITHUB_TOKEN not set — issue creation will fail for "
                "private repos and may hit rate limits on public repos."
            )

    @property
    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "archon-actions/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    async def create_issue(
        self,
        owner: str,
        repo: str,
        *,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a GitHub issue and return the API response."""
        payload: dict[str, Any] = {"title": title, "body": body}
        if labels:
            payload["labels"] = labels

        url = f"{_API_BASE}/repos/{owner}/{repo}/issues"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(url, headers=self._headers, json=payload)
            if resp.status_code >= 400:
                raise GitHubActionsError(resp.status_code, resp.text[:500])
            return resp.json()

    # -- convenience builders ------------------------------------------------

    async def create_security_issue(
        self,
        owner: str,
        repo: str,
        *,
        title: str,
        severity: str,
        summary: str,
        findings: list[dict[str, Any]],
        recommendations: list[str],
    ) -> dict[str, Any]:
        """Create a structured security issue with formatted body.

        Parameters
        ----------
        owner / repo:
            Target repository.
        title:
            Issue title.
        severity:
            Risk level (critical/high/medium/low).
        summary:
            One-paragraph executive summary.
        findings:
            List of finding dicts (each should have fields like
            ``cve_id``, ``severity``, ``description``, etc.).
        recommendations:
            Ordered remediation steps.
        """
        body = self._format_security_body(
            severity=severity,
            summary=summary,
            findings=findings,
            recommendations=recommendations,
        )
        labels = _SEVERITY_LABELS.get(severity.lower(), []) + ["archon-automated"]

        return await self.create_issue(
            owner, repo, title=title, body=body, labels=labels,
        )

    async def create_incident_issue(
        self,
        owner: str,
        repo: str,
        *,
        title: str,
        severity: str,
        description: str,
        affected_components: list[str],
        timeline: list[str],
        action_items: list[str],
    ) -> dict[str, Any]:
        """Create a structured incident issue."""
        body = self._format_incident_body(
            severity=severity,
            description=description,
            affected_components=affected_components,
            timeline=timeline,
            action_items=action_items,
        )
        labels = _SEVERITY_LABELS.get(severity.lower(), []) + [
            "incident", "archon-automated",
        ]
        return await self.create_issue(
            owner, repo, title=title, body=body, labels=labels,
        )

    # -- formatters ----------------------------------------------------------

    @staticmethod
    def _format_security_body(
        *,
        severity: str,
        summary: str,
        findings: list[dict[str, Any]],
        recommendations: list[str],
    ) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        severity_emoji = {
            "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢",
        }
        emoji = severity_emoji.get(severity.lower(), "⚪")

        lines = [
            f"## {emoji} Security Alert — {severity.upper()}",
            "",
            f"**Generated by ARCHON** on {now}",
            "",
            "### Summary",
            "",
            summary,
            "",
        ]

        if findings:
            lines.append("### Findings")
            lines.append("")
            lines.append("| # | ID/Type | Severity | Description |")
            lines.append("|---|---------|----------|-------------|")
            for i, f in enumerate(findings[:20], 1):
                fid = f.get("cve_id") or f.get("secret_type") or "—"
                sev = f.get("severity", "unknown")
                desc = (f.get("description") or f.get("preview") or "—")[:80]
                lines.append(f"| {i} | `{fid}` | {sev} | {desc} |")
            lines.append("")

        if recommendations:
            lines.append("### Recommended Actions")
            lines.append("")
            for i, rec in enumerate(recommendations, 1):
                lines.append(f"{i}. {rec}")
            lines.append("")

        lines.append("---")
        lines.append("*This issue was created automatically by [ARCHON](https://github.com) — "
                      "an MCP-based operational control system running on Archestra.*")
        return "\n".join(lines)

    @staticmethod
    def _format_incident_body(
        *,
        severity: str,
        description: str,
        affected_components: list[str],
        timeline: list[str],
        action_items: list[str],
    ) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        severity_emoji = {
            "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢",
        }
        emoji = severity_emoji.get(severity.lower(), "⚪")

        lines = [
            f"## {emoji} Incident Report — {severity.upper()}",
            "",
            f"**Generated by ARCHON** on {now}",
            "",
            "### Description",
            "",
            description,
            "",
        ]

        if affected_components:
            lines.append("### Affected Components")
            lines.append("")
            for comp in affected_components:
                lines.append(f"- {comp}")
            lines.append("")

        if timeline:
            lines.append("### Timeline")
            lines.append("")
            for entry in timeline:
                lines.append(f"- {entry}")
            lines.append("")

        if action_items:
            lines.append("### Action Items")
            lines.append("")
            for i, item in enumerate(action_items, 1):
                lines.append(f"- [ ] {item}")
            lines.append("")

        lines.append("---")
        lines.append("*This incident was created automatically by [ARCHON](https://github.com) — "
                      "an MCP-based operational control system running on Archestra.*")
        return "\n".join(lines)
