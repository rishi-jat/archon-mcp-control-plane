"""archon-repo-intel — Repository Intelligence MCP Server.

Provides tools that fetch and analyze GitHub repository signals:
  • Recent commit risk analysis
  • Open pull-request risk analysis
  • Composite repository health scoring

Designed to run inside Archestra as a local (stdio) MCP server.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from commit_analyzer import CommitAnalyzer
from github_client import GitHubClient, GitHubClientError
from health_analyzer import HealthAnalyzer
from pr_analyzer import PRAnalyzer

# ---------------------------------------------------------------------------
# Logging – send everything to stderr so stdout stays clean for MCP protocol
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("archon-repo-intel")

# ---------------------------------------------------------------------------
# Shared clients / analyzers
# ---------------------------------------------------------------------------

_gh = GitHubClient()  # reads GITHUB_TOKEN from env
_commits = CommitAnalyzer(_gh)
_prs = PRAnalyzer(_gh)
_health = HealthAnalyzer(_gh)

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "archon-repo-intel",
    instructions=(
        "Repository intelligence signal server.  Use these tools to gather "
        "structured risk signals from GitHub repositories.  Each tool returns "
        "JSON with a top-level 'signal_type' field and an 'aggregate_risk_level' "
        "or 'health_score' that downstream agents can use for correlation."
    ),
)


def _serialize(obj: Any) -> str:
    """Pretty-print a dict/list as JSON for the LLM to consume."""
    return json.dumps(obj, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def analyze_recent_commits(
    owner: str,
    repo: str,
    count: int = 30,
) -> str:
    """Analyze recent commits for risk signals.

    Scores each commit on message quality, change size, sensitive-file
    modifications, and off-hours activity.  Returns per-commit assessments
    and an aggregate risk level.

    Args:
        owner: GitHub repository owner (org or user).
        repo: Repository name.
        count: Number of recent commits to analyze (1–100, default 30).
    """
    try:
        result = await _commits.analyze(owner, repo, count)
        return _serialize(result)
    except GitHubClientError as exc:
        return _serialize({"error": str(exc), "signal_type": "commit_analysis"})
    except Exception as exc:
        logger.exception("Unexpected error in analyze_recent_commits")
        return _serialize({"error": f"Internal error: {exc}", "signal_type": "commit_analysis"})


@mcp.tool()
async def analyze_pull_requests(
    owner: str,
    repo: str,
    count: int = 20,
) -> str:
    """Analyze open pull requests for risk signals.

    Checks staleness, diff size, sensitive-file changes, and review
    status.  Returns per-PR assessments and an aggregate risk level.

    Args:
        owner: GitHub repository owner.
        repo: Repository name.
        count: Maximum open PRs to examine (1–50, default 20).
    """
    try:
        result = await _prs.analyze(owner, repo, count)
        return _serialize(result)
    except GitHubClientError as exc:
        return _serialize({"error": str(exc), "signal_type": "pull_request_analysis"})
    except Exception as exc:
        logger.exception("Unexpected error in analyze_pull_requests")
        return _serialize({"error": f"Internal error: {exc}", "signal_type": "pull_request_analysis"})


@mcp.tool()
async def get_repository_health(
    owner: str,
    repo: str,
) -> str:
    """Compute a composite health score (0–100) for a repository.

    Evaluates community profile, commit cadence, issue hygiene,
    CI/CD presence, security policy, and contributor diversity.
    Returns a letter grade (A–F), dimension breakdown, and
    actionable recommendations.

    Args:
        owner: GitHub repository owner.
        repo: Repository name.
    """
    try:
        result = await _health.analyze(owner, repo)
        return _serialize(result)
    except GitHubClientError as exc:
        return _serialize({"error": str(exc), "signal_type": "repository_health"})
    except Exception as exc:
        logger.exception("Unexpected error in get_repository_health")
        return _serialize({"error": f"Internal error: {exc}", "signal_type": "repository_health"})


@mcp.tool()
async def get_repository_overview(
    owner: str,
    repo: str,
) -> str:
    """Fetch a quick overview of a repository's metadata.

    Returns key stats (stars, forks, language, size, last push)
    without deep analysis.  Useful for initial recon before running
    full analysis tools.

    Args:
        owner: GitHub repository owner.
        repo: Repository name.
    """
    try:
        repo_data = await _gh.get_repo(owner, repo)
        languages = await _gh.get_languages(owner, repo)

        overview = {
            "signal_type": "repository_overview",
            "repository": f"{owner}/{repo}",
            "description": repo_data.get("description"),
            "default_branch": repo_data.get("default_branch"),
            "stars": repo_data.get("stargazers_count", 0),
            "forks": repo_data.get("forks_count", 0),
            "open_issues": repo_data.get("open_issues_count", 0),
            "size_kb": repo_data.get("size", 0),
            "language": repo_data.get("language"),
            "languages": languages,
            "created_at": repo_data.get("created_at"),
            "pushed_at": repo_data.get("pushed_at"),
            "archived": repo_data.get("archived", False),
            "visibility": repo_data.get("visibility", "public"),
            "license": (repo_data.get("license") or {}).get("spdx_id"),
            "topics": repo_data.get("topics", []),
        }
        return _serialize(overview)
    except GitHubClientError as exc:
        return _serialize({"error": str(exc), "signal_type": "repository_overview"})
    except Exception as exc:
        logger.exception("Unexpected error in get_repository_overview")
        return _serialize({"error": f"Internal error: {exc}", "signal_type": "repository_overview"})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
