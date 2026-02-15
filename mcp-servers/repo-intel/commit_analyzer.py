"""Commit-level risk analysis.

Examines recent commits in a repository and flags risk indicators such as
oversized diffs, sensitive file changes, vague messages, and off-hours
activity.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from github_client import GitHubClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensitive path patterns (case-insensitive)
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\.env",
        r"Dockerfile",
        r"docker-compose",
        r"\.github/workflows/",
        r"Jenkinsfile",
        r"\.gitlab-ci",
        r"terraform/",
        r"\.tf$",
        r"k8s/",
        r"kubernetes/",
        r"helm/",
        r"secrets?[/.]",
        r"credentials?[/.]",
        r"\.pem$",
        r"\.key$",
        r"\.cert$",
        r"config\.ya?ml$",
        r"package-lock\.json$",
        r"yarn\.lock$",
        r"requirements.*\.txt$",
        r"go\.sum$",
        r"Cargo\.lock$",
    ]
]

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

_LARGE_CHANGE_LINES = 500
_VERY_LARGE_CHANGE_LINES = 1000
_LARGE_FILE_COUNT = 20
_SHORT_MESSAGE_LEN = 10
_VAGUE_MESSAGES = frozenset(
    {"fix", "update", "wip", "temp", "test", "asdf", "stuff", "changes", "."}
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sensitive_files(files: list[dict[str, Any]]) -> list[str]:
    """Return filenames that match any sensitive pattern."""
    hits: list[str] = []
    for f in files:
        name = f.get("filename", "")
        if any(p.search(name) for p in _SENSITIVE_PATTERNS):
            hits.append(name)
    return hits


def _assess_one(
    commit: dict[str, Any],
    detail: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build the risk assessment dict for a single commit."""
    indicators: list[str] = []
    risk = "low"

    meta = commit.get("commit", {})
    author = meta.get("author", {})
    message = meta.get("message", "")
    first_line = message.split("\n", 1)[0].strip()

    # -- message quality -----------------------------------------------------
    if len(first_line) < _SHORT_MESSAGE_LEN:
        indicators.append("short_commit_message")
    if first_line.lower().strip(" .") in _VAGUE_MESSAGES:
        indicators.append("vague_commit_message")
    if first_line.lower().startswith("revert"):
        indicators.append("revert_commit")

    # -- timing --------------------------------------------------------------
    ts_str = author.get("date", "")
    if ts_str:
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts.hour < 6 or ts.hour >= 23:
                indicators.append("off_hours_commit")
        except (ValueError, TypeError):
            pass

    # -- change size ---------------------------------------------------------
    stats = detail.get("stats", {}) if detail else {}
    files = detail.get("files", []) if detail else []
    total_changes = stats.get("total", 0)
    files_changed = len(files)

    if total_changes > _VERY_LARGE_CHANGE_LINES:
        indicators.append("very_large_commit")
        risk = "high"
    elif total_changes > _LARGE_CHANGE_LINES:
        indicators.append("large_commit")
        risk = max(risk, "medium", key=_risk_ord)

    if files_changed > _LARGE_FILE_COUNT:
        indicators.append("many_files_changed")
        risk = max(risk, "medium", key=_risk_ord)

    # -- sensitive files -----------------------------------------------------
    sens = _sensitive_files(files)
    if sens:
        indicators.append("sensitive_files_modified")
        risk = max(risk, "medium", key=_risk_ord)

    # -- aggregated risk bump ------------------------------------------------
    if len(indicators) >= 3:
        risk = max(risk, "high", key=_risk_ord)
    elif len(indicators) >= 2:
        risk = max(risk, "medium", key=_risk_ord)

    return {
        "sha": commit.get("sha", "")[:12],
        "author": author.get("name", "unknown"),
        "email": author.get("email", ""),
        "message": first_line[:200],
        "timestamp": ts_str,
        "files_changed": files_changed,
        "additions": stats.get("additions", 0),
        "deletions": stats.get("deletions", 0),
        "total_changes": total_changes,
        "sensitive_files": sens,
        "risk_level": risk,
        "risk_indicators": indicators,
    }


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _risk_ord(level: str) -> int:
    return _RISK_ORDER.get(level, -1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class CommitAnalyzer:
    """Fetches and scores recent commits for operational risk signals."""

    def __init__(self, client: GitHubClient) -> None:
        self._client = client

    async def analyze(
        self, owner: str, repo: str, count: int = 30,
    ) -> dict[str, Any]:
        """Return a structured commit-risk report.

        Parameters
        ----------
        owner:
            GitHub org or user.
        repo:
            Repository name.
        count:
            Number of recent commits to examine (max 100).
        """
        count = min(count, 100)
        logger.info("Analyzing %d commits for %s/%s", count, owner, repo)

        commits = await self._client.get_commits(
            owner, repo, per_page=count,
        )

        # Fetch file-level detail for the first N commits (stay within rate
        # limits on unauthenticated requests).
        detail_limit = min(len(commits), 15)
        assessed: list[dict[str, Any]] = []

        for idx, c in enumerate(commits):
            detail: dict[str, Any] | None = None
            if idx < detail_limit:
                try:
                    detail = await self._client.get_commit_detail(
                        owner, repo, c["sha"],
                    )
                except Exception:
                    logger.warning(
                        "Failed to fetch detail for %s", c["sha"][:12],
                        exc_info=True,
                    )
            assessed.append(_assess_one(c, detail))

        # -- aggregate -------------------------------------------------------
        risk_dist: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        indicator_counts: dict[str, int] = {}
        total_add = total_del = 0

        for a in assessed:
            risk_dist[a["risk_level"]] = risk_dist.get(a["risk_level"], 0) + 1
            total_add += a["additions"]
            total_del += a["deletions"]
            for ind in a["risk_indicators"]:
                indicator_counts[ind] = indicator_counts.get(ind, 0) + 1

        if risk_dist.get("high", 0) >= 3:
            agg_risk = "high"
        elif risk_dist.get("high", 0) >= 1 or risk_dist.get("medium", 0) >= 5:
            agg_risk = "medium"
        else:
            agg_risk = "low"

        top_indicators = dict(
            sorted(indicator_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
        )

        return {
            "signal_type": "commit_analysis",
            "repository": f"{owner}/{repo}",
            "commits_analyzed": len(assessed),
            "aggregate_risk_level": agg_risk,
            "risk_distribution": risk_dist,
            "top_risk_indicators": top_indicators,
            "total_additions": total_add,
            "total_deletions": total_del,
            "commits": assessed,
        }
