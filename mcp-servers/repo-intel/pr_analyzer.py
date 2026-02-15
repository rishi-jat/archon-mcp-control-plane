"""Pull request risk analysis.

Examines open pull requests to identify review delays, oversized diffs,
sensitive file changes, and overall merge-readiness.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any

from github_client import GitHubClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SENSITIVE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\.env",
        r"Dockerfile",
        r"docker-compose",
        r"\.github/workflows/",
        r"terraform/",
        r"\.tf$",
        r"k8s/",
        r"secrets?[/.]",
        r"\.pem$",
        r"\.key$",
    ]
]

_STALE_DAYS = 7
_LARGE_PR_LINES = 500
_VERY_LARGE_PR_LINES = 1500
_LARGE_PR_FILES = 20


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _days_since(iso_ts: str) -> float:
    """Return fractional days between *iso_ts* and now (UTC)."""
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400
    except (ValueError, TypeError):
        return 0.0


def _review_summary(reviews: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarise review state from the list of review objects."""
    approved = 0
    changes_requested = 0
    commented = 0
    reviewers: set[str] = set()

    for r in reviews:
        state = r.get("state", "").upper()
        user = r.get("user", {}).get("login", "unknown")
        reviewers.add(user)
        if state == "APPROVED":
            approved += 1
        elif state == "CHANGES_REQUESTED":
            changes_requested += 1
        elif state == "COMMENTED":
            commented += 1

    return {
        "approved": approved,
        "changes_requested": changes_requested,
        "commented": commented,
        "unique_reviewers": len(reviewers),
    }


def _sensitive_files_in_pr(files: list[dict[str, Any]]) -> list[str]:
    hits: list[str] = []
    for f in files:
        name = f.get("filename", "")
        if any(p.search(name) for p in _SENSITIVE_PATTERNS):
            hits.append(name)
    return hits


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_risk(*levels: str) -> str:
    return max(levels, key=lambda l: _RISK_ORDER.get(l, -1))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class PRAnalyzer:
    """Fetches and scores open pull requests for risk signals."""

    def __init__(self, client: GitHubClient) -> None:
        self._client = client

    async def analyze(
        self, owner: str, repo: str, count: int = 20,
    ) -> dict[str, Any]:
        """Return a structured pull-request risk report.

        Parameters
        ----------
        owner:
            GitHub org or user.
        repo:
            Repository name.
        count:
            Maximum number of open PRs to examine.
        """
        count = min(count, 50)
        logger.info("Analyzing up to %d PRs for %s/%s", count, owner, repo)

        pulls = await self._client.get_pulls(
            owner, repo, state="open", per_page=count,
        )

        assessed: list[dict[str, Any]] = []
        detail_limit = min(len(pulls), 10)

        for idx, pr in enumerate(pulls):
            indicators: list[str] = []
            risk = "low"
            pr_number = pr["number"]

            # -- staleness ---------------------------------------------------
            created = pr.get("created_at", "")
            updated = pr.get("updated_at", "")
            age_days = _days_since(created)
            idle_days = _days_since(updated)

            if idle_days > _STALE_DAYS:
                indicators.append("stale_pr")
                risk = _max_risk(risk, "medium")

            # -- draft -------------------------------------------------------
            if pr.get("draft", False):
                indicators.append("draft_pr")

            # -- size & files (requires detail) ------------------------------
            review_info: dict[str, Any] = {}
            sensitive: list[str] = []
            additions = pr.get("additions", 0)
            deletions = pr.get("deletions", 0)
            changed_files = pr.get("changed_files", 0)

            if idx < detail_limit:
                try:
                    files = await self._client.get_pull_files(
                        owner, repo, pr_number,
                    )
                    changed_files = len(files)
                    additions = sum(f.get("additions", 0) for f in files)
                    deletions = sum(f.get("deletions", 0) for f in files)
                    sensitive = _sensitive_files_in_pr(files)
                except Exception:
                    logger.warning(
                        "Failed to fetch files for PR #%d", pr_number,
                        exc_info=True,
                    )

                try:
                    reviews = await self._client.get_pull_reviews(
                        owner, repo, pr_number,
                    )
                    review_info = _review_summary(reviews)
                except Exception:
                    logger.warning(
                        "Failed to fetch reviews for PR #%d", pr_number,
                        exc_info=True,
                    )

            total_changes = additions + deletions
            if total_changes > _VERY_LARGE_PR_LINES:
                indicators.append("very_large_pr")
                risk = _max_risk(risk, "high")
            elif total_changes > _LARGE_PR_LINES:
                indicators.append("large_pr")
                risk = _max_risk(risk, "medium")

            if changed_files > _LARGE_PR_FILES:
                indicators.append("many_files_changed")
                risk = _max_risk(risk, "medium")

            if sensitive:
                indicators.append("sensitive_files_in_pr")
                risk = _max_risk(risk, "medium")

            # -- review status -----------------------------------------------
            if review_info.get("changes_requested", 0) > 0:
                indicators.append("changes_requested")
                risk = _max_risk(risk, "medium")

            if (
                review_info.get("approved", 0) == 0
                and age_days > 3
                and not pr.get("draft", False)
            ):
                indicators.append("no_approvals")
                risk = _max_risk(risk, "medium")

            # -- compound risk -----------------------------------------------
            if len(indicators) >= 3:
                risk = _max_risk(risk, "high")

            assessed.append({
                "number": pr_number,
                "title": pr.get("title", "")[:200],
                "author": pr.get("user", {}).get("login", "unknown"),
                "state": "draft" if pr.get("draft") else "open",
                "created_at": created,
                "updated_at": updated,
                "age_days": round(age_days, 1),
                "idle_days": round(idle_days, 1),
                "additions": additions,
                "deletions": deletions,
                "total_changes": total_changes,
                "changed_files": changed_files,
                "sensitive_files": sensitive,
                "review": review_info,
                "risk_level": risk,
                "risk_indicators": indicators,
                "url": pr.get("html_url", ""),
            })

        # -- aggregate -------------------------------------------------------
        risk_dist: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
        for a in assessed:
            risk_dist[a["risk_level"]] = risk_dist.get(a["risk_level"], 0) + 1

        if risk_dist.get("high", 0) >= 2:
            agg_risk = "high"
        elif risk_dist.get("high", 0) >= 1 or risk_dist.get("medium", 0) >= 3:
            agg_risk = "medium"
        else:
            agg_risk = "low"

        return {
            "signal_type": "pull_request_analysis",
            "repository": f"{owner}/{repo}",
            "open_prs_analyzed": len(assessed),
            "aggregate_risk_level": agg_risk,
            "risk_distribution": risk_dist,
            "pull_requests": assessed,
        }
