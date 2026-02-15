"""Repository health scoring.

Produces a composite health score (0–100) from multiple dimensions:
community profile, activity cadence, issue hygiene, and CI/CD presence.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from github_client import GitHubClient, GitHubClientError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weights (total = 100)
# ---------------------------------------------------------------------------

_W_COMMUNITY = 25      # README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT
_W_ACTIVITY = 25       # recent commit cadence
_W_ISSUES = 15         # open-issue count relative to repo size
_W_CI = 15             # presence of CI/CD configuration
_W_SECURITY = 10       # SECURITY.md / security policy
_W_CONTRIBUTORS = 10   # bus-factor / contributor diversity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bool_score(condition: bool, weight: int) -> int:
    return weight if condition else 0


def _clamp(value: float, lo: float = 0, hi: float = 100) -> float:
    return max(lo, min(hi, value))


def _days_since(iso_ts: str | None) -> float:
    if not iso_ts:
        return 999
    try:
        dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).total_seconds() / 86400
    except (ValueError, TypeError):
        return 999


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class HealthAnalyzer:
    """Computes a composite health score for a GitHub repository."""

    def __init__(self, client: GitHubClient) -> None:
        self._client = client

    async def analyze(self, owner: str, repo: str) -> dict[str, Any]:
        """Return a structured health-score report."""
        logger.info("Computing health score for %s/%s", owner, repo)

        # -- fetch data concurrently-ish (sequential to respect rate limits) -
        repo_data = await self._client.get_repo(owner, repo)

        community: dict[str, Any] = {}
        try:
            community = await self._client.get_community_profile(owner, repo)
        except GitHubClientError as exc:
            logger.warning("Community profile unavailable: %s", exc)

        contributors: list[dict[str, Any]] = []
        try:
            contributors = await self._client.get_contributors(
                owner, repo, per_page=100,
            )
        except GitHubClientError:
            pass

        recent_commits: list[dict[str, Any]] = []
        try:
            recent_commits = await self._client.get_commits(
                owner, repo, per_page=30,
            )
        except GitHubClientError:
            pass

        languages: dict[str, int] = {}
        try:
            languages = await self._client.get_languages(owner, repo)
        except GitHubClientError:
            pass

        # -- dimension: community (25 pts) -----------------------------------
        files = community.get("files", {})
        has_readme = files.get("readme") is not None
        has_license = repo_data.get("license") is not None
        has_contributing = files.get("contributing") is not None
        has_coc = files.get("code_of_conduct") is not None
        has_description = bool(repo_data.get("description"))

        community_score = 0
        # 5 boolean checks → 5 pts each (total 25)
        community_score += _bool_score(has_readme, 7)
        community_score += _bool_score(has_license, 6)
        community_score += _bool_score(has_contributing, 5)
        community_score += _bool_score(has_coc, 4)
        community_score += _bool_score(has_description, 3)

        # -- dimension: activity (25 pts) ------------------------------------
        last_push = repo_data.get("pushed_at")
        days_idle = _days_since(last_push)

        if days_idle < 7:
            activity_score = _W_ACTIVITY
            commit_frequency = "high"
        elif days_idle < 30:
            activity_score = int(_W_ACTIVITY * 0.7)
            commit_frequency = "medium"
        elif days_idle < 90:
            activity_score = int(_W_ACTIVITY * 0.4)
            commit_frequency = "low"
        else:
            activity_score = int(_W_ACTIVITY * 0.1)
            commit_frequency = "stale"

        # -- dimension: issue hygiene (15 pts) -------------------------------
        open_issues = repo_data.get("open_issues_count", 0)
        size_kb = repo_data.get("size", 1)

        # heuristic: fewer open issues per KB of code → healthier
        issue_ratio = open_issues / max(size_kb / 1000, 1)
        if issue_ratio < 0.5:
            issue_score = _W_ISSUES
        elif issue_ratio < 2:
            issue_score = int(_W_ISSUES * 0.7)
        elif issue_ratio < 5:
            issue_score = int(_W_ISSUES * 0.4)
        else:
            issue_score = int(_W_ISSUES * 0.1)

        # -- dimension: CI/CD (15 pts) --------------------------------------
        # Check for .github/workflows by looking at the tree
        has_ci = False
        try:
            tree = await self._client.get_directory_tree(
                owner, repo, sha="HEAD", recursive=True,
            )
            ci_paths = [
                ".github/workflows/",
                "Jenkinsfile",
                ".gitlab-ci.yml",
                ".circleci/",
                ".travis.yml",
            ]
            for item in tree:
                path = item.get("path", "")
                if any(path.startswith(cp) or path == cp.rstrip("/") for cp in ci_paths):
                    has_ci = True
                    break
        except GitHubClientError:
            pass

        ci_score = _bool_score(has_ci, _W_CI)

        # -- dimension: security (10 pts) -----------------------------------
        has_security_policy = files.get("security") is not None
        security_score = _bool_score(has_security_policy, _W_SECURITY)

        # -- dimension: contributors (10 pts) --------------------------------
        contributor_count = len(contributors)
        if contributor_count >= 10:
            contrib_score = _W_CONTRIBUTORS
        elif contributor_count >= 5:
            contrib_score = int(_W_CONTRIBUTORS * 0.7)
        elif contributor_count >= 2:
            contrib_score = int(_W_CONTRIBUTORS * 0.4)
        else:
            contrib_score = int(_W_CONTRIBUTORS * 0.1)  # bus-factor risk

        # -- composite -------------------------------------------------------
        total = (
            community_score
            + activity_score
            + issue_score
            + ci_score
            + security_score
            + contrib_score
        )
        total = int(_clamp(total, 0, 100))

        if total >= 80:
            grade = "A"
        elif total >= 60:
            grade = "B"
        elif total >= 40:
            grade = "C"
        elif total >= 20:
            grade = "D"
        else:
            grade = "F"

        # -- recommendations -------------------------------------------------
        recommendations: list[str] = []
        if not has_readme:
            recommendations.append("Add a README.md to explain the project")
        if not has_license:
            recommendations.append("Add a LICENSE file")
        if not has_contributing:
            recommendations.append("Add a CONTRIBUTING.md guide")
        if not has_security_policy:
            recommendations.append("Add a SECURITY.md with vulnerability reporting instructions")
        if not has_ci:
            recommendations.append("Set up CI/CD (e.g. GitHub Actions) for automated testing")
        if contributor_count <= 1:
            recommendations.append("Bus-factor risk: encourage additional contributors")
        if commit_frequency in ("low", "stale"):
            recommendations.append("Repository activity is declining; consider prioritizing maintenance")
        if open_issues > 50:
            recommendations.append(f"High open-issue count ({open_issues}); triage and close stale issues")

        return {
            "signal_type": "repository_health",
            "repository": f"{owner}/{repo}",
            "health_score": total,
            "grade": grade,
            "dimensions": {
                "community": {"score": community_score, "max": _W_COMMUNITY},
                "activity": {"score": activity_score, "max": _W_ACTIVITY},
                "issues": {"score": issue_score, "max": _W_ISSUES},
                "ci_cd": {"score": ci_score, "max": _W_CI},
                "security": {"score": security_score, "max": _W_SECURITY},
                "contributors": {"score": contrib_score, "max": _W_CONTRIBUTORS},
            },
            "details": {
                "has_readme": has_readme,
                "has_license": has_license,
                "has_contributing": has_contributing,
                "has_code_of_conduct": has_coc,
                "has_security_policy": has_security_policy,
                "has_ci_cd": has_ci,
                "commit_frequency": commit_frequency,
                "days_since_last_push": round(days_idle, 1),
                "open_issues": open_issues,
                "contributor_count": contributor_count,
                "languages": languages,
                "stars": repo_data.get("stargazers_count", 0),
                "forks": repo_data.get("forks_count", 0),
            },
            "recommendations": recommendations,
        }
