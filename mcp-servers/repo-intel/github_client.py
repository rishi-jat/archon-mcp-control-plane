"""GitHub REST API v3 async client.

Provides a thin, typed wrapper around the GitHub API endpoints used by
the repo-intel MCP server.  Works with or without a personal access token
(unauthenticated requests are limited to 60 req/hour).
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_API_BASE = "https://api.github.com"
_TIMEOUT = 30.0


class GitHubClientError(Exception):
    """Raised when a GitHub API request returns a non-2xx status."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        super().__init__(f"GitHub API {status_code}: {detail}")


class GitHubClient:
    """Async client for the GitHub REST API v3.

    Parameters
    ----------
    token:
        Personal access token.  Falls back to the ``GITHUB_TOKEN``
        environment variable when *None*.
    """

    def __init__(self, token: str | None = None) -> None:
        self._token = token or os.environ.get("GITHUB_TOKEN")

    # -- internal helpers ----------------------------------------------------

    @property
    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "archon-repo-intel/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    async def _get(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> Any:
        """Execute a GET request and return parsed JSON."""
        url = f"{_API_BASE}{path}"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(url, headers=self._headers, params=params)
            if resp.status_code >= 400:
                raise GitHubClientError(resp.status_code, resp.text[:500])
            return resp.json()

    async def _post(
        self,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        """Execute a POST request and return parsed JSON."""
        url = f"{_API_BASE}{path}"
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                url, headers=self._headers, json=json_body,
            )
            if resp.status_code >= 400:
                raise GitHubClientError(resp.status_code, resp.text[:500])
            return resp.json()

    # -- repository ----------------------------------------------------------

    async def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        """Fetch top-level repository metadata."""
        return await self._get(f"/repos/{owner}/{repo}")

    async def get_languages(self, owner: str, repo: str) -> dict[str, int]:
        """Fetch language breakdown (language name → bytes)."""
        return await self._get(f"/repos/{owner}/{repo}/languages")

    async def get_contributors(
        self, owner: str, repo: str, *, per_page: int = 30,
    ) -> list[dict[str, Any]]:
        """Fetch repository contributors."""
        return await self._get(
            f"/repos/{owner}/{repo}/contributors",
            params={"per_page": per_page},
        )

    async def get_community_profile(
        self, owner: str, repo: str,
    ) -> dict[str, Any]:
        """Fetch community health percentage and file presence."""
        return await self._get(f"/repos/{owner}/{repo}/community/profile")

    # -- commits -------------------------------------------------------------

    async def get_commits(
        self, owner: str, repo: str, *, per_page: int = 30,
    ) -> list[dict[str, Any]]:
        """Fetch the most recent commits (newest first)."""
        return await self._get(
            f"/repos/{owner}/{repo}/commits",
            params={"per_page": per_page},
        )

    async def get_commit_detail(
        self, owner: str, repo: str, sha: str,
    ) -> dict[str, Any]:
        """Fetch full detail (stats, files) for a single commit."""
        return await self._get(f"/repos/{owner}/{repo}/commits/{sha}")

    # -- pull requests -------------------------------------------------------

    async def get_pulls(
        self,
        owner: str,
        repo: str,
        *,
        state: str = "open",
        per_page: int = 30,
    ) -> list[dict[str, Any]]:
        """Fetch pull requests."""
        return await self._get(
            f"/repos/{owner}/{repo}/pulls",
            params={"state": state, "per_page": per_page},
        )

    async def get_pull_files(
        self, owner: str, repo: str, pr_number: int,
    ) -> list[dict[str, Any]]:
        """Fetch the list of files changed in a pull request."""
        return await self._get(
            f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
        )

    async def get_pull_reviews(
        self, owner: str, repo: str, pr_number: int,
    ) -> list[dict[str, Any]]:
        """Fetch reviews for a pull request."""
        return await self._get(
            f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews",
        )

    # -- issues (read) -------------------------------------------------------

    async def get_issues(
        self,
        owner: str,
        repo: str,
        *,
        state: str = "open",
        per_page: int = 30,
    ) -> list[dict[str, Any]]:
        """Fetch issues (includes PRs on GitHub's side)."""
        return await self._get(
            f"/repos/{owner}/{repo}/issues",
            params={"state": state, "per_page": per_page},
        )

    # -- issues (write) -------------------------------------------------------

    async def create_issue(
        self,
        owner: str,
        repo: str,
        *,
        title: str,
        body: str,
        labels: list[str] | None = None,
    ) -> dict[str, Any]:
        """Create a new issue on a repository."""
        payload: dict[str, Any] = {"title": title, "body": body}
        if labels:
            payload["labels"] = labels
        return await self._post(
            f"/repos/{owner}/{repo}/issues", json_body=payload,
        )

    # -- content (for secret scanning) ---------------------------------------

    async def get_directory_tree(
        self,
        owner: str,
        repo: str,
        *,
        sha: str = "HEAD",
        recursive: bool = True,
    ) -> list[dict[str, Any]]:
        """Fetch the Git tree (list of all files) for a ref."""
        data = await self._get(
            f"/repos/{owner}/{repo}/git/trees/{sha}",
            params={"recursive": "1"} if recursive else None,
        )
        return data.get("tree", [])

    async def get_file_content(
        self, owner: str, repo: str, path: str,
    ) -> dict[str, Any]:
        """Fetch a single file's metadata and content (base64)."""
        return await self._get(f"/repos/{owner}/{repo}/contents/{path}")
