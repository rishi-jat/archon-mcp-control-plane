"""archon-security — Security Signal MCP Server.

Provides tools that detect vulnerabilities and leaked credentials:
  • Dependency vulnerability scanning (via real NIST NVD API)
  • Individual CVE lookup
  • Source-code secret / credential detection
  • Aggregate security report generation

Designed to run inside Archestra as a local (stdio) MCP server.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

from dependency_scanner import DependencyScanner, detect_ecosystem
from nvd_client import NVDClient, NVDClientError, parse_cve_item
from secret_scanner import scan_content, scan_file_list

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("archon-security")

# ---------------------------------------------------------------------------
# Shared clients
# ---------------------------------------------------------------------------

_nvd = NVDClient()
_dep_scanner = DependencyScanner(_nvd)
_github_token = os.environ.get("GITHUB_TOKEN")


def _gh_headers() -> dict[str, str]:
    h: dict[str, str] = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "archon-security/1.0",
    }
    if _github_token:
        h["Authorization"] = f"Bearer {_github_token}"
    return h


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "archon-security",
    instructions=(
        "Security signal server.  Use these tools to detect vulnerabilities "
        "in dependencies and leaked secrets in source code.  Each tool returns "
        "JSON with a 'signal_type' and 'risk_level' that downstream agents "
        "can use for correlation and decision-making."
    ),
)


def _serialize(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def scan_dependencies(
    owner: str,
    repo: str,
    manifest_path: str = "",
) -> str:
    """Scan a repository's dependencies for known CVE vulnerabilities.

    Fetches a dependency manifest (package.json, requirements.txt, etc.)
    from GitHub, parses it, and checks each package against the NIST
    National Vulnerability Database.

    If manifest_path is empty, the tool auto-detects common manifest
    files at the repository root.

    Args:
        owner: GitHub repository owner.
        repo: Repository name.
        manifest_path: Path to the manifest file inside the repo (optional).
    """
    try:
        # -- auto-detect manifest if not specified ---------------------------
        if not manifest_path:
            candidates = [
                "package.json",
                "requirements.txt",
                "go.mod",
                "Cargo.toml",
            ]
            for candidate in candidates:
                try:
                    async with httpx.AsyncClient(timeout=15) as client:
                        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{candidate}"
                        resp = await client.get(url, headers=_gh_headers())
                        if resp.status_code == 200:
                            manifest_path = candidate
                            break
                except Exception:
                    continue

            if not manifest_path:
                return _serialize({
                    "signal_type": "dependency_scan",
                    "error": "No supported manifest file found at repository root.",
                    "hint": "Specify manifest_path explicitly.",
                })

        # -- fetch file content ----------------------------------------------
        async with httpx.AsyncClient(timeout=15) as client:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{manifest_path}"
            resp = await client.get(url, headers=_gh_headers())
            if resp.status_code != 200:
                return _serialize({
                    "signal_type": "dependency_scan",
                    "error": f"Could not fetch {manifest_path}: HTTP {resp.status_code}",
                })
            data = resp.json()
            content_b64 = data.get("content", "")
            content = base64.b64decode(content_b64).decode("utf-8", errors="replace")

        # -- scan ------------------------------------------------------------
        result = await _dep_scanner.scan(manifest_path, content)
        result["repository"] = f"{owner}/{repo}"
        return _serialize(result)

    except Exception as exc:
        logger.exception("Error in scan_dependencies")
        return _serialize({
            "signal_type": "dependency_scan",
            "error": f"Internal error: {exc}",
        })


@mcp.tool()
async def lookup_cve(cve_id: str) -> str:
    """Look up detailed information for a specific CVE.

    Queries the NIST NVD API for full CVE details including severity,
    CVSS score, description, references, and affected configurations.

    Args:
        cve_id: The CVE identifier, e.g. 'CVE-2024-3094'.
    """
    try:
        raw = await _nvd.get_cve(cve_id)
        vulns = raw.get("vulnerabilities", [])
        if not vulns:
            return _serialize({
                "signal_type": "cve_lookup",
                "cve_id": cve_id,
                "error": "CVE not found in NVD.",
            })
        parsed = parse_cve_item(vulns[0])
        parsed["signal_type"] = "cve_lookup"
        return _serialize(parsed)

    except NVDClientError as exc:
        return _serialize({
            "signal_type": "cve_lookup",
            "cve_id": cve_id,
            "error": str(exc),
        })
    except Exception as exc:
        logger.exception("Error in lookup_cve")
        return _serialize({
            "signal_type": "cve_lookup",
            "cve_id": cve_id,
            "error": f"Internal error: {exc}",
        })


@mcp.tool()
async def scan_for_secrets(
    owner: str,
    repo: str,
    path: str = "",
    max_files: int = 50,
) -> str:
    """Scan repository source code for leaked secrets and credentials.

    Uses pattern matching (regex for AWS keys, GitHub tokens, private
    keys, database URLs, etc.) and Shannon entropy analysis to detect
    high-entropy strings that may be secrets.

    Args:
        owner: GitHub repository owner.
        repo: Repository name.
        path: Subdirectory to scan (empty = repo root, scans top-level files).
        max_files: Maximum number of files to scan (default 50).
    """
    try:
        # Fetch the file tree
        async with httpx.AsyncClient(timeout=20) as client:
            tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD"
            resp = await client.get(
                tree_url, headers=_gh_headers(), params={"recursive": "1"},
            )
            if resp.status_code != 200:
                return _serialize({
                    "signal_type": "secret_scan",
                    "error": f"Could not fetch repo tree: HTTP {resp.status_code}",
                })
            tree = resp.json().get("tree", [])

        # Filter to text-like files (blobs) of reasonable size
        scannable_extensions = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java",
            ".rb", ".php", ".sh", ".bash", ".zsh", ".yml", ".yaml",
            ".json", ".toml", ".ini", ".cfg", ".conf", ".env",
            ".properties", ".xml", ".tf", ".hcl", ".md", ".txt",
        }
        candidates = []
        for item in tree:
            if item.get("type") != "blob":
                continue
            item_path = item.get("path", "")
            if path and not item_path.startswith(path):
                continue
            ext = ""
            dot_idx = item_path.rfind(".")
            if dot_idx != -1:
                ext = item_path[dot_idx:].lower()
            size = item.get("size", 0)
            if ext in scannable_extensions and size < 500_000:
                candidates.append(item_path)

        candidates = candidates[:max_files]

        # Fetch file contents
        files_to_scan: list[tuple[str, str]] = []
        async with httpx.AsyncClient(timeout=15) as client:
            for fpath in candidates:
                try:
                    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{fpath}"
                    resp = await client.get(url, headers=_gh_headers())
                    if resp.status_code == 200:
                        data = resp.json()
                        content_b64 = data.get("content", "")
                        if content_b64:
                            content = base64.b64decode(content_b64).decode(
                                "utf-8", errors="replace",
                            )
                            files_to_scan.append((fpath, content))
                except Exception:
                    logger.warning("Failed to fetch %s", fpath, exc_info=True)

        result = scan_file_list(files_to_scan)
        result["repository"] = f"{owner}/{repo}"
        return _serialize(result)

    except Exception as exc:
        logger.exception("Error in scan_for_secrets")
        return _serialize({
            "signal_type": "secret_scan",
            "error": f"Internal error: {exc}",
        })


@mcp.tool()
async def generate_security_report(
    owner: str,
    repo: str,
) -> str:
    """Generate a comprehensive security report for a repository.

    Runs both dependency scanning and secret detection, then produces
    an aggregate risk assessment with prioritized findings and
    remediation recommendations.

    This is a higher-level tool that orchestrates the individual
    scanners. Use it when you want a single consolidated view.

    Args:
        owner: GitHub repository owner.
        repo: Repository name.
    """
    try:
        # Run dependency scan
        dep_result_raw = await scan_dependencies(owner, repo)
        dep_result = json.loads(dep_result_raw)

        # Run secret scan (limited scope for speed)
        secret_result_raw = await scan_for_secrets(owner, repo, max_files=30)
        secret_result = json.loads(secret_result_raw)

        # -- aggregate risk --------------------------------------------------
        dep_risk = dep_result.get("risk_level", "none")
        secret_risk = secret_result.get("risk_level", "none")

        risk_order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        overall_risk = max(dep_risk, secret_risk, key=lambda r: risk_order.get(r, 0))

        # -- recommendations -------------------------------------------------
        recommendations: list[str] = []

        dep_vulns = dep_result.get("vulnerabilities", [])
        critical_vulns = [v for v in dep_vulns if v.get("severity") == "CRITICAL"]
        high_vulns = [v for v in dep_vulns if v.get("severity") == "HIGH"]

        if critical_vulns:
            recommendations.append(
                f"URGENT: {len(critical_vulns)} critical vulnerability(ies) found in dependencies. "
                "Update affected packages immediately."
            )
        if high_vulns:
            recommendations.append(
                f"{len(high_vulns)} high-severity vulnerability(ies) in dependencies. "
                "Schedule updates within the next sprint."
            )

        secret_findings = secret_result.get("findings", [])
        critical_secrets = [f for f in secret_findings if f.get("severity") == "critical"]
        if critical_secrets:
            recommendations.append(
                f"URGENT: {len(critical_secrets)} potential credential leak(s) detected. "
                "Rotate affected secrets and remove from source code."
            )

        if not recommendations:
            recommendations.append("No critical issues found. Continue monitoring.")

        report = {
            "signal_type": "security_report",
            "repository": f"{owner}/{repo}",
            "overall_risk_level": overall_risk,
            "dependency_scan": {
                "risk_level": dep_risk,
                "vulnerability_count": dep_result.get("vulnerability_count", 0),
                "severity_distribution": dep_result.get("severity_distribution", {}),
            },
            "secret_scan": {
                "risk_level": secret_risk,
                "finding_count": secret_result.get("total_findings", 0),
                "severity_distribution": secret_result.get("severity_distribution", {}),
            },
            "critical_findings": critical_vulns[:5] + critical_secrets[:5],
            "recommendations": recommendations,
        }
        return _serialize(report)

    except Exception as exc:
        logger.exception("Error in generate_security_report")
        return _serialize({
            "signal_type": "security_report",
            "error": f"Internal error: {exc}",
        })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
