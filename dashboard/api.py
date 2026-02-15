"""ARCHON Dashboard API — real-time streaming analysis backend.

Thin FastAPI layer that imports the MCP server modules directly,
runs the full Signal → Correlate → Decide → Act pipeline, and
streams every event to the frontend via Server-Sent Events.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Module path setup — import analyzers from the MCP server packages
# ---------------------------------------------------------------------------
_BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BASE / "mcp-servers" / "repo-intel"))
sys.path.insert(0, str(_BASE / "mcp-servers" / "security"))
sys.path.insert(0, str(_BASE / "mcp-servers" / "actions"))

from github_client import GitHubClient, GitHubClientError  # noqa: E402
from commit_analyzer import CommitAnalyzer                  # noqa: E402
from pr_analyzer import PRAnalyzer                          # noqa: E402
from health_analyzer import HealthAnalyzer                  # noqa: E402
from dependency_scanner import DependencyScanner            # noqa: E402
from nvd_client import NVDClient                            # noqa: E402
from secret_scanner import scan_content                     # noqa: E402
from report_generator import (                              # noqa: E402
    build_security_report,
    build_operational_report,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("archon-dashboard")

# ---------------------------------------------------------------------------
# FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(title="ARCHON Dashboard", version="1.0.0")

_STATIC = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_MANIFEST_NAMES = {
    "requirements.txt", "Pipfile", "setup.py", "setup.cfg", "pyproject.toml",
    "package.json", "go.mod", "Cargo.toml",
}

_SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".min.js", ".min.css", ".map",
    ".lock", ".sum",
}

_SKIP_DIRS = {
    "node_modules", "vendor", ".git", "__pycache__", "dist", "build",
    ".next", "venv", ".venv", ".tox", "eggs", ".eggs", "site-packages",
}


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------
def _sse(event: str, data: Any) -> str:
    """Format one Server-Sent Event frame."""
    payload = json.dumps(data, default=str)
    return f"event: {event}\ndata: {payload}\n\n"


def _risk_ord(level: str) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(level, 0)


# ---------------------------------------------------------------------------
# Correlation + Decision logic
# ---------------------------------------------------------------------------
def _correlate(
    health: dict,
    commits: dict,
    prs: dict,
    deps: dict,
    secrets: dict,
) -> dict:
    """Cross-reference all signals and compute overall risk."""
    commit_risk = commits.get("aggregate_risk_level", "low")
    pr_risk = prs.get("aggregate_risk_level", "low")
    dep_risk = deps.get("risk_level", "none")
    secret_risk = secrets.get("risk_level", "none")
    score = health.get("health_score", 100)

    # ---- Risk matrix -------------------------------------------------------
    if _risk_ord(dep_risk) >= 4 or _risk_ord(secret_risk) >= 4:
        overall = "critical"
    elif _risk_ord(dep_risk) >= 3 or _risk_ord(secret_risk) >= 3:
        overall = "high"
    elif _risk_ord(commit_risk) >= 3:
        overall = "high"
    elif _risk_ord(dep_risk) >= 2 and (_risk_ord(pr_risk) >= 2 or score < 50):
        overall = "medium"
    elif any(_risk_ord(r) >= 2 for r in [commit_risk, pr_risk]):
        overall = "medium"
    else:
        overall = "low"

    # ---- Correlation insights -----------------------------------------------
    correlations: list[str] = []
    if dep_risk in ("high", "critical") and commit_risk in ("medium", "high"):
        correlations.append(
            "Dependency vulnerabilities combined with risky commit patterns "
            "— possible supply-chain concern"
        )
    if secret_risk != "none" and pr_risk in ("medium", "high"):
        correlations.append(
            "Secret exposure amplified by under-reviewed pull requests"
        )
    if score < 50 and dep_risk in ("medium", "high", "critical"):
        correlations.append(
            "Low repository health combined with dependency vulnerabilities "
            "suggests a maintenance gap"
        )
    if not correlations:
        correlations.append("No compound risk patterns detected")

    return {
        "overall_risk": overall,
        "signal_risks": {
            "health": {"score": score, "grade": health.get("grade", "?")},
            "commits": commit_risk,
            "pull_requests": pr_risk,
            "dependencies": dep_risk,
            "secrets": secret_risk,
        },
        "correlations": correlations,
        "health_score": score,
    }


def _decide(correlation: dict) -> dict:
    """Determine actions and recommendations from correlated risk."""
    overall = correlation["overall_risk"]
    recs: list[str] = []

    if overall == "critical":
        actions = ["create_security_issue", "generate_security_report",
                    "generate_operational_report"]
        recs = [
            "Immediately address critical vulnerabilities before next deployment",
            "Rotate any exposed credentials and audit access logs",
            "Enable branch protection and require security reviews",
        ]
    elif overall == "high":
        actions = ["create_incident_issue", "generate_security_report"]
        recs = [
            "Schedule vulnerability remediation within 72 hours",
            "Review and merge or close stale pull requests",
            "Add automated dependency scanning to CI pipeline",
        ]
    elif overall == "medium":
        actions = ["generate_operational_report"]
        recs = [
            "Address medium-severity findings in next sprint",
            "Improve PR review coverage for sensitive files",
        ]
    else:
        actions = ["log_action"]
        recs = [
            "Continue regular monitoring",
            "Consider setting up automated security scanning",
        ]

    sr = correlation["signal_risks"]
    if sr["dependencies"] in ("medium", "high", "critical"):
        recs.append("Run dependency audit and update vulnerable packages")
    if sr["secrets"] != "none":
        recs.append("Add pre-commit hooks (detect-secrets) to prevent credential leaks")
    if sr["pull_requests"] in ("medium", "high"):
        recs.append("Enforce code review via branch protection rules")
    hs = sr["health"]
    if hs["score"] < 60:
        recs.append(f"Repository health is {hs['score']}/100 — address community files and stale issues")

    # deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for r in recs:
        if r not in seen:
            seen.add(r)
            unique.append(r)

    return {
        "overall_risk": overall,
        "actions_to_take": actions,
        "recommendations": unique,
        "reasoning": (
            f"Overall risk is {overall.upper()}. "
            + "; ".join(correlation.get("correlations", []))
        ),
    }


# ---------------------------------------------------------------------------
# Main analysis SSE stream
# ---------------------------------------------------------------------------
async def _analysis_stream(owner: str, repo: str) -> AsyncGenerator[str, None]:
    client = GitHubClient()

    try:
        # ======== PHASE 1 — SIGNAL COLLECTION ========
        yield _sse("phase", {"phase": "signal", "status": "active"})
        await asyncio.sleep(0.2)

        # Health
        health = await HealthAnalyzer(client).analyze(owner, repo)
        yield _sse("signal", {"type": "health", "data": health})

        # Commits
        commits = await CommitAnalyzer(client).analyze(owner, repo, count=10)
        yield _sse("signal", {"type": "commits", "data": commits})
        for c in commits.get("commits", []):
            if c.get("risk_level") in ("medium", "high"):
                yield _sse("finding", {
                    "type": "commit",
                    "severity": c["risk_level"],
                    "title": f"Risky commit: {c.get('message', '')[:60]}",
                    "detail": (
                        f"by {c.get('author', 'unknown')} — "
                        f"{', '.join(c.get('risk_indicators', []))}"
                    ),
                })

        # Pull requests
        prs = await PRAnalyzer(client).analyze(owner, repo)
        yield _sse("signal", {"type": "prs", "data": prs})
        for p in prs.get("pull_requests", []):
            if p.get("risk_level") in ("medium", "high"):
                yield _sse("finding", {
                    "type": "pr",
                    "severity": p["risk_level"],
                    "title": f"Risky PR #{p.get('number', '?')}: {p.get('title', '')[:50]}",
                    "detail": ", ".join(p.get("risk_indicators", [])),
                })

        yield _sse("phase", {"phase": "signal", "status": "complete"})
        await asyncio.sleep(0.2)

        # ======== PHASE 2 — CORRELATE (security scanning) ========
        yield _sse("phase", {"phase": "correlate", "status": "active"})

        tree_items = await client.get_directory_tree(owner, repo)
        tree_paths = [i["path"] for i in tree_items if i.get("type") == "blob"]

        # -- Dependency scan --
        dep_results: dict[str, Any] = {
            "risk_level": "none",
            "vulnerabilities": [],
            "packages_scanned": 0,
            "severity_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        }
        manifests = [
            p for p in tree_paths
            if os.path.basename(p) in _MANIFEST_NAMES
        ]

        if manifests:
            nvd = NVDClient()
            scanner = DependencyScanner(nvd)
            for mp in manifests[:3]:
                try:
                    content = await client.get_file_content(owner, repo, mp)
                    result = await scanner.scan(mp, content)
                    if result:
                        dep_results["packages_scanned"] += result.get("packages_scanned", 0)
                        dep_results["vulnerabilities"].extend(result.get("vulnerabilities", []))
                        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                            dep_results["severity_distribution"][sev] += (
                                result.get("severity_distribution", {}).get(sev, 0)
                            )
                        if _risk_ord(result.get("risk_level", "none")) > _risk_ord(dep_results["risk_level"]):
                            dep_results["risk_level"] = result["risk_level"]
                except Exception as exc:
                    logger.warning("Dep scan failed for %s: %s", mp, exc)
            dep_results["vulnerability_count"] = len(dep_results["vulnerabilities"])

        yield _sse("signal", {"type": "dependencies", "data": dep_results})
        for v in dep_results["vulnerabilities"]:
            yield _sse("finding", {
                "type": "cve",
                "severity": v.get("severity", "unknown").lower(),
                "title": f"{v.get('cve_id', 'CVE')} in {v.get('package', '?')}",
                "detail": (v.get("description") or "")[:80],
            })

        # -- Secret scan --
        scan_paths = [
            p for p in tree_paths
            if not any(d in p.split("/") for d in _SKIP_DIRS)
            and not any(p.lower().endswith(ext) for ext in _SKIP_EXTS)
        ][:25]

        all_secrets: list[dict] = []
        for sp in scan_paths:
            try:
                content = await client.get_file_content(owner, repo, sp)
                findings = scan_content(content, sp)
                all_secrets.extend(findings)
            except Exception:
                pass

        secret_data: dict[str, Any] = {
            "files_scanned": len(scan_paths),
            "finding_count": len(all_secrets),
            "risk_level": (
                "critical" if any(s.get("severity") == "critical" for s in all_secrets)
                else "high" if any(s.get("severity") == "high" for s in all_secrets)
                else "medium" if all_secrets
                else "none"
            ),
            "findings": all_secrets,
            "severity_distribution": {
                "critical": sum(1 for s in all_secrets if s.get("severity") == "critical"),
                "high": sum(1 for s in all_secrets if s.get("severity") == "high"),
                "medium": sum(1 for s in all_secrets if s.get("severity") == "medium"),
            },
        }
        yield _sse("signal", {"type": "secrets", "data": secret_data})
        for s in all_secrets:
            yield _sse("finding", {
                "type": "secret",
                "severity": s.get("severity", "medium"),
                "title": f"{s.get('secret_type', 'Secret')} in {s.get('file_path', '?')}",
                "detail": f"Line {s.get('line', '?')} — {s.get('preview', '')}",
            })

        # -- Correlate --
        correlation = _correlate(health, commits, prs, dep_results, secret_data)
        yield _sse("correlation", correlation)

        yield _sse("phase", {"phase": "correlate", "status": "complete"})
        await asyncio.sleep(0.2)

        # ======== PHASE 3 — DECIDE ========
        yield _sse("phase", {"phase": "decide", "status": "active"})
        decision = _decide(correlation)
        yield _sse("decision", decision)
        yield _sse("phase", {"phase": "decide", "status": "complete"})
        await asyncio.sleep(0.2)

        # ======== PHASE 4 — ACT ========
        yield _sse("phase", {"phase": "act", "status": "active"})

        all_critical = dep_results["vulnerabilities"] + all_secrets
        sec_report = build_security_report(
            repository=f"{owner}/{repo}",
            overall_risk=correlation["overall_risk"],
            dependency_summary=dep_results,
            secret_summary=secret_data,
            critical_findings=all_critical[:10],
            recommendations=decision["recommendations"],
        )
        yield _sse("action", {
            "type": "report_generated",
            "detail": "Security audit report generated",
            "id": sec_report["report_id"],
        })

        op_report = build_operational_report(
            repository=f"{owner}/{repo}",
            health_score=health.get("health_score", 0),
            grade=health.get("grade", "?"),
            commit_risk=commits.get("aggregate_risk_level", "unknown"),
            pr_risk=prs.get("aggregate_risk_level", "unknown"),
            security_risk=correlation["overall_risk"],
            health_details=health,
            commit_summary=commits,
            pr_summary=prs,
            security_summary=sec_report,
            action_items=decision["recommendations"],
        )
        yield _sse("action", {
            "type": "operational_report",
            "detail": "Operational status report generated",
            "id": op_report["report_id"],
        })

        yield _sse("report", {
            "security": sec_report["markdown"],
            "operational": op_report["markdown"],
        })

        yield _sse("action", {
            "type": "action_logged",
            "detail": f"Analysis of {owner}/{repo} logged to audit trail",
            "id": "audit",
        })

        yield _sse("phase", {"phase": "act", "status": "complete"})

        # ======== COMPLETE ========
        total_findings = len(dep_results["vulnerabilities"]) + len(all_secrets)
        for c in commits.get("commits", []):
            if c.get("risk_level") in ("medium", "high"):
                total_findings += 1
        for p in prs.get("pull_requests", []):
            if p.get("risk_level") in ("medium", "high"):
                total_findings += 1

        yield _sse("complete", {
            "repository": f"{owner}/{repo}",
            "overall_risk": correlation["overall_risk"],
            "health_score": health.get("health_score", 0),
            "grade": health.get("grade", "?"),
            "total_findings": total_findings,
            "actions_taken": 3,
        })

    except GitHubClientError as exc:
        yield _sse("error_event", {"message": f"GitHub API error: {exc}"})
    except Exception as exc:
        logger.exception("Unexpected error during analysis")
        yield _sse("error_event", {"message": f"Analysis error: {exc}"})


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
async def index():
    return FileResponse(str(_STATIC / "index.html"))


@app.get("/api/analyze/{owner}/{repo}")
async def analyze(owner: str, repo: str):
    return StreamingResponse(
        _analysis_stream(owner, repo),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8501))
    logger.info("Starting ARCHON Dashboard at http://localhost:%d", port)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
