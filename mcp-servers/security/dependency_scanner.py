"""Dependency vulnerability scanner.

Parses common dependency manifest files (package.json, requirements.txt,
go.mod, Cargo.toml, pom.xml, etc.) and checks each dependency against
the NIST NVD for known CVEs.

Designed to work with raw file content (fetched via the GitHub API or
supplied directly).
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from nvd_client import NVDClient, NVDClientError, parse_cve_item

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Parsers — extract (name, version) pairs from manifest content
# ---------------------------------------------------------------------------

# We support the most common ecosystems.  Each parser receives the raw
# file content as a string and returns a list of (package, version) tuples.


def _parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """Parse Python requirements.txt / requirements*.txt."""
    deps: list[tuple[str, str]] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle: package==1.2.3, package>=1.2.3, package~=1.2.3
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*[=~!<>]=?\s*([0-9][^\s,;]*)", line)
        if match:
            deps.append((match.group(1).lower(), match.group(2)))
        else:
            # package without pinned version
            plain = re.match(r"^([A-Za-z0-9_.-]+)", line)
            if plain:
                deps.append((plain.group(1).lower(), "latest"))
    return deps


def _parse_package_json(content: str) -> list[tuple[str, str]]:
    """Parse Node.js package.json (dependencies + devDependencies)."""
    import json as _json

    deps: list[tuple[str, str]] = []
    try:
        data = _json.loads(content)
    except _json.JSONDecodeError:
        return deps

    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            # Strip semver prefixes: ^1.2.3 → 1.2.3
            clean = re.sub(r"^[~^>=<]*", "", str(version)).strip()
            deps.append((name, clean or "latest"))
    return deps


def _parse_go_mod(content: str) -> list[tuple[str, str]]:
    """Parse Go go.mod require block."""
    deps: list[tuple[str, str]] = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require or stripped.startswith("require "):
            parts = stripped.replace("require ", "").strip().split()
            if len(parts) >= 2:
                deps.append((parts[0], parts[1]))
    return deps


def _parse_cargo_toml(content: str) -> list[tuple[str, str]]:
    """Parse Rust Cargo.toml [dependencies]."""
    deps: list[tuple[str, str]] = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[dependencies]"):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps:
            match = re.match(r'^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"', stripped)
            if match:
                deps.append((match.group(1), match.group(2)))
    return deps


# ---------------------------------------------------------------------------
# Ecosystem detection
# ---------------------------------------------------------------------------

_PARSERS: dict[str, Any] = {
    "requirements.txt": ("pip", _parse_requirements_txt),
    "requirements-dev.txt": ("pip", _parse_requirements_txt),
    "requirements-prod.txt": ("pip", _parse_requirements_txt),
    "package.json": ("npm", _parse_package_json),
    "go.mod": ("go", _parse_go_mod),
    "Cargo.toml": ("cargo", _parse_cargo_toml),
}


def detect_ecosystem(filename: str) -> tuple[str, Any] | None:
    """Return (ecosystem, parser_fn) for a known manifest filename."""
    basename = filename.rsplit("/", 1)[-1]
    entry = _PARSERS.get(basename)
    if entry:
        return entry
    # Catch requirements-*.txt variants
    if re.match(r"requirements.*\.txt$", basename):
        return ("pip", _parse_requirements_txt)
    return None


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class DependencyScanner:
    """Scans parsed dependencies against the NVD for known CVEs."""

    def __init__(self, nvd: NVDClient) -> None:
        self._nvd = nvd

    async def scan(
        self,
        filename: str,
        content: str,
        *,
        max_checks: int = 25,
    ) -> dict[str, Any]:
        """Parse a manifest file and check dependencies for CVEs.

        Parameters
        ----------
        filename:
            The manifest filename (e.g. ``package.json``).
        content:
            Raw text content of the file.
        max_checks:
            Maximum number of packages to query against NVD (rate-limit
            protection).

        Returns
        -------
        dict:
            Structured scan result with per-package vulnerability info.
        """
        detection = detect_ecosystem(filename)
        if detection is None:
            return {
                "signal_type": "dependency_scan",
                "error": f"Unsupported manifest file: {filename}",
            }

        ecosystem, parser = detection
        deps = parser(content)
        logger.info(
            "Parsed %d dependencies from %s (%s)", len(deps), filename, ecosystem,
        )

        # Limit NVD queries to stay within rate limits
        deps_to_check = deps[:max_checks]
        vulnerabilities: list[dict[str, Any]] = []
        checked = 0

        for name, version in deps_to_check:
            checked += 1
            try:
                result = await self._nvd.search_cves(
                    name, results_per_page=5,
                )
                for vuln in result.get("vulnerabilities", []):
                    parsed = parse_cve_item(vuln)
                    parsed["affected_package"] = name
                    parsed["installed_version"] = version
                    vulnerabilities.append(parsed)
            except NVDClientError as exc:
                logger.warning("NVD lookup failed for %s: %s", name, exc)
            except Exception:
                logger.warning("Error checking %s", name, exc_info=True)

            # Small delay to respect rate limits
            if not self._nvd._api_key and checked % 4 == 0:
                await asyncio.sleep(6)

        # -- risk scoring ----------------------------------------------------
        severity_counts: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0,
        }
        for v in vulnerabilities:
            sev = v.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if severity_counts["CRITICAL"] > 0:
            risk_level = "critical"
        elif severity_counts["HIGH"] > 0:
            risk_level = "high"
        elif severity_counts["MEDIUM"] > 0:
            risk_level = "medium"
        elif vulnerabilities:
            risk_level = "low"
        else:
            risk_level = "none"

        return {
            "signal_type": "dependency_scan",
            "manifest_file": filename,
            "ecosystem": ecosystem,
            "total_dependencies": len(deps),
            "dependencies_checked": checked,
            "vulnerability_count": len(vulnerabilities),
            "risk_level": risk_level,
            "severity_distribution": severity_counts,
            "vulnerabilities": vulnerabilities,
        }
