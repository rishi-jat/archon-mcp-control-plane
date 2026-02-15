"""NVD (National Vulnerability Database) async client.

Queries the NIST NVD 2.0 REST API for CVE data.  The public API is
rate-limited to ~5 requests per rolling 30-second window without an
API key and ~50 with one.

Reference: https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = 30.0


class NVDClientError(Exception):
    """Raised when the NVD API returns a non-2xx response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        super().__init__(f"NVD API {status_code}: {detail}")


class NVDClient:
    """Async client for the NIST NVD 2.0 Vulnerability API."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = api_key or os.environ.get("NVD_API_KEY")

    @property
    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"User-Agent": "archon-security/1.0"}
        if self._api_key:
            h["apiKey"] = self._api_key
        return h

    async def search_cves(
        self,
        keyword: str,
        *,
        results_per_page: int = 20,
        start_index: int = 0,
    ) -> dict[str, Any]:
        """Search CVEs by keyword (package name, library, etc.).

        Returns the raw NVD response dict with a ``vulnerabilities``
        list.
        """
        params: dict[str, Any] = {
            "keywordSearch": keyword,
            "resultsPerPage": min(results_per_page, 100),
            "startIndex": start_index,
        }
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                _API_BASE, headers=self._headers, params=params,
            )
            if resp.status_code >= 400:
                raise NVDClientError(resp.status_code, resp.text[:500])
            return resp.json()

    async def get_cve(self, cve_id: str) -> dict[str, Any]:
        """Fetch full details for a specific CVE ID (e.g. CVE-2024-1234)."""
        params = {"cveId": cve_id}
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(
                _API_BASE, headers=self._headers, params=params,
            )
            if resp.status_code >= 400:
                raise NVDClientError(resp.status_code, resp.text[:500])
            return resp.json()


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def parse_cve_item(vuln_wrapper: dict[str, Any]) -> dict[str, Any]:
    """Flatten an NVD ``vulnerabilities[]`` entry into a usable dict.

    The NVD 2.0 response nests data several levels deep.  This function
    extracts the fields we care about into a flat structure.
    """
    cve = vuln_wrapper.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")
    descriptions = cve.get("descriptions", [])
    desc_en = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available",
    )

    # -- CVSS scoring --------------------------------------------------------
    metrics = cve.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [{}])
    cvss_v30 = metrics.get("cvssMetricV30", [{}])
    cvss_v2 = metrics.get("cvssMetricV2", [{}])

    cvss_data: dict[str, Any] = {}
    severity = "UNKNOWN"
    base_score = 0.0

    if cvss_v31:
        cvss_data = cvss_v31[0].get("cvssData", {})
        severity = cvss_v31[0].get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
        base_score = cvss_data.get("baseScore", 0.0)
    elif cvss_v30:
        cvss_data = cvss_v30[0].get("cvssData", {})
        severity = cvss_v30[0].get("baseSeverity", cvss_data.get("baseSeverity", "UNKNOWN"))
        base_score = cvss_data.get("baseScore", 0.0)
    elif cvss_v2:
        cvss_data = cvss_v2[0].get("cvssData", {})
        base_score = cvss_data.get("baseScore", 0.0)
        if base_score >= 9.0:
            severity = "CRITICAL"
        elif base_score >= 7.0:
            severity = "HIGH"
        elif base_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    # -- references ----------------------------------------------------------
    refs = [
        r.get("url", "")
        for r in cve.get("references", [])
        if r.get("url")
    ][:5]

    # -- affected configurations (CPE) --------------------------------------
    affected: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if criteria:
                    affected.append(criteria)

    return {
        "cve_id": cve_id,
        "severity": severity.upper(),
        "cvss_score": base_score,
        "description": desc_en[:500],
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "references": refs,
        "affected_cpe": affected[:10],
        "attack_vector": cvss_data.get("attackVector", "UNKNOWN"),
    }
