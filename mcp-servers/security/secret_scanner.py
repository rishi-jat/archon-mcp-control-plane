"""Secret / credential detection in source code.

Combines high-entropy string detection (Shannon entropy) with
regex-based pattern matching for common secret formats:
  • AWS access keys and secret keys
  • GitHub personal access tokens
  • Generic API keys and bearer tokens
  • Private keys (RSA, EC, etc.)
  • Connection strings and database URLs
  • JWT tokens
"""

from __future__ import annotations

import base64
import logging
import math
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns for known secret formats
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "AWS Access Key",
        re.compile(r"(?:^|[^A-Za-z0-9/+=])(?:AKIA|ASIA)[A-Z0-9]{16}(?:[^A-Za-z0-9/+=]|$)"),
        "critical",
    ),
    (
        "AWS Secret Key",
        re.compile(r"""(?:aws_secret_access_key|secret_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?""", re.IGNORECASE),
        "critical",
    ),
    (
        "GitHub Token",
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"),
        "critical",
    ),
    (
        "GitHub Fine-Grained PAT",
        re.compile(r"github_pat_[A-Za-z0-9_]{22,255}"),
        "critical",
    ),
    (
        "Generic API Key Assignment",
        re.compile(r"""(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"]?[A-Za-z0-9_\-]{20,}['"]?""", re.IGNORECASE),
        "high",
    ),
    (
        "Bearer Token",
        re.compile(r"""[Bb]earer\s+[A-Za-z0-9_\-\.]{20,}"""),
        "high",
    ),
    (
        "Private Key Header",
        re.compile(r"-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----"),
        "critical",
    ),
    (
        "Database URL",
        re.compile(r"""(?:postgres|mysql|mongodb|redis)://[^\s'"]{10,}""", re.IGNORECASE),
        "high",
    ),
    (
        "Slack Token",
        re.compile(r"xox[bporas]-[A-Za-z0-9-]{10,}"),
        "high",
    ),
    (
        "JWT Token",
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "medium",
    ),
    (
        "Hex-encoded Secret (32+ chars)",
        re.compile(r"""(?:secret|password|token|key)\s*[=:]\s*['"]?[0-9a-f]{32,}['"]?""", re.IGNORECASE),
        "high",
    ),
    (
        "Generic Password Assignment",
        re.compile(r"""(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]""", re.IGNORECASE),
        "high",
    ),
]

# Files to always skip
_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".bin", ".exe",
    ".mp3", ".mp4", ".avi", ".mov",
    ".pdf", ".doc", ".docx",
    ".lock",
})

_SKIP_PATHS = frozenset({
    "node_modules/",
    "vendor/",
    ".git/",
    "dist/",
    "build/",
    "__pycache__/",
})


# ---------------------------------------------------------------------------
# Entropy calculation
# ---------------------------------------------------------------------------


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string (bits per character)."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values()
    )


# Typical thresholds:
#   English text: ~3.5–4.5
#   Base64 encoded: ~5.2–5.8
#   Hex strings:   ~3.5–4.0
#   Random secrets: ~5.5–6.0+
_HIGH_ENTROPY_THRESHOLD = 5.0
_MIN_ENTROPY_TOKEN_LEN = 20


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _should_skip_path(path: str) -> bool:
    """Return True if this file path should be excluded from scanning."""
    ext = ""
    dot_idx = path.rfind(".")
    if dot_idx != -1:
        ext = path[dot_idx:].lower()
    if ext in _SKIP_EXTENSIONS:
        return True
    return any(skip in path for skip in _SKIP_PATHS)


def _mask(text: str, visible: int = 6) -> str:
    """Mask a secret, keeping the first *visible* characters."""
    if len(text) <= visible:
        return "***"
    return text[:visible] + "***" + text[-3:]


def scan_content(
    content: str,
    file_path: str = "<unknown>",
    *,
    max_findings: int = 50,
) -> list[dict[str, Any]]:
    """Scan a single file's content for potential secrets.

    Returns a list of finding dicts, each with ``secret_type``,
    ``severity``, ``line``, ``preview`` (masked), and optionally
    ``entropy``.
    """
    if _should_skip_path(file_path):
        return []

    findings: list[dict[str, Any]] = []
    seen_lines: set[int] = set()  # avoid duplicate reports per line

    for line_no, line in enumerate(content.splitlines(), start=1):
        if len(findings) >= max_findings:
            break

        # -- regex patterns --------------------------------------------------
        for secret_type, pattern, severity in _SECRET_PATTERNS:
            match = pattern.search(line)
            if match and line_no not in seen_lines:
                seen_lines.add(line_no)
                matched_text = match.group(0).strip()
                findings.append({
                    "file_path": file_path,
                    "line": line_no,
                    "secret_type": secret_type,
                    "severity": severity,
                    "preview": _mask(matched_text),
                    "detection": "pattern",
                })
                break  # one finding per line is enough

        # -- high-entropy tokens (only for lines not already flagged) --------
        if line_no not in seen_lines:
            tokens = re.findall(r"[A-Za-z0-9_/+=\-]{20,}", line)
            for token in tokens:
                if len(token) >= _MIN_ENTROPY_TOKEN_LEN:
                    ent = shannon_entropy(token)
                    if ent >= _HIGH_ENTROPY_THRESHOLD:
                        findings.append({
                            "file_path": file_path,
                            "line": line_no,
                            "secret_type": "High-Entropy String",
                            "severity": "medium",
                            "preview": _mask(token),
                            "entropy": round(ent, 2),
                            "detection": "entropy",
                        })
                        seen_lines.add(line_no)
                        break

    return findings


def scan_file_list(
    files: list[tuple[str, str]],
    *,
    max_findings_per_file: int = 30,
    max_total_findings: int = 100,
) -> dict[str, Any]:
    """Scan multiple files for secrets.

    Parameters
    ----------
    files:
        List of (file_path, content) tuples.
    max_findings_per_file:
        Cap per individual file.
    max_total_findings:
        Global cap across all files.

    Returns
    -------
    dict:
        Structured scan result.
    """
    all_findings: list[dict[str, Any]] = []
    files_scanned = 0
    files_with_findings = 0

    for path, content in files:
        if len(all_findings) >= max_total_findings:
            break
        if _should_skip_path(path):
            continue

        findings = scan_content(
            content, path, max_findings=max_findings_per_file,
        )
        files_scanned += 1
        if findings:
            files_with_findings += 1
            remaining = max_total_findings - len(all_findings)
            all_findings.extend(findings[:remaining])

    severity_dist: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0,
    }
    for f in all_findings:
        sev = f.get("severity", "medium")
        severity_dist[sev] = severity_dist.get(sev, 0) + 1

    if severity_dist["critical"] > 0:
        risk_level = "critical"
    elif severity_dist["high"] > 0:
        risk_level = "high"
    elif severity_dist["medium"] > 0:
        risk_level = "medium"
    elif all_findings:
        risk_level = "low"
    else:
        risk_level = "none"

    return {
        "signal_type": "secret_scan",
        "files_scanned": files_scanned,
        "files_with_findings": files_with_findings,
        "total_findings": len(all_findings),
        "risk_level": risk_level,
        "severity_distribution": severity_dist,
        "findings": all_findings,
    }
