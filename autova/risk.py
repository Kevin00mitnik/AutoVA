"""Finding normalization and straightforward severity-based risk scoring."""

from __future__ import annotations

from typing import Any


SEVERITY_SCORES = {
    "critical": 10,
    "high": 8,
    "medium": 6,
    "low": 3,
    "info": 1,
    "informational": 1,
    "unknown": 2,
}


def make_finding(
    *,
    title: str,
    severity: str,
    source: str,
    asset: str,
    detail: str = "",
    evidence: str = "",
    identifier: str = "",
) -> dict[str, Any]:
    severity = severity.lower()
    if severity not in SEVERITY_SCORES:
        severity = "unknown"
    return {
        "id": identifier or f"{source}:{title}",
        "title": title,
        "severity": severity,
        "score": SEVERITY_SCORES[severity],
        "source": source,
        "asset": asset,
        "detail": detail,
        "evidence": evidence,
    }


def risk_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info", "unknown")}
    for finding in findings:
        severity = finding["severity"]
        counts[severity if severity in counts else "unknown"] += 1
    overall = next(
        (severity for severity in ("critical", "high", "medium", "low") if counts[severity]),
        "informational" if findings else "none",
    )
    return {
        "overall": overall,
        "score": max((finding["score"] for finding in findings), default=0),
        "finding_count": len(findings),
        "counts": counts,
    }
