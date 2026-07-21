from __future__ import annotations

from typing import Any, Iterable


DEFAULT_SEVERITY_POINTS = {
    "info": 0,
    "low": 5,
    "medium": 15,
    "high": 30,
    "critical": 50,
}

RISK_MODEL_VERSION = "3.0"
CATEGORY_CAPS = {
    "authentication": 40,
    "identity": 25,
    "html": 40,
    "content": 20,
    "attachment": 60,
    "threat_intelligence": 60,
    "privacy": 10,
}


def _value(item: Any, key: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def assess_risk(findings: Iterable[Any], reports: Iterable[Any] = ()) -> dict[str, Any]:
    """Build one explainable risk verdict from local and online findings."""
    raw_contributions: list[dict[str, Any]] = []
    for finding in findings:
        severity = str(_value(finding, "severity", "info")).lower()
        configured = _value(finding, "risk_points")
        points = DEFAULT_SEVERITY_POINTS.get(severity, 0) if configured is None else max(0, int(configured))
        if points <= 0:
            continue
        category = str(_value(finding, "category", "other")).lower()
        raw_contributions.append({
            "title": str(_value(finding, "title", "Finding")),
            "raw_points": points,
            "severity": severity,
            "source": str(_value(finding, "tool_id", "unknown")),
            "category": category,
            "rationale": str(_value(finding, "description", "")),
        })
    raw_contributions.sort(key=lambda item: (-int(item["raw_points"]), item["title"].lower()))
    category_used: dict[str, int] = {}
    category_raw: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    contributions: list[dict[str, Any]] = []
    for item in raw_contributions:
        category = str(item["category"])
        cap = CATEGORY_CAPS.get(category, 50)
        used = category_used.get(category, 0)
        credited = min(int(item["raw_points"]), max(0, cap - used))
        category_used[category] = used + credited
        category_raw[category] = category_raw.get(category, 0) + int(item["raw_points"])
        category_counts[category] = category_counts.get(category, 0) + 1
        contributions.append({**item, "points": credited, "category_cap": cap})
    contributions.sort(key=lambda item: (-int(item["points"]), -int(item["raw_points"]), item["title"].lower()))
    score = min(100, sum(int(item["points"]) for item in contributions))
    level = (
        "critical" if score >= 80 else
        "high" if score >= 55 else
        "medium" if score >= 30 else
        "low" if score >= 10 else
        "informational"
    )

    report_list = list(reports)
    incomplete_checks: list[str] = []
    for report in report_list:
        name = str(_value(report, "name", _value(report, "tool_id", "Unknown check")))
        status = str(_value(report, "status", "")).lower()
        metrics = _value(report, "metrics", {}) or {}
        errors = int(metrics.get("errors", 0) or 0) if isinstance(metrics, dict) else 0
        label = f"{name} ({errors} lookup error{'s' if errors != 1 else ''})" if errors else name
        if status in {"error", "offline", "unavailable"} or errors:
            if label not in incomplete_checks:
                incomplete_checks.append(label)
    online_status = next(
        (str(_value(report, "status", "")) for report in report_list if _value(report, "tool_id") == "online_status"),
        "",
    )
    if online_status == "disabled":
        coverage = "local-only"
    elif incomplete_checks:
        coverage = "medium" if len(incomplete_checks) <= 2 else "low"
    else:
        coverage = "high"

    if score >= 55:
        actions = [
            "Quarantine the message and escalate it for analyst review.",
            "Block confirmed malicious indicators according to organizational policy.",
            "Validate the sender through a trusted out-of-band channel before taking business action.",
        ]
    elif score >= 30:
        actions = [
            "Hold the message for manual review before interacting with links or attachments.",
            "Validate the sender and business context through a trusted channel.",
            "Review the highest-scoring evidence and provider details.",
        ]
    elif score >= 10:
        actions = [
            "Review the highlighted evidence and confirm the expected business context.",
            "Avoid interacting with links or attachments until the sender is validated when uncertainty remains.",
        ]
    else:
        actions = [
            "No elevated evidence was found; apply normal organizational email-handling policy.",
        ]
    if incomplete_checks:
        actions.append("Refresh or repeat incomplete intelligence checks before closing the case.")

    return {
        "model_version": RISK_MODEL_VERSION,
        "score": score,
        "level": level,
        # Kept for backwards-compatible JSON consumers. The product presents
        # this as analysis coverage, never as a safety guarantee.
        "confidence": coverage,
        "coverage": coverage,
        "reasons": [str(item["title"]) for item in contributions if int(item["points"]) > 0][:8],
        "score_breakdown": contributions,
        "category_breakdown": [
            {
                "category": category,
                "raw_points": category_raw[category],
                "credited_points": category_used[category],
                "cap": CATEGORY_CAPS.get(category, 50),
                "evidence_count": category_counts[category],
            }
            for category in sorted(category_raw)
        ],
        "incomplete_checks": incomplete_checks,
        "recommended_actions": actions,
    }
