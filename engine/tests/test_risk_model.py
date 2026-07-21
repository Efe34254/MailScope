from __future__ import annotations

from app.risk_engine import assess_risk


def test_correlated_provider_findings_are_capped_by_category() -> None:
    findings = [
        {
            "severity": "critical",
            "category": "threat_intelligence",
            "title": f"Provider {index}",
            "description": "Same indicator was reported by another provider.",
            "tool_id": f"provider_{index}",
            "risk_points": 45,
        }
        for index in range(3)
    ]

    risk = assess_risk(findings)

    assert risk["model_version"] == "3.0"
    assert risk["score"] == 60
    category = risk["category_breakdown"][0]
    assert category["raw_points"] == 135
    assert category["credited_points"] == 60
    assert category["cap"] == 60
    assert sum(item["points"] for item in risk["score_breakdown"]) == 60
