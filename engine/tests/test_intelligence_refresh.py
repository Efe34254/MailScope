from __future__ import annotations

from app import main
from app.database import AnalysisDatabase


def test_refresh_intelligence_replaces_saved_provider_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("MAILSCOPE_DATA_DIR", str(tmp_path))
    database = AnalysisDatabase(tmp_path / "mailscope.db")
    database.save({
        "analysis_id": "anl_refresh",
        "created_at": "2026-07-21T00:00:00+00:00",
        "status": "completed",
        "source": {"file_name": "sample.eml", "sha256": "a" * 64},
        "email": {"subject": "Refresh test", "from": {"address": "sender@example.org"}},
        "risk": {"score": 0, "level": "informational"},
        "findings": [],
        "iocs": [],
        "attachments": [],
        "tool_reports": [{"tool_id": "urlscan", "name": "urlscan.io", "status": "error", "summary": "Old result", "metrics": {}, "details": []}],
    })

    def fake_enrich(payload: dict, base_dir, force_refresh: bool = False) -> dict:
        payload["tool_reports"] = [{"tool_id": "urlscan", "name": "urlscan.io", "status": "clean", "summary": "Refreshed", "metrics": {}, "details": []}]
        payload["risk"] = {"score": 0, "level": "informational", "confidence": "high", "reasons": [], "score_breakdown": [], "incomplete_checks": [], "recommended_actions": []}
        payload["intelligence"] = {"refreshed_at": "2026-07-21T01:00:00+00:00", "indicator_verdicts": [], "provider_errors": [], "file_uploads": 0, "email_uploads": 0}
        return payload

    monkeypatch.setattr(main, "enrich", fake_enrich)

    assert main.refresh_intelligence("anl_refresh") == 0
    saved = AnalysisDatabase(tmp_path / "mailscope.db").get("anl_refresh")
    assert saved is not None
    assert saved["tool_reports"][0]["status"] == "clean"
    assert saved["intelligence_refreshed"] is True
