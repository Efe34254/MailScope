from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.database import AnalysisDatabase
from app.main import _apply_retention
from app.online_intel import load_settings, save_settings


def _result(analysis_id: str, created_at: str) -> dict:
    return {
        "analysis_id": analysis_id,
        "created_at": created_at,
        "status": "completed",
        "source": {"file_name": f"{analysis_id}.eml", "sha256": analysis_id},
        "email": {"subject": analysis_id, "from": {"address": "sender@example.org"}},
        "iocs": [],
        "attachments": [],
    }


def test_settings_are_normalized_and_deprecated_keys_are_removed(tmp_path: Path) -> None:
    saved = save_settings(tmp_path, {
        "online_intelligence": False,
        "auto_check_online": True,
        "max_queries_per_provider": 200,
        "history_retention_days": 17,
        "upload_attachments": True,
        "upload_emails": True,
    })

    assert saved["online_intelligence"] is False
    assert saved["verify_email_authentication"] is True
    assert saved["max_queries_per_provider"] == 25
    assert saved["history_retention_days"] == 30
    assert saved["upload_attachments"] is False
    assert saved["upload_emails"] is False
    assert "auto_check_online" not in saved
    assert load_settings(tmp_path) == saved


def test_api_keys_are_encrypted_at_rest_with_windows_dpapi(tmp_path: Path) -> None:
    secret = "soc-test-api-key-value"
    abusech_secret = "abusech-shared-auth-key"
    urlscan_secret = "urlscan-search-api-key"
    saved = save_settings(tmp_path, {"virustotal_api_key": secret, "abusech_auth_key": abusech_secret, "urlscan_api_key": urlscan_secret})

    assert saved["virustotal_api_key"] == secret
    stored = (tmp_path / "settings.json").read_text(encoding="utf-8")
    assert secret not in stored
    assert abusech_secret not in stored
    assert urlscan_secret not in stored
    assert "dpapi:v1:" in stored
    assert load_settings(tmp_path)["virustotal_api_key"] == secret
    assert load_settings(tmp_path)["abusech_auth_key"] == abusech_secret
    assert load_settings(tmp_path)["urlscan_api_key"] == urlscan_secret


def test_retention_removes_old_database_rows_and_workspace(tmp_path: Path) -> None:
    database = AnalysisDatabase(tmp_path / "mailscope.db")
    workspace = tmp_path / "workspace"
    old_id = "anl_old"
    recent_id = "anl_recent"
    now = datetime.now(timezone.utc)
    database.save(_result(old_id, (now - timedelta(days=31)).isoformat()))
    database.save(_result(recent_id, (now - timedelta(days=2)).isoformat()))
    for analysis_id in (old_id, recent_id):
        folder = workspace / analysis_id / "attachments"
        folder.mkdir(parents=True)
        (folder / "sample.bin").write_bytes(b"sample")

    save_settings(tmp_path, {"history_retention_days": 30})
    _apply_retention(tmp_path, workspace, database)

    assert database.get(old_id) is None
    assert not (workspace / old_id).exists()
    assert database.get(recent_id) is not None
    assert (workspace / recent_id).is_dir()


def test_dashboard_counts_analyses_with_tool_errors(tmp_path: Path) -> None:
    database = AnalysisDatabase(tmp_path / "mailscope.db")
    result = _result("anl_error", datetime.now(timezone.utc).isoformat())
    result["tool_reports"] = [{"tool_id": "capa", "status": "error"}]
    database.save(result)

    assert database.stats()["flagged_count"] == 1
