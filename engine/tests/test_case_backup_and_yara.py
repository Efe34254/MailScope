from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from app.backup_manager import create_backup, restore_backup
from app.database import AnalysisDatabase
from app.static_tools import yara_scan
from app.yara_manager import import_rule, set_active


def _result(analysis_id: str = "anl_case") -> dict:
    return {
        "analysis_id": analysis_id,
        "created_at": "2026-07-21T10:00:00+00:00",
        "status": "completed",
        "source": {"file_name": "case.eml", "sha256": "f" * 64},
        "email": {"subject": "Case", "from": {"address": "sender@example.org"}},
        "iocs": [], "attachments": [], "tool_reports": [],
    }


def test_case_metadata_and_event_history_are_persisted(tmp_path: Path) -> None:
    database = AnalysisDatabase(tmp_path / "mailscope.db")
    database.save(_result())

    case = database.update_case("anl_case", {
        "state": "Investigating",
        "assigned_analyst": "Analyst One",
        "analyst_decision": "Needs sender validation",
        "closure_reason": "",
        "tags": ["phishing", "priority"],
        "note": "Contacted finance through a trusted channel.",
    })

    assert case["state"] == "Investigating"
    assert case["tags"] == ["phishing", "priority"]
    assert case["events"][0]["event_type"] == "case_updated"
    assert case["events"][0]["details"]["note"].startswith("Contacted finance")
    assert database.list()[0]["case_state"] == "Investigating"


def test_backup_restore_validates_and_restores_case_data(tmp_path: Path) -> None:
    database = AnalysisDatabase(tmp_path / "mailscope.db")
    database.save(_result())
    database.update_case("anl_case", {"state": "Malicious", "tags": ["confirmed"]})
    (tmp_path / "settings.json").write_text(json.dumps({"online_intelligence": False}), encoding="utf-8")
    workspace = tmp_path / "workspace" / "anl_case"
    workspace.mkdir(parents=True)
    (workspace / "evidence.txt").write_text("evidence", encoding="utf-8")
    backup = tmp_path / "exports" / "case.msbackup"

    created = create_backup(tmp_path, backup)
    database.update_case("anl_case", {"state": "Benign", "tags": []})
    restored = restore_backup(tmp_path, backup)

    reloaded = AnalysisDatabase(tmp_path / "mailscope.db")
    assert created["format"] == "mailscope-backup-v1"
    assert restored["restored"] is True
    assert reloaded.case("anl_case")["state"] == "Malicious"
    assert (workspace / "evidence.txt").read_text(encoding="utf-8") == "evidence"
    assert Path(restored["automatic_backup"]).is_file()


def test_custom_yara_rule_versions_can_be_enabled_and_disabled(tmp_path: Path, monkeypatch) -> None:
    rule = tmp_path / "custom-test.yar"
    rule.write_text(
        'rule custom_marker { meta: severity = "medium" description = "custom marker" '
        'strings: $a = "MAILSCOPE_CUSTOM_MARKER" condition: $a }',
        encoding="utf-8",
    )
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"prefix MAILSCOPE_CUSTOM_MARKER suffix")
    monkeypatch.setenv("MAILSCOPE_DATA_DIR", str(tmp_path))

    imported = import_rule(tmp_path, rule)
    digest = imported["custom_rules"][0]["active"]
    enabled_scan = yara_scan(sample)
    disabled = set_active(tmp_path, "custom-test", None)
    disabled_scan = yara_scan(sample)

    assert any(item["rule"] == "custom_marker" for item in enabled_scan["matches"])
    assert disabled["custom_rules"][0]["enabled"] is False
    assert not any(item["rule"] == "custom_marker" for item in disabled_scan["matches"])
    assert len(digest) == 64


def test_legacy_database_without_status_column_is_migrated(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    result = {
        "analysis_id": "anl_legacy",
        "created_at": "2026-07-01T00:00:00+00:00",
        "status": "completed",
        "source": {"file_name": "legacy.eml", "sha256": "a" * 64},
    }
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE analyses (analysis_id TEXT PRIMARY KEY, created_at TEXT, "
            "file_name TEXT, result_json TEXT, source_sha256 TEXT)"
        )
        connection.execute(
            "INSERT INTO analyses VALUES (?, ?, ?, ?, ?)",
            ("anl_legacy", result["created_at"], "legacy.eml", json.dumps(result), "a" * 64),
        )

    database = AnalysisDatabase(path)

    assert database.get("anl_legacy") is not None
    with sqlite3.connect(path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(analyses)")}
        status = connection.execute(
            "SELECT status FROM analyses WHERE analysis_id = 'anl_legacy'"
        ).fetchone()[0]
    assert "status" in columns
    assert status == "completed"
