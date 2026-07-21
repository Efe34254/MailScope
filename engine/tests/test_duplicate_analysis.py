from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.database import AnalysisDatabase
from app.main import analyze
from app.online_intel import save_settings


def test_same_email_content_opens_existing_result_without_duplicate(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("MAILSCOPE_DATA_DIR", str(tmp_path))
    save_settings(tmp_path, {"online_intelligence": False})
    content = (
        "From: Sender <sender@example.org>\n"
        "To: analyst@example.net\n"
        "Subject: Duplicate guard\n"
        "Message-ID: <duplicate@example.org>\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "The same raw message content must be stored only once.\n"
    )
    first_path = tmp_path / "first-name.eml"
    renamed_path = tmp_path / "renamed-copy.eml"
    first_path.write_text(content, encoding="utf-8")
    renamed_path.write_text(content, encoding="utf-8")

    assert analyze(str(first_path)) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["duplicate"] is False

    assert analyze(str(renamed_path)) == 0
    duplicate = json.loads(capsys.readouterr().out)
    assert duplicate["duplicate"] is True
    assert duplicate["analysis_id"] == first["analysis_id"]
    assert duplicate["source"]["file_name"] == "first-name.eml"

    database = AnalysisDatabase(tmp_path / "mailscope.db")
    assert database.stats()["analysis_count"] == 1
    assert database.get_by_sha256(first["source"]["sha256"])["analysis_id"] == first["analysis_id"]


def test_existing_database_is_backfilled_with_source_hash(tmp_path: Path) -> None:
    database_path = tmp_path / "mailscope.db"
    legacy = {
        "analysis_id": "anl_legacy",
        "created_at": "2026-07-19T00:00:00+00:00",
        "status": "completed",
        "source": {"file_name": "legacy.eml", "sha256": "A" * 64},
        "email": {"subject": "Legacy", "from": {"address": "sender@example.org"}},
        "iocs": [],
        "attachments": [],
    }
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE analyses (
                analysis_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                file_name TEXT NOT NULL,
                status TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO analyses VALUES (?, ?, ?, ?, ?)",
            (
                legacy["analysis_id"], legacy["created_at"], legacy["source"]["file_name"],
                legacy["status"], json.dumps(legacy),
            ),
        )

    database = AnalysisDatabase(database_path)

    assert database.get_by_sha256("a" * 64)["analysis_id"] == "anl_legacy"
    with sqlite3.connect(database_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(analyses)")}
    assert "source_sha256" in columns


def test_legacy_exact_duplicates_are_archived_and_newest_is_kept(tmp_path: Path) -> None:
    database_path = tmp_path / "mailscope.db"
    database = AnalysisDatabase(database_path)
    shared_hash = "b" * 64
    for analysis_id, created_at in (
        ("anl_old", "2026-07-18T08:00:00+00:00"),
        ("anl_new", "2026-07-19T08:00:00+00:00"),
    ):
        database.save({
            "analysis_id": analysis_id,
            "created_at": created_at,
            "status": "completed",
            "source": {"file_name": "same.eml", "sha256": shared_hash},
            "email": {"subject": "Same email", "from": {"address": "sender@example.org"}},
            "iocs": [],
            "attachments": [],
            "tool_reports": [],
        })

    archived = database.archive_exact_duplicates()

    assert archived == ["anl_old"]
    assert database.stats()["analysis_count"] == 1
    assert database.get_by_sha256(shared_hash)["analysis_id"] == "anl_new"
    with sqlite3.connect(database_path) as connection:
        archived_row = connection.execute(
            "SELECT analysis_id, reason FROM archived_duplicate_analyses"
        ).fetchone()
    assert archived_row == ("anl_old", "exact_source_sha256_duplicate")


def test_database_unique_hash_constraint_handles_concurrent_saves(tmp_path: Path) -> None:
    database = AnalysisDatabase(tmp_path / "mailscope.db")
    database.ensure_unique_source_hash()
    shared_hash = "c" * 64

    def save_case(index: int) -> dict:
        return database.save({
            "analysis_id": f"anl_{index}",
            "created_at": f"2026-07-21T10:00:0{index}+00:00",
            "status": "completed",
            "source": {"file_name": f"copy-{index}.eml", "sha256": shared_hash},
            "email": {"subject": "Concurrent", "from": {"address": "sender@example.org"}},
            "iocs": [],
            "attachments": [],
            "tool_reports": [],
        })

    with ThreadPoolExecutor(max_workers=2) as executor:
        saved = list(executor.map(save_case, (1, 2)))

    assert database.stats()["analysis_count"] == 1
    assert saved[0]["analysis_id"] == saved[1]["analysis_id"]
    with sqlite3.connect(tmp_path / "mailscope.db") as connection:
        indexes = {row[1] for row in connection.execute("PRAGMA index_list(analyses)")}
    assert "idx_analyses_unique_source_sha256" in indexes


def test_archived_duplicates_follow_retention_and_manual_delete(tmp_path: Path) -> None:
    database = AnalysisDatabase(tmp_path / "mailscope.db")
    shared_hash = "d" * 64
    old_created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    for analysis_id in ("anl_old_1", "anl_old_2"):
        database.save({
            "analysis_id": analysis_id,
            "created_at": old_created,
            "status": "completed",
            "source": {"file_name": "old.eml", "sha256": shared_hash},
            "email": {"subject": "Old", "from": {"address": "sender@example.org"}},
            "iocs": [],
            "attachments": [],
            "tool_reports": [],
        })
    database.archive_exact_duplicates()
    database.prune_older_than(1)

    with sqlite3.connect(tmp_path / "mailscope.db") as connection:
        assert connection.execute("SELECT COUNT(*) FROM archived_duplicate_analyses").fetchone()[0] == 0

    # Manual deletion also removes any archived copies with the same source hash.
    active = {
        "analysis_id": "anl_active",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "completed",
        "source": {"file_name": "active.eml", "sha256": "e" * 64},
        "email": {"subject": "Active", "from": {"address": "sender@example.org"}},
        "iocs": [], "attachments": [], "tool_reports": [],
    }
    duplicate = {**active, "analysis_id": "anl_active_duplicate"}
    database.save(active)
    database.save(duplicate)
    database.archive_exact_duplicates()
    assert database.delete("anl_active_duplicate") or database.delete("anl_active")
    with sqlite3.connect(tmp_path / "mailscope.db") as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM archived_duplicate_analyses WHERE source_sha256 = ?", ("e" * 64,)
        ).fetchone()[0] == 0
