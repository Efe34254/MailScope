from __future__ import annotations

import json
import hashlib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock

_DB_LOCK = Lock()


class _ClosingConnection(sqlite3.Connection):
    """sqlite transaction context that also releases the Windows file handle."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class AnalysisDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15, factory=_ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 15000")
        return connection

    def _initialize(self) -> None:
        with _DB_LOCK, self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    source_sha256 TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS case_metadata (
                    analysis_id TEXT PRIMARY KEY,
                    state TEXT NOT NULL DEFAULT 'New',
                    assigned_analyst TEXT NOT NULL DEFAULT '',
                    analyst_decision TEXT NOT NULL DEFAULT '',
                    closure_reason TEXT NOT NULL DEFAULT '',
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS case_events (
                    event_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY (analysis_id) REFERENCES analyses(analysis_id) ON DELETE CASCADE
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_case_events_analysis_created "
                "ON case_events(analysis_id, created_at DESC)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS provider_cache (
                    cache_key TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    indicator_type TEXT NOT NULL,
                    indicator_value TEXT NOT NULL,
                    verdict_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_provider_cache_expiry ON provider_cache(expires_at)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    event_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    provider_id TEXT NOT NULL DEFAULT '',
                    indicator_type TEXT NOT NULL DEFAULT '',
                    indicator_digest TEXT NOT NULL DEFAULT '',
                    outcome TEXT NOT NULL DEFAULT '',
                    details_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC)"
            )
            now = datetime.now(timezone.utc).isoformat()
            connection.execute(
                """
                INSERT OR IGNORE INTO case_metadata (analysis_id, updated_at)
                SELECT analysis_id, ? FROM analyses
                """,
                (now,),
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(analyses)").fetchall()
            }
            # Pre-1.0 development builds stored the JSON result without a
            # dedicated status column. Keep those databases readable instead
            # of requiring a destructive reset.
            if "status" not in columns:
                connection.execute(
                    "ALTER TABLE analyses ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'"
                )
                columns.add("status")
            if "source_sha256" not in columns:
                connection.execute("ALTER TABLE analyses ADD COLUMN source_sha256 TEXT")

            # Older databases predate the dedicated hash column. Backfill it
            # without deleting any historical records.
            rows = connection.execute(
                "SELECT analysis_id, result_json FROM analyses "
                "WHERE source_sha256 IS NULL OR source_sha256 = ''"
            ).fetchall()
            for row in rows:
                try:
                    result = json.loads(row["result_json"])
                    source_sha256 = str(result.get("source", {}).get("sha256", "")).lower()
                except (json.JSONDecodeError, TypeError, AttributeError):
                    source_sha256 = ""
                if source_sha256:
                    connection.execute(
                        "UPDATE analyses SET source_sha256 = ? WHERE analysis_id = ?",
                        (source_sha256, row["analysis_id"]),
                    )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_analyses_source_sha256 "
                "ON analyses(source_sha256)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS archived_duplicate_analyses (
                    analysis_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    source_sha256 TEXT NOT NULL,
                    archived_at TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
                """
            )

    def ensure_unique_source_hash(self) -> None:
        """Enforce one active case per non-empty source SHA-256 at database level."""
        with _DB_LOCK, self._connect() as connection:
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_analyses_unique_source_sha256 "
                "ON analyses(source_sha256) "
                "WHERE source_sha256 IS NOT NULL AND source_sha256 != ''"
            )

    def save(self, result: dict) -> dict:
        normalized_hash = str(result["source"].get("sha256", "")).strip().lower()
        serialized = json.dumps(result, ensure_ascii=False)
        with _DB_LOCK, self._connect() as connection:
            existed = connection.execute(
                "SELECT 1 FROM analyses WHERE analysis_id = ?", (result["analysis_id"],)
            ).fetchone() is not None
            try:
                connection.execute(
                    """
                    INSERT INTO analyses
                    (analysis_id, created_at, file_name, status, result_json, source_sha256)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(analysis_id) DO UPDATE SET
                        created_at = excluded.created_at,
                        file_name = excluded.file_name,
                        status = excluded.status,
                        result_json = excluded.result_json,
                        source_sha256 = excluded.source_sha256
                    """,
                    (
                        result["analysis_id"], result["created_at"], result["source"]["file_name"],
                        result["status"], serialized, normalized_hash,
                    ),
                )
            except sqlite3.IntegrityError:
                # Another process may have completed the same source while this
                # process was analysing it. Return the canonical saved case.
                if normalized_hash:
                    row = connection.execute(
                        "SELECT result_json FROM analyses WHERE source_sha256 = ? LIMIT 1",
                        (normalized_hash,),
                    ).fetchone()
                    if row:
                        return json.loads(row["result_json"])
                raise
            now = datetime.now(timezone.utc).isoformat()
            connection.execute(
                "INSERT OR IGNORE INTO case_metadata (analysis_id, updated_at) VALUES (?, ?)",
                (result["analysis_id"], now),
            )
            if not existed:
                connection.execute(
                    "INSERT INTO case_events VALUES (?, ?, ?, ?, ?)",
                    (
                        f"evt_{uuid.uuid4()}", result["analysis_id"], "analysis_created", now,
                        json.dumps({"source_sha256": normalized_hash}, ensure_ascii=False),
                    ),
                )
        return result

    def get(self, analysis_id: str) -> dict | None:
        with _DB_LOCK, self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def get_by_sha256(self, source_sha256: str) -> dict | None:
        normalized = source_sha256.strip().lower()
        if not normalized:
            return None
        with _DB_LOCK, self._connect() as connection:
            row = connection.execute(
                "SELECT result_json FROM analyses WHERE source_sha256 = ? "
                "ORDER BY created_at DESC LIMIT 1",
                (normalized,),
            ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def archive_exact_duplicates(self) -> list[str]:
        """Keep the newest analysis for each source hash and safely archive older rows."""
        archived_ids: list[str] = []
        archived_at = datetime.now(timezone.utc).isoformat()
        with _DB_LOCK, self._connect() as connection:
            rows = connection.execute(
                "SELECT analysis_id, created_at, file_name, status, result_json, source_sha256 "
                "FROM analyses WHERE source_sha256 IS NOT NULL AND source_sha256 != '' "
                "ORDER BY source_sha256, created_at DESC, analysis_id DESC"
            ).fetchall()
            seen_hashes: set[str] = set()
            for row in rows:
                source_sha256 = str(row["source_sha256"]).lower()
                if source_sha256 not in seen_hashes:
                    seen_hashes.add(source_sha256)
                    continue
                connection.execute(
                    """
                    INSERT OR IGNORE INTO archived_duplicate_analyses
                    (analysis_id, created_at, file_name, status, result_json, source_sha256, archived_at, reason)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        row["analysis_id"], row["created_at"], row["file_name"], row["status"],
                        row["result_json"], source_sha256, archived_at, "exact_source_sha256_duplicate",
                    ),
                )
                connection.execute("DELETE FROM analyses WHERE analysis_id = ?", (row["analysis_id"],))
                archived_ids.append(str(row["analysis_id"]))
        return archived_ids

    def delete(self, analysis_id: str) -> bool:
        with _DB_LOCK, self._connect() as connection:
            row = connection.execute(
                "SELECT source_sha256 FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
            cursor = connection.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,))
            if row and row["source_sha256"]:
                connection.execute(
                    "DELETE FROM archived_duplicate_analyses WHERE source_sha256 = ?",
                    (str(row["source_sha256"]).lower(),),
                )
            return cursor.rowcount > 0

    def add_case_event(self, analysis_id: str, event_type: str, details: dict | None = None) -> None:
        with _DB_LOCK, self._connect() as connection:
            if not connection.execute(
                "SELECT 1 FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone():
                return
            connection.execute(
                "INSERT INTO case_events VALUES (?, ?, ?, ?, ?)",
                (
                    f"evt_{uuid.uuid4()}", analysis_id, event_type,
                    datetime.now(timezone.utc).isoformat(),
                    json.dumps(details or {}, ensure_ascii=False),
                ),
            )

    def case(self, analysis_id: str) -> dict | None:
        with _DB_LOCK, self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM case_metadata WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
            if row is None:
                return None
            events = connection.execute(
                "SELECT event_id, event_type, created_at, details_json FROM case_events "
                "WHERE analysis_id = ? ORDER BY created_at DESC LIMIT 200",
                (analysis_id,),
            ).fetchall()
        return {
            "analysis_id": analysis_id,
            "state": row["state"],
            "assigned_analyst": row["assigned_analyst"],
            "analyst_decision": row["analyst_decision"],
            "closure_reason": row["closure_reason"],
            "tags": json.loads(row["tags_json"]),
            "updated_at": row["updated_at"],
            "events": [
                {
                    "event_id": event["event_id"],
                    "event_type": event["event_type"],
                    "created_at": event["created_at"],
                    "details": json.loads(event["details_json"]),
                }
                for event in events
            ],
        }

    def update_case(self, analysis_id: str, changes: dict) -> dict:
        allowed_states = {"New", "Investigating", "Benign", "Malicious", "Closed"}
        state = str(changes.get("state", "New")).strip()
        if state not in allowed_states:
            raise ValueError("Unsupported case state")
        assigned = str(changes.get("assigned_analyst", "")).strip()[:120]
        decision = str(changes.get("analyst_decision", "")).strip()[:1000]
        closure = str(changes.get("closure_reason", "")).strip()[:1000]
        raw_tags = changes.get("tags", [])
        if not isinstance(raw_tags, list):
            raise ValueError("Case tags must be a list")
        tags = sorted({str(value).strip()[:40] for value in raw_tags if str(value).strip()})[:20]
        note = str(changes.get("note", "")).strip()[:4000]
        now = datetime.now(timezone.utc).isoformat()
        with _DB_LOCK, self._connect() as connection:
            if not connection.execute(
                "SELECT 1 FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone():
                raise KeyError("Analysis was not found")
            previous = connection.execute(
                "SELECT * FROM case_metadata WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
            connection.execute(
                """
                INSERT INTO case_metadata
                    (analysis_id, state, assigned_analyst, analyst_decision, closure_reason, tags_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    state=excluded.state,
                    assigned_analyst=excluded.assigned_analyst,
                    analyst_decision=excluded.analyst_decision,
                    closure_reason=excluded.closure_reason,
                    tags_json=excluded.tags_json,
                    updated_at=excluded.updated_at
                """,
                (analysis_id, state, assigned, decision, closure, json.dumps(tags), now),
            )
            changed = {
                "state": state,
                "assigned_analyst": assigned,
                "analyst_decision": decision,
                "closure_reason": closure,
                "tags": tags,
            }
            if previous:
                changed["previous_state"] = previous["state"]
            if note:
                changed["note"] = note
            connection.execute(
                "INSERT INTO case_events VALUES (?, ?, ?, ?, ?)",
                (f"evt_{uuid.uuid4()}", analysis_id, "case_updated", now, json.dumps(changed, ensure_ascii=False)),
            )
        case = self.case(analysis_id)
        if case is None:
            raise KeyError("Analysis was not found")
        return case

    @staticmethod
    def _cache_key(provider_id: str, indicator_type: str, indicator_value: str) -> str:
        material = f"{provider_id.lower()}\0{indicator_type.lower()}\0{indicator_value.strip().lower()}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def cache_get(self, provider_id: str, indicator_type: str, indicator_value: str) -> dict | None:
        key = self._cache_key(provider_id, indicator_type, indicator_value)
        now = datetime.now(timezone.utc).isoformat()
        with _DB_LOCK, self._connect() as connection:
            row = connection.execute(
                "SELECT verdict_json, created_at, expires_at FROM provider_cache "
                "WHERE cache_key = ? AND expires_at > ?",
                (key, now),
            ).fetchone()
        if row is None:
            return None
        result = json.loads(row["verdict_json"])
        result["cache"] = {"hit": True, "created_at": row["created_at"], "expires_at": row["expires_at"]}
        return result

    def cache_put(
        self,
        provider_id: str,
        indicator_type: str,
        indicator_value: str,
        verdict: dict,
        ttl_hours: int,
    ) -> None:
        key = self._cache_key(provider_id, indicator_type, indicator_value)
        created = datetime.now(timezone.utc)
        expires = created + timedelta(hours=max(1, min(ttl_hours, 24 * 30)))
        stored = dict(verdict)
        stored.pop("cache", None)
        # The cache key is always the privacy-filtered query value. Never retain
        # an original URL that may contain credentials, query tokens, or fragments.
        stored["value"] = indicator_value
        stored.pop("queried_value", None)
        with _DB_LOCK, self._connect() as connection:
            connection.execute(
                """
                INSERT INTO provider_cache
                    (cache_key, provider_id, indicator_type, indicator_value, verdict_json, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    verdict_json=excluded.verdict_json,
                    created_at=excluded.created_at,
                    expires_at=excluded.expires_at
                """,
                (
                    key, provider_id, indicator_type, indicator_value,
                    json.dumps(stored, ensure_ascii=False), created.isoformat(), expires.isoformat(),
                ),
            )

    def prune_provider_cache(self) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with _DB_LOCK, self._connect() as connection:
            cursor = connection.execute("DELETE FROM provider_cache WHERE expires_at <= ?", (now,))
            return cursor.rowcount

    def audit(
        self,
        event_type: str,
        *,
        provider_id: str = "",
        indicator_type: str = "",
        indicator_value: str = "",
        outcome: str = "",
        details: dict | None = None,
    ) -> None:
        digest = hashlib.sha256(indicator_value.encode("utf-8")).hexdigest()[:24] if indicator_value else ""
        safe_details = details or {}
        with _DB_LOCK, self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_log VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"aud_{uuid.uuid4()}", datetime.now(timezone.utc).isoformat(), event_type,
                    provider_id[:80], indicator_type[:40], digest, outcome[:80],
                    json.dumps(safe_details, ensure_ascii=False),
                ),
            )

    def audit_entries(self, limit: int = 200) -> list[dict]:
        safe_limit = max(1, min(int(limit), 1000))
        with _DB_LOCK, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (safe_limit,)
            ).fetchall()
        return [
            {
                "event_id": row["event_id"],
                "created_at": row["created_at"],
                "event_type": row["event_type"],
                "provider_id": row["provider_id"],
                "indicator_type": row["indicator_type"],
                "indicator_digest": row["indicator_digest"],
                "outcome": row["outcome"],
                "details": json.loads(row["details_json"]),
            }
            for row in rows
        ]

    def prune_older_than(self, days: int) -> list[str]:
        if days <= 0:
            return []
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with _DB_LOCK, self._connect() as connection:
            rows = connection.execute(
                "SELECT analysis_id FROM analyses WHERE created_at < ?", (cutoff,)
            ).fetchall()
            analysis_ids = [str(row["analysis_id"]) for row in rows]
            if analysis_ids:
                connection.executemany(
                    "DELETE FROM analyses WHERE analysis_id = ?",
                    [(analysis_id,) for analysis_id in analysis_ids],
                )
            connection.execute(
                "DELETE FROM archived_duplicate_analyses WHERE created_at < ?", (cutoff,)
            )
        return analysis_ids

    def _all_results(self) -> list[dict]:
        with _DB_LOCK, self._connect() as connection:
            rows = connection.execute("SELECT result_json FROM analyses ORDER BY created_at DESC").fetchall()
        return [json.loads(row["result_json"]) for row in rows]

    def list(self, limit: int = 100) -> list[dict]:
        results = self._all_results()[:limit]
        output: list[dict] = []
        for result in results:
            iocs = result.get("iocs", [])
            case = self.case(str(result.get("analysis_id", ""))) or {}
            output.append({
                "analysis_id": result.get("analysis_id", ""),
                "created_at": result.get("created_at", ""),
                "file_name": result.get("source", {}).get("file_name", ""),
                "status": result.get("status", ""),
                "subject": result.get("email", {}).get("subject", ""),
                "from_address": result.get("email", {}).get("from", {}).get("address", ""),
                "ioc_count": len(iocs),
                "attachment_count": len(result.get("attachments", [])),
                "sha256": result.get("source", {}).get("sha256", ""),
                "case_state": case.get("state", "New"),
                "tags": case.get("tags", []),
                "case_updated_at": case.get("updated_at", result.get("created_at", "")),
            })
        return output

    def stats(self) -> dict:
        results = self._all_results()
        unique_iocs: set[tuple[str, str]] = set()
        total_attachments = 0
        with_errors = 0
        for result in results:
            total_attachments += len(result.get("attachments", []))
            for ioc in result.get("iocs", []):
                unique_iocs.add((ioc.get("type", ""), ioc.get("normalized_value", "")))
            if any(report.get("status") == "error" for report in result.get("tool_reports", [])):
                with_errors += 1
        return {
            "analysis_count": len(results),
            "unique_ioc_count": len(unique_iocs),
            "attachment_count": total_attachments,
            "flagged_count": with_errors,
            "recent": self.list(5),
        }

    def iocs(self) -> list[dict]:
        rows: dict[tuple[str, str], dict] = {}
        for result in self._all_results():
            analysis_id = result.get("analysis_id", "")
            file_name = result.get("source", {}).get("file_name", "")
            created_at = result.get("created_at", "")
            for ioc in result.get("iocs", []):
                key = (ioc.get("type", ""), ioc.get("normalized_value", ""))
                if key not in rows:
                    rows[key] = {
                        **ioc,
                        "occurrences": 0,
                        "analyses": [],
                        "last_seen": created_at,
                    }
                rows[key]["occurrences"] += 1
                rows[key]["analyses"].append({"analysis_id": analysis_id, "file_name": file_name})
                if created_at > rows[key]["last_seen"]:
                    rows[key]["last_seen"] = created_at
        return sorted(rows.values(), key=lambda x: (x["type"], x["normalized_value"]))
