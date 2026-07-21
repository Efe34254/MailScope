from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import uuid
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


BACKUP_FORMAT = "mailscope-backup-v1"
MAX_BACKUP_BYTES = 2 * 1024 * 1024 * 1024
MAX_BACKUP_FILES = 10_000
MAX_BACKUP_RATIO = 500


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validated_output(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if resolved.suffix.lower() != ".msbackup":
        resolved = resolved.with_suffix(".msbackup")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def create_backup(base_dir: Path, output_path: Path) -> dict[str, Any]:
    base_dir = base_dir.resolve()
    output = _validated_output(output_path)
    database_path = base_dir / "mailscope.db"
    if not database_path.is_file():
        raise FileNotFoundError("MailScope database was not found")
    backup_root = base_dir / "backups"
    backup_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="backup-staging-", dir=backup_root) as temporary:
        staging = Path(temporary)
        database_copy = staging / "mailscope.db"
        with closing(sqlite3.connect(database_path)) as source, closing(sqlite3.connect(database_copy)) as destination:
            source.backup(destination)
            check = destination.execute("PRAGMA quick_check").fetchone()
            if not check or check[0] != "ok":
                raise ValueError("Database backup failed its integrity check")

        files: list[tuple[Path, str]] = [(database_copy, "mailscope.db")]
        settings = base_dir / "settings.json"
        if settings.is_file():
            files.append((settings, "settings.json"))
        workspace = base_dir / "workspace"
        if workspace.is_dir():
            for path in sorted(workspace.rglob("*")):
                if path.is_file():
                    files.append((path, (Path("workspace") / path.relative_to(workspace)).as_posix()))

        manifest = {
            "format": BACKUP_FORMAT,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "files": {archive_name: _sha256(path) for path, archive_name in files},
        }
        temporary_output = output.with_suffix(output.suffix + ".tmp")
        try:
            with zipfile.ZipFile(temporary_output, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                for path, archive_name in files:
                    archive.write(path, archive_name)
                archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
            os.replace(temporary_output, output)
        finally:
            if temporary_output.exists():
                temporary_output.unlink()
    return {
        "created": True,
        "path": str(output),
        "size": output.stat().st_size,
        "sha256": _sha256(output),
        "file_count": len(files),
        "format": BACKUP_FORMAT,
    }


def _validate_member(info: zipfile.ZipInfo) -> None:
    path = PurePosixPath(info.filename)
    if path.is_absolute() or ".." in path.parts or "\\" in info.filename:
        raise ValueError(f"Unsafe backup path: {info.filename}")
    ratio = info.file_size / max(info.compress_size, 1)
    if ratio > MAX_BACKUP_RATIO:
        raise ValueError(f"Unsafe backup compression ratio: {info.filename}")


def restore_backup(base_dir: Path, backup_path: Path) -> dict[str, Any]:
    base_dir = base_dir.resolve()
    backup = backup_path.expanduser().resolve()
    if not backup.is_file() or backup.stat().st_size > MAX_BACKUP_BYTES:
        raise ValueError("Backup file is missing or exceeds the safety limit")
    backup_root = base_dir / "backups"
    backup_root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    automatic_backup = backup_root / f"automatic-before-restore-{timestamp}.msbackup"
    create_backup(base_dir, automatic_backup)

    with tempfile.TemporaryDirectory(prefix="restore-staging-", dir=backup_root) as temporary:
        staging = Path(temporary)
        with zipfile.ZipFile(backup) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_BACKUP_FILES:
                raise ValueError("Backup contains too many files")
            total_size = 0
            for info in infos:
                _validate_member(info)
                total_size += info.file_size
                if total_size > MAX_BACKUP_BYTES:
                    raise ValueError("Expanded backup exceeds the safety limit")
            try:
                manifest = json.loads(archive.read("manifest.json"))
            except Exception as exc:
                raise ValueError("Backup manifest is missing or invalid") from exc
            if manifest.get("format") != BACKUP_FORMAT or "mailscope.db" not in manifest.get("files", {}):
                raise ValueError("Unsupported MailScope backup format")
            archive.extractall(staging)

        for relative, expected in manifest["files"].items():
            path = (staging / relative).resolve()
            if staging.resolve() not in path.parents or not path.is_file():
                raise ValueError(f"Backup file is missing: {relative}")
            if _sha256(path) != str(expected).lower():
                raise ValueError(f"Backup integrity check failed: {relative}")

        restored_database = staging / "mailscope.db"
        with closing(sqlite3.connect(restored_database)) as connection:
            check = connection.execute("PRAGMA quick_check").fetchone()
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not check or check[0] != "ok" or "analyses" not in tables:
                raise ValueError("Restored database failed validation")

        restored_settings = staging / "settings.json"
        if restored_settings.is_file():
            json.loads(restored_settings.read_text(encoding="utf-8"))
        os.replace(restored_database, base_dir / "mailscope.db")
        for suffix in ("-wal", "-shm"):
            sidecar = base_dir / f"mailscope.db{suffix}"
            if sidecar.exists():
                sidecar.unlink()
        if restored_settings.is_file():
            os.replace(restored_settings, base_dir / "settings.json")
        restored_workspace = staging / "workspace"
        if restored_workspace.is_dir():
            current_workspace = base_dir / "workspace"
            retired_workspace = base_dir / f"workspace-before-restore-{uuid.uuid4().hex}"
            if current_workspace.exists():
                os.replace(current_workspace, retired_workspace)
            try:
                os.replace(restored_workspace, current_workspace)
            except Exception:
                if retired_workspace.exists():
                    os.replace(retired_workspace, current_workspace)
                raise
            if retired_workspace.exists():
                shutil.rmtree(retired_workspace)

    return {
        "restored": True,
        "source": str(backup),
        "automatic_backup": str(automatic_backup),
        "format": BACKUP_FORMAT,
    }
