from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SAFE_LOGICAL_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _root(base_dir: Path) -> Path:
    root = base_dir / "yara_rules"
    (root / "versions").mkdir(parents=True, exist_ok=True)
    return root


def _manifest_path(base_dir: Path) -> Path:
    return _root(base_dir) / "manifest.json"


def _load(base_dir: Path) -> dict[str, Any]:
    path = _manifest_path(base_dir)
    if not path.is_file():
        return {"format": "mailscope-custom-yara-v1", "rules": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and isinstance(data.get("rules"), dict) else {"format": "mailscope-custom-yara-v1", "rules": {}}
    except Exception:
        return {"format": "mailscope-custom-yara-v1", "rules": {}}


def _save(base_dir: Path, manifest: dict[str, Any]) -> None:
    path = _manifest_path(base_dir)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def import_rule(base_dir: Path, source_path: Path) -> dict[str, Any]:
    import yara

    source = source_path.expanduser().resolve()
    if not source.is_file() or source.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("YARA rule file is missing or exceeds 2 MiB")
    yara.compile(filepath=str(source))
    content = source.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    logical_name = SAFE_LOGICAL_NAME.sub("_", source.stem).strip("._-")[:80] or "custom_rule"
    destination_name = f"{logical_name}-{digest[:16]}.yar"
    destination = _root(base_dir) / "versions" / destination_name
    if not destination.exists():
        shutil.copy2(source, destination)
    manifest = _load(base_dir)
    entry = manifest["rules"].setdefault(logical_name, {"active": "", "versions": []})
    if not any(item.get("sha256") == digest for item in entry["versions"]):
        entry["versions"].append({
            "sha256": digest,
            "file": destination_name,
            "imported_at": datetime.now(timezone.utc).isoformat(),
        })
    entry["active"] = digest
    _save(base_dir, manifest)
    return status(base_dir)


def set_active(base_dir: Path, logical_name: str, digest: str | None) -> dict[str, Any]:
    manifest = _load(base_dir)
    entry = manifest.get("rules", {}).get(logical_name)
    if not isinstance(entry, dict):
        raise KeyError("Custom YARA rule was not found")
    if digest and not any(item.get("sha256") == digest for item in entry.get("versions", [])):
        raise KeyError("Requested YARA rule version was not found")
    entry["active"] = digest or ""
    _save(base_dir, manifest)
    return status(base_dir)


def active_files(base_dir: Path) -> list[Path]:
    manifest = _load(base_dir)
    files: list[Path] = []
    versions_root = (_root(base_dir) / "versions").resolve()
    for entry in manifest.get("rules", {}).values():
        active = str(entry.get("active", ""))
        version = next((item for item in entry.get("versions", []) if item.get("sha256") == active), None)
        if not version:
            continue
        path = (versions_root / str(version.get("file", ""))).resolve()
        if versions_root in path.parents and path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == active:
            files.append(path)
    return files


def status(base_dir: Path) -> dict[str, Any]:
    manifest = _load(base_dir)
    output = []
    for logical_name, entry in sorted(manifest.get("rules", {}).items()):
        output.append({
            "name": logical_name,
            "active": entry.get("active", ""),
            "enabled": bool(entry.get("active")),
            "versions": list(entry.get("versions", [])),
        })
    return {"format": manifest.get("format", "mailscope-custom-yara-v1"), "custom_rules": output}


def bundled_status(rules_root: Path) -> dict[str, Any]:
    """Describe and integrity-check the immutable rule pack shipped with MailScope."""
    manifest_path = rules_root / "manifest.json"
    yara_root = rules_root / "yara"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = manifest.get("rules", {})
        actual_files = {path.name: path for path in yara_root.glob("*.yar")}
        if set(expected) != set(actual_files):
            raise ValueError("manifest file set does not match bundled rules")
        for name, digest in expected.items():
            actual = hashlib.sha256(actual_files[name].read_bytes()).hexdigest()
            if actual.lower() != str(digest).lower():
                raise ValueError(f"integrity mismatch: {name}")
        return {
            "ruleset_version": str(manifest.get("ruleset_version", "unknown")),
            "rule_files": len(actual_files),
            "integrity": "verified",
        }
    except Exception as exc:
        return {"ruleset_version": "unknown", "rule_files": 0, "integrity": "failed", "error": str(exc)}
