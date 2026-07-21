from __future__ import annotations

import gzip
import hashlib
import math
import re
import uuid
import zipfile
from collections import Counter, deque
from pathlib import Path
from typing import Any


MAX_RECURSION_DEPTH = 3
MAX_EXTRACTED_FILES = 50
MAX_EXTRACTED_TOTAL_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_FILE_BYTES = 20 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._ -]+")
OFFICE_EXTENSIONS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
OFFICE_INTERESTING_PARTS = (
    "/embeddings/", "/activex/", "vbaproject.bin", "customui/", "oleobject",
)
DANGEROUS_EXTENSIONS = {".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".scr", ".hta", ".lnk", ".iso", ".img"}


def _safe_name(value: str, fallback: str) -> str:
    name = SAFE_NAME_RE.sub("_", Path(value.replace("\\", "/")).name).strip(" .")[:180]
    return name or fallback


def _file_type(data: bytes) -> str:
    signatures = [
        (b"MZ", "PE executable"), (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP/Office archive"), (b"\xD0\xCF\x11\xE0", "OLE compound document"),
        (b"\x7fELF", "ELF executable"), (b"Rar!", "RAR archive"),
        (b"\x1f\x8b", "GZIP archive"), (b"7z\xbc\xaf'\x1c", "7-Zip archive"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"), (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"),
    ]
    for signature, name in signatures:
        if data.startswith(signature):
            return name
    return "text/script" if data[:512].decode("utf-8", errors="ignore").strip() else "unknown"


def _hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),  # nosec - evidence identifier, not cryptographic trust
        "sha1": hashlib.sha1(data).hexdigest(),  # nosec - evidence identifier, not cryptographic trust
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return round(-sum((count / size) * math.log2(count / size) for count in counts.values()), 3)


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def _office_member_is_interesting(name: str) -> bool:
    normalized = "/" + name.replace("\\", "/").lower().lstrip("/")
    return any(marker in normalized for marker in OFFICE_INTERESTING_PARTS)


def _artifact(data: bytes, name: str, parent: dict[str, Any], output_dir: Path, index: int) -> dict[str, Any]:
    safe = _safe_name(name, f"embedded-{index}.bin")
    destination = output_dir / f"embedded-{index:03d}-{safe}"
    destination.write_bytes(data)
    detected = _file_type(data)
    extension = Path(safe).suffix.lower()
    flags: list[str] = []
    if detected == "PE executable" and extension not in {".exe", ".dll", ".scr", ".sys"}:
        flags.append("Embedded executable content does not match the file extension")
    if extension in DANGEROUS_EXTENSIONS:
        flags.append("Potentially dangerous embedded attachment extension")
    return {
        "attachment_id": f"att_{uuid.uuid4()}",
        "file_name": name,
        "sanitized_file_name": safe,
        "declared_content_type": "application/octet-stream",
        "detected_type": detected,
        "size": len(data),
        "entropy": _entropy(data),
        "hashes": _hashes(data),
        "stored_path": str(destination),
        "static_flags": flags,
        "analysis_status": "analyzed",
        "parent_attachment_id": parent["attachment_id"],
        "depth": int(parent.get("depth", 0)) + 1,
        "is_embedded": True,
        "extracted_from": parent.get("file_name", ""),
        "extraction_notes": [],
    }


def expand_nested_attachments(roots: list[dict[str, Any]], output_dir: Path) -> dict[str, Any]:
    """Safely extract supported embedded objects without executing their content."""
    output_dir.mkdir(parents=True, exist_ok=True)
    queue: deque[dict[str, Any]] = deque(roots)
    artifacts: list[dict[str, Any]] = []
    updates: dict[str, dict[str, Any]] = {}
    details: list[str] = []
    total_bytes = 0
    blocked = 0
    encrypted = 0
    unsupported = 0

    def note(parent: dict[str, Any], status: str, message: str) -> None:
        entry = updates.setdefault(parent["attachment_id"], {"analysis_status": "analyzed", "extraction_notes": []})
        if status != "analyzed":
            entry["analysis_status"] = status
        entry["extraction_notes"].append(message)
        details.append(f"{parent.get('file_name', 'attachment')}: {message}")

    def store(data: bytes, name: str, parent: dict[str, Any]) -> dict[str, Any] | None:
        nonlocal total_bytes, blocked
        if len(artifacts) >= MAX_EXTRACTED_FILES:
            blocked += 1
            note(parent, "blocked_by_safety_limit", f"embedded file count exceeded {MAX_EXTRACTED_FILES}")
            return None
        if len(data) > MAX_EXTRACTED_FILE_BYTES:
            blocked += 1
            note(parent, "blocked_by_safety_limit", f"embedded file exceeded {MAX_EXTRACTED_FILE_BYTES // (1024 * 1024)} MiB")
            return None
        if total_bytes + len(data) > MAX_EXTRACTED_TOTAL_BYTES:
            blocked += 1
            note(parent, "blocked_by_safety_limit", f"expanded content exceeded {MAX_EXTRACTED_TOTAL_BYTES // (1024 * 1024)} MiB")
            return None
        artifact = _artifact(data, name, parent, output_dir, len(artifacts) + 1)
        artifacts.append(artifact)
        total_bytes += len(data)
        details.append(f"Extracted {name} from {parent.get('file_name', 'attachment')} at depth {artifact['depth']}")
        queue.append(artifact)
        return artifact

    while queue:
        parent = queue.popleft()
        path = Path(str(parent.get("stored_path", "")))
        if not path.is_file():
            note(parent, "tool_failed", "stored attachment was unavailable for container inspection")
            continue
        depth = int(parent.get("depth", 0))
        detected = str(parent.get("detected_type", ""))
        extension = path.suffix.lower()
        is_container = detected in {
            "PDF document", "ZIP/Office archive", "OLE compound document", "GZIP archive",
            "RAR archive", "7-Zip archive",
        }
        if is_container and depth >= MAX_RECURSION_DEPTH:
            blocked += 1
            note(parent, "blocked_by_safety_limit", f"container recursion exceeded depth {MAX_RECURSION_DEPTH}")
            continue

        try:
            if detected == "PDF document" or extension == ".pdf":
                from pypdf import PdfReader

                reader = PdfReader(str(path), strict=False)
                if reader.is_encrypted and not reader.decrypt(""):
                    encrypted += 1
                    note(parent, "encrypted", "encrypted PDF could not be opened with an empty password")
                    continue
                for name, values in reader.attachments.items():
                    for position, data in enumerate(values, 1):
                        child_name = name if len(values) == 1 else f"{position}-{name}"
                        store(bytes(data), child_name, parent)

            elif detected == "ZIP/Office archive" or zipfile.is_zipfile(path):
                office_package = extension in OFFICE_EXTENSIONS
                with zipfile.ZipFile(path) as archive:
                    for info in archive.infolist():
                        if info.is_dir() or _is_zip_symlink(info):
                            continue
                        if office_package and not _office_member_is_interesting(info.filename):
                            continue
                        if info.flag_bits & 0x1:
                            encrypted += 1
                            note(parent, "encrypted", f"encrypted archive member was not extracted: {info.filename}")
                            continue
                        ratio = info.file_size / max(info.compress_size, 1)
                        if ratio > MAX_COMPRESSION_RATIO:
                            blocked += 1
                            note(parent, "blocked_by_safety_limit", f"compression ratio {ratio:.1f}:1 blocked for {info.filename}")
                            continue
                        if info.file_size > MAX_EXTRACTED_FILE_BYTES:
                            blocked += 1
                            note(parent, "blocked_by_safety_limit", f"oversized archive member blocked: {info.filename}")
                            continue
                        store(archive.read(info), info.filename, parent)

            elif detected == "OLE compound document":
                from oletools.oleobj import OleNativeStream, find_ole

                found = False
                for ole in find_ole(str(path), None):
                    if ole is None:
                        continue
                    try:
                        for stream_path in ole.listdir():
                            if not stream_path or stream_path[-1] != "\x01Ole10Native":
                                continue
                            native = OleNativeStream(ole.openstream(stream_path).read())
                            if native.is_link or native.data is None:
                                continue
                            data = native.data.read() if hasattr(native.data, "read") else bytes(native.data)
                            store(data, str(native.filename or "embedded-ole.bin"), parent)
                            found = True
                    finally:
                        ole.close()
                if not found:
                    note(parent, "analyzed", "no extractable Ole10Native embedded objects were found")

            elif detected == "GZIP archive" or extension == ".gz":
                with gzip.open(path, "rb") as stream:
                    data = stream.read(MAX_EXTRACTED_FILE_BYTES + 1)
                name = path.stem or "gzip-content.bin"
                store(data, name, parent)

            elif detected in {"RAR archive", "7-Zip archive"}:
                unsupported += 1
                note(parent, "partially_analyzed", f"{detected} extraction is not supported; metadata and YARA checks still ran")
        except (zipfile.BadZipFile, EOFError, ValueError, OSError) as exc:
            note(parent, "tool_failed", f"container parser failed safely: {type(exc).__name__}: {exc}")
        except Exception as exc:
            note(parent, "tool_failed", f"container parser returned an error: {type(exc).__name__}: {exc}")

    return {
        "artifacts": artifacts,
        "updates": updates,
        "metrics": {
            "root_attachments": len(roots),
            "embedded_files": len(artifacts),
            "expanded_bytes": total_bytes,
            "encrypted_items": encrypted,
            "blocked_items": blocked,
            "unsupported_containers": unsupported,
            "max_depth": MAX_RECURSION_DEPTH,
            "max_files": MAX_EXTRACTED_FILES,
            "max_expanded_bytes": MAX_EXTRACTED_TOTAL_BYTES,
        },
        "details": details[:50],
    }
