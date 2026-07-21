from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any


CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
MAX_TOOL_OUTPUT_BYTES = 8 * 1024 * 1024
TOOL_EXECUTABLES = {
    "capa": Path("capa/capa.exe"),
    "floss": Path("floss/floss.exe"),
    "exiftool": Path("exiftool/exiftool.exe"),
}


def _resource_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parents[1]


def _tool_root() -> Path:
    return _resource_root() / "tools"


def _rule_root() -> Path:
    return _resource_root() / "rules" / "yara"


@lru_cache(maxsize=1)
def _tool_manifest() -> dict[str, Any]:
    manifest_path = _tool_root() / "manifest.json"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


@lru_cache(maxsize=None)
def resolve_tool(name: str) -> tuple[Path | None, str]:
    """Resolve a verified bundled executable without trusting the process PATH."""
    relative = TOOL_EXECUTABLES.get(name)
    if relative is None:
        return None, f"Unknown local tool: {name}"

    candidate = (_tool_root() / relative).resolve()
    tool_root = _tool_root().resolve()
    if tool_root not in candidate.parents or not candidate.is_file():
        return None, f"Bundled {name} executable is missing"

    if name == "exiftool" and not (candidate.parent / "exiftool_files").is_dir():
        return None, "Bundled ExifTool support directory is missing"

    manifest = _tool_manifest().get("tools", {}).get(name, {})
    expected = str(manifest.get("executable_sha256", "")).upper()
    if not expected:
        return None, f"Bundled {name} hash is not declared"
    actual = _sha256(candidate)
    if actual != expected:
        return None, f"Bundled {name} failed its SHA-256 integrity check"
    return candidate, "bundled"


def _safe_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in ("PYTHONHOME", "PYTHONPATH", "PERL5LIB", "PERLLIB"):
        environment.pop(key, None)
    environment["NO_COLOR"] = "1"
    environment["TERM"] = "dumb"
    return environment


def _read_limited(stream: Any) -> tuple[str, bool]:
    size = stream.tell()
    stream.seek(0)
    raw = stream.read(MAX_TOOL_OUTPUT_BYTES)
    truncated = size > MAX_TOOL_OUTPUT_BYTES
    text = raw.decode("utf-8", errors="replace")
    if truncated:
        text += "\n[MailScope: tool output truncated at 8 MiB]"
    return text.strip(), truncated


def _run(cmd: list[str], timeout: int = 30, cwd: Path | None = None) -> dict[str, Any]:
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=timeout,
                creationflags=CREATE_NO_WINDOW,
                cwd=str(cwd) if cwd else None,
                env=_safe_environment(),
                shell=False,
                check=False,
            )
            stdout, stdout_truncated = _read_limited(stdout_file)
            stderr, stderr_truncated = _read_limited(stderr_file)
        return {
            "success": process.returncode == 0,
            "return_code": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "output_truncated": stdout_truncated or stderr_truncated,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "return_code": None,
            "stdout": "",
            "stderr": f"Tool exceeded the {timeout}-second analysis limit",
            "output_truncated": False,
            "timed_out": True,
        }
    except Exception as exc:
        return {
            "success": False,
            "return_code": None,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "output_truncated": False,
        }


@lru_cache(maxsize=1)
def _compiled_yara_rules():
    import re
    import yara

    files = sorted(_rule_root().glob("*.yar"))
    if not files:
        raise FileNotFoundError("Bundled YARA rule files are missing")
    manifest_path = _rule_root().parent / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected_rules = manifest.get("rules", {})
    if set(expected_rules) != {rule_file.name for rule_file in files}:
        raise ValueError("Bundled YARA manifest does not match the rule files")
    for rule_file in files:
        actual = hashlib.sha256(rule_file.read_bytes()).hexdigest().upper()
        if actual != str(expected_rules.get(rule_file.name, "")).upper():
            raise ValueError(f"Bundled YARA rule integrity check failed: {rule_file.name}")
    namespaces = {rule_file.stem: str(rule_file) for rule_file in files}
    rule_count = 0
    for rule_file in files:
        source = rule_file.read_text(encoding="utf-8")
        rule_count += len(re.findall(r"(?m)^\s*(?:private\s+|global\s+)?rule\s+[A-Za-z_][A-Za-z0-9_]*", source))
    return yara.compile(filepaths=namespaces), rule_count, [rule_file.name for rule_file in files], str(manifest.get("ruleset_version", "unknown"))


def yara_scan(path: Path) -> dict[str, Any]:
    try:
        rules, rule_count, rule_files, ruleset_version = _compiled_yara_rules()
        matches = []
        for match in rules.match(str(path), timeout=15):
            matches.append({
                "rule": match.rule,
                "namespace": match.namespace,
                "tags": list(match.tags),
                "severity": str(match.meta.get("severity", "medium")).lower(),
                "category": str(match.meta.get("category", "detection")),
                "description": str(match.meta.get("description", "YARA rule matched")),
            })
        custom_files: list[Path] = []
        base_value = os.environ.get("MAILSCOPE_DATA_DIR", "").strip()
        if base_value:
            from .yara_manager import active_files

            custom_files = active_files(Path(base_value))
            if custom_files:
                custom_rules = __import__("yara").compile(filepaths={f"custom_{index}": str(value) for index, value in enumerate(custom_files)})
                for match in custom_rules.match(str(path), timeout=15):
                    matches.append({
                        "rule": match.rule,
                        "namespace": match.namespace,
                        "tags": list(match.tags),
                        "severity": str(match.meta.get("severity", "medium")).lower(),
                        "category": str(match.meta.get("category", "custom_detection")),
                        "description": str(match.meta.get("description", "Custom YARA rule matched")),
                    })
        return {"available": True, "matches": matches, "metrics": {"rules_loaded": rule_count, "rule_files": len(rule_files), "custom_rule_files": len(custom_files), "matches": len(matches), "ruleset_version": ruleset_version}, "rule_files": rule_files}
    except Exception as exc:
        return {"available": False, "error": str(exc), "matches": [], "metrics": {"rules_loaded": 0, "rule_files": 0, "matches": 0}}


def pdf_scan(path: Path) -> dict[str, Any]:
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path), strict=False)
        raw = path.read_bytes()
        return {
            "available": True,
            "pages": len(reader.pages),
            "encrypted": bool(reader.is_encrypted),
            "javascript": b"/JavaScript" in raw or b"/JS" in raw,
            "open_action": b"/OpenAction" in raw,
            "launch": b"/Launch" in raw,
            "embedded_files": b"/EmbeddedFile" in raw,
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def office_scan(path: Path) -> dict[str, Any]:
    try:
        from oletools.olevba import VBA_Parser

        parser = VBA_Parser(str(path))
        has_macros = parser.detect_vba_macros()
        macros = []
        if has_macros:
            for _, stream, name, code in parser.extract_macros():
                macros.append({"name": name or stream, "size": len(code or "")})
        parser.close()
        return {
            "available": True,
            "has_macros": bool(has_macros),
            "macro_count": len(macros),
            "macros": macros[:30],
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def pe_scan(path: Path) -> dict[str, Any]:
    try:
        import pefile

        pe = pefile.PE(str(path), fast_load=False)
        imports = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:30]:
                imports.append((entry.dll or b"").decode(errors="replace"))
        sections = [
            {
                "name": section.Name.rstrip(b"\x00").decode(errors="replace"),
                "entropy": round(section.get_entropy(), 3),
                "size": section.SizeOfRawData,
            }
            for section in pe.sections
        ]
        return {
            "available": True,
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "sections": sections,
            "imports": imports,
            "signed": hasattr(pe, "DIRECTORY_ENTRY_SECURITY"),
        }
    except Exception as exc:
        return {"available": False, "error": str(exc)}


def _string_value(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("string", ""))
    return str(value)


def _summarize_json(name: str, output: str) -> tuple[dict[str, Any], list[str]]:
    try:
        data = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        return {}, []

    if name == "capa" and isinstance(data, dict):
        rules = data.get("rules", {})
        names = sorted(str(value) for value in rules) if isinstance(rules, dict) else []
        return {"capability_count": len(names)}, [f"Capability: {value}" for value in names[:30]]

    if name == "floss" and isinstance(data, dict):
        strings = data.get("strings", {})
        if not isinstance(strings, dict):
            return {}, []
        keys = ("decoded_strings", "stack_strings", "tight_strings", "language_strings", "static_strings")
        metrics = {key: len(strings.get(key, [])) for key in keys if isinstance(strings.get(key, []), list)}
        details = []
        for key in ("decoded_strings", "stack_strings", "tight_strings", "language_strings"):
            for item in strings.get(key, [])[:8]:
                value = _string_value(item).replace("\r", " ").replace("\n", " ").strip()
                if value:
                    details.append(f"{key}: {value[:240]}")
        if not details:
            details.append(f"Static strings extracted: {metrics.get('static_strings', 0)}")
        return metrics, details[:30]

    if name == "exiftool" and isinstance(data, list) and data and isinstance(data[0], dict):
        metadata = data[0]
        preferred = (
            "FileType", "MIMEType", "FileSize", "MachineType", "PEType", "CompanyName",
            "ProductName", "ProductVersion", "OriginalFileName", "Author", "Creator", "Producer",
        )
        details = [f"{key}: {metadata[key]}" for key in preferred if metadata.get(key) not in (None, "")]
        return {"metadata_fields": len(metadata)}, details[:30]

    return {}, []


def external_tool(name: str, path: Path, args: list[str], timeout: int) -> dict[str, Any]:
    executable, source = resolve_tool(name)
    if executable is None:
        return {"available": False, "error": source}

    run = _run([str(executable), *args, str(path.resolve())], timeout=timeout, cwd=executable.parent)
    metrics, details = _summarize_json(name, run.get("stdout", ""))
    result = {
        "available": True,
        "success": bool(run.get("success")),
        "source": source,
        "return_code": run.get("return_code"),
        "output_truncated": bool(run.get("output_truncated")),
        "metrics": metrics,
        "details": details,
    }
    if not result["success"]:
        result["error"] = run.get("stderr") or "Tool returned a non-zero exit code"
    return result


def tools_status(run_versions: bool = True) -> dict[str, dict[str, Any]]:
    manifest_tools = _tool_manifest().get("tools", {})
    results: dict[str, dict[str, Any]] = {}
    version_args = {"capa": ["--version"], "floss": ["--version"], "exiftool": ["-ver"]}
    for name in TOOL_EXECUTABLES:
        executable, source = resolve_tool(name)
        entry = manifest_tools.get(name, {})
        result = {
            "available": executable is not None,
            "version": str(entry.get("version", "")),
            "source": source,
            "integrity": "verified" if executable is not None else "failed",
        }
        if executable is not None and run_versions:
            run = _run([str(executable), *version_args[name]], timeout=20, cwd=executable.parent)
            result["self_test"] = "passed" if run.get("success") else "failed"
            if not run.get("success"):
                result["error"] = run.get("stderr") or "Version self-test failed"
        results[name] = result
    return results


def scan_attachment_direct(path: Path, detected_type: str) -> dict[str, dict[str, Any]]:
    result = {"yara": yara_scan(path)}
    lower = path.suffix.lower()
    if detected_type == "PDF document" or lower == ".pdf":
        result["pdf_analyzer"] = pdf_scan(path)
    if detected_type in {"ZIP/Office archive", "OLE compound document"} or lower in {
        ".doc", ".docm", ".docx", ".xls", ".xlsm", ".xlsx", ".ppt", ".pptm", ".pptx",
    }:
        result["office_analyzer"] = office_scan(path)
    if detected_type == "PE executable" or lower in {".exe", ".dll", ".sys", ".scr"}:
        result["pe_analyzer"] = pe_scan(path)
        result["capa"] = external_tool("capa", path, ["--json"], timeout=180)
        result["floss"] = external_tool("floss", path, ["--json"], timeout=180)
    result["exiftool"] = external_tool("exiftool", path, ["-j"], timeout=60)
    return result


def scan_attachment(path: Path, detected_type: str) -> dict[str, dict[str, Any]]:
    """Analyze an attachment outside the main engine process.

    In a frozen build the engine invokes its private static-worker command. In
    development it invokes the same worker as a Python module. The worker and
    every external child are contained by a Windows Job Object where the OS
    permits nested jobs.
    """
    from .process_isolation import run_contained_json_worker

    if getattr(sys, "frozen", False):
        command = [sys.executable, "static-worker", str(path.resolve()), detected_type]
    else:
        command = [sys.executable, "-m", "app.static_worker", str(path.resolve()), detected_type]
    run = run_contained_json_worker(command, timeout_seconds=240, memory_limit_mb=768, cwd=_resource_root())
    isolation = run.get("isolation", {})
    if not run.get("success"):
        status = "timed_out" if run.get("timed_out") else "worker_failed"
        return {
            "worker_isolation": {
                "available": True,
                "success": False,
                "error": run.get("stderr") or "Static analysis worker failed",
                "status": status,
                "metrics": isolation,
            }
        }
    try:
        parsed = json.loads(str(run.get("stdout", "")))
        if not isinstance(parsed, dict):
            raise TypeError("Worker result is not an object")
    except Exception as exc:
        return {
            "worker_isolation": {
                "available": True,
                "success": False,
                "error": f"Worker returned invalid JSON: {exc}",
                "status": "worker_failed",
                "metrics": isolation,
            }
        }
    parsed["worker_isolation"] = {
        "available": True,
        "success": True,
        "status": "contained",
        "metrics": isolation,
        "details": [
            "Attachment parsers ran in a separate worker process.",
            "No worker code path performs network requests; OS firewall isolation requires administrator policy.",
        ],
    }
    return parsed
