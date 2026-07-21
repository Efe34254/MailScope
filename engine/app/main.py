from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from app.analyzer import analyze_eml
from app.backup_manager import create_backup, restore_backup
from app.database import AnalysisDatabase
from app.online_intel import enrich, load_settings, save_settings
from app.reporting import build_html_report
from app.static_tools import tools_status

ENGINE_VERSION = "1.1.0"
MAX_EMAIL_SIZE = 100 * 1024 * 1024


def _remove_analysis_workspace(workspace: Path, analysis_id: str) -> None:
    workspace_root = workspace.resolve()
    target = (workspace_root / analysis_id).resolve()
    if target.parent == workspace_root and target.is_dir():
        shutil.rmtree(target)


def _apply_retention(base_dir: Path, workspace: Path, database: AnalysisDatabase) -> None:
    days = int(load_settings(base_dir).get("history_retention_days", 0) or 0)
    for analysis_id in database.prune_older_than(days):
        _remove_analysis_workspace(workspace, analysis_id)


def data_paths() -> tuple[Path, Path, AnalysisDatabase]:
    base_dir = Path(os.environ.get("MAILSCOPE_DATA_DIR", Path.home() / ".mailscope"))
    workspace = base_dir / "workspace"
    database = AnalysisDatabase(base_dir / "mailscope.db")
    for analysis_id in database.archive_exact_duplicates():
        _remove_analysis_workspace(workspace, analysis_id)
    database.ensure_unique_source_hash()
    _apply_retention(base_dir, workspace, database)
    return base_dir, workspace, database


def _write_utf8(stream_name: str, text: str) -> None:
    """Write protocol/log text as UTF-8 regardless of the Windows code page.

    PyInstaller GUI executables launched with redirected pipes can inherit a
    legacy Windows encoding (for example cp1252). Writing bytes directly keeps
    the IPC protocol Unicode-safe for every RFC 5322/MIME message.
    """
    stream = getattr(sys, stream_name)
    data = text.encode("utf-8", errors="replace")
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        buffer.write(data)
        buffer.flush()
        return
    # Fallback for test doubles and unusual embedded interpreters.
    stream.write(data.decode("utf-8"))
    stream.flush()


def emit(payload: object) -> None:
    _write_utf8("stdout", json.dumps(payload, ensure_ascii=False))


def fail(message: str, code: int = 1) -> int:
    _write_utf8("stderr", message.strip() + "\n")
    return code


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def analyze(file_path: str) -> int:
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        return fail("Email file was not found.", 2)
    if path.suffix.lower() != ".eml":
        return fail("This version supports only .eml files.", 3)
    if path.stat().st_size > MAX_EMAIL_SIZE:
        return fail("Email file exceeds the 100 MB limit.", 4)

    base_dir, workspace, database = data_paths()
    try:
        source_sha256 = _file_sha256(path)
        existing = database.get_by_sha256(source_sha256)
        if existing is not None:
            database.add_case_event(
                str(existing.get("analysis_id", "")),
                "duplicate_opened",
                {"submitted_file_name": path.name, "source_sha256": source_sha256},
            )
            payload = dict(existing)
            payload["case"] = database.case(str(existing.get("analysis_id", "")))
            payload["duplicate"] = True
            payload["duplicate_message"] = (
                "This exact email was analyzed previously. The saved result was opened "
                "and no duplicate analysis was created."
            )
            emit(payload)
            return 0

        settings = load_settings(base_dir)
        result = analyze_eml(
            path,
            workspace,
            revalidate_auth=bool(settings.get("online_intelligence") and settings.get("verify_email_authentication")),
            trusted_authserv_ids=list(settings.get("trusted_authserv_ids", [])),
        )
        payload = result.model_dump(by_alias=True)
        payload = enrich(payload, base_dir)
        payload["duplicate"] = False
        saved = database.save(payload)
        if saved.get("analysis_id") != payload.get("analysis_id"):
            _remove_analysis_workspace(workspace, str(payload.get("analysis_id", "")))
            saved = dict(saved)
            saved["duplicate"] = True
            saved["duplicate_message"] = (
                "This exact email completed in another analysis process. The saved result "
                "was opened and no duplicate case was created."
            )
        saved["case"] = database.case(str(saved.get("analysis_id", "")))
        emit(saved)
        return 0
    except Exception as exc:
        return fail(f"Email could not be analyzed: {exc}", 5)


def list_history() -> int:
    try:
        _, _, database = data_paths()
        emit(database.list())
        return 0
    except Exception as exc:
        return fail(f"History could not be loaded: {exc}", 6)


def get_analysis(analysis_id: str) -> int:
    try:
        _, _, database = data_paths()
        result = database.get(analysis_id)
        if result is None:
            return fail("Analysis was not found.", 7)
        result["case"] = database.case(analysis_id)
        emit(result)
        return 0
    except Exception as exc:
        return fail(f"Analysis could not be loaded: {exc}", 8)


def refresh_intelligence(analysis_id: str) -> int:
    try:
        base_dir, _, database = data_paths()
        result = database.get(analysis_id)
        if result is None:
            return fail("Analysis was not found.", 7)
        refreshed = enrich(dict(result), base_dir, force_refresh=True)
        refreshed["duplicate"] = False
        refreshed["intelligence_refreshed"] = True
        database.save(refreshed)
        database.add_case_event(analysis_id, "intelligence_refreshed", {"force_refresh": True})
        refreshed["case"] = database.case(analysis_id)
        emit(refreshed)
        return 0
    except Exception as exc:
        return fail(f"Threat intelligence could not be refreshed: {exc}", 18)


def delete_analysis(analysis_id: str) -> int:
    try:
        _, workspace, database = data_paths()
        deleted = database.delete(analysis_id)
        if deleted:
            _remove_analysis_workspace(workspace, analysis_id)
        emit({"deleted": deleted})
        return 0
    except Exception as exc:
        return fail(f"Analysis could not be deleted: {exc}", 10)


def get_stats() -> int:
    try:
        _, _, database = data_paths()
        emit(database.stats())
        return 0
    except Exception as exc:
        return fail(f"Statistics could not be loaded: {exc}", 11)


def list_iocs() -> int:
    try:
        _, _, database = data_paths()
        emit(database.iocs())
        return 0
    except Exception as exc:
        return fail(f"IOCs could not be loaded: {exc}", 12)


def get_tools_status() -> int:
    try:
        emit({"status": "ok", "tools": tools_status(run_versions=True)})
        return 0
    except Exception as exc:
        return fail(f"Bundled tool self-test failed: {exc}", 17)


def get_case(analysis_id: str) -> int:
    try:
        _, _, database = data_paths()
        case = database.case(analysis_id)
        if case is None:
            return fail("Analysis was not found.", 7)
        emit(case)
        return 0
    except Exception as exc:
        return fail(f"Case metadata could not be loaded: {exc}", 21)


def put_case(analysis_id: str, changes_json: str) -> int:
    try:
        _, _, database = data_paths()
        changes = json.loads(changes_json)
        if not isinstance(changes, dict):
            return fail("Case update must be a JSON object.", 22)
        emit(database.update_case(analysis_id, changes))
        return 0
    except Exception as exc:
        return fail(f"Case metadata could not be saved: {exc}", 22)


def list_audit(limit: int) -> int:
    try:
        _, _, database = data_paths()
        emit(database.audit_entries(limit))
        return 0
    except Exception as exc:
        return fail(f"Audit log could not be loaded: {exc}", 23)


def backup_create(output_path: str) -> int:
    try:
        base_dir, _, database = data_paths()
        result = create_backup(base_dir, Path(output_path))
        database.audit("backup_created", outcome="success", details={"file_count": result["file_count"]})
        emit(result)
        return 0
    except Exception as exc:
        return fail(f"Backup could not be created: {exc}", 24)


def backup_restore(input_path: str) -> int:
    try:
        base_dir, _, _ = data_paths()
        result = restore_backup(base_dir, Path(input_path))
        restored_database = AnalysisDatabase(base_dir / "mailscope.db")
        restored_database.archive_exact_duplicates()
        restored_database.ensure_unique_source_hash()
        restored_database.audit("backup_restored", outcome="success", details={"format": result["format"]})
        emit(result)
        return 0
    except Exception as exc:
        return fail(f"Backup could not be restored: {exc}", 25)


def yara_status() -> int:
    try:
        from app.yara_manager import bundled_status, status

        base_dir, _, _ = data_paths()
        result = status(base_dir)
        resource_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
        result["bundled"] = bundled_status(resource_root / "rules")
        emit(result)
        return 0
    except Exception as exc:
        return fail(f"YARA status could not be loaded: {exc}", 26)


def yara_import(path: str) -> int:
    try:
        from app.yara_manager import import_rule

        base_dir, _, database = data_paths()
        result = import_rule(base_dir, Path(path))
        database.audit("yara_rule_imported", outcome="success", details={"custom_rule_count": len(result["custom_rules"])})
        emit(result)
        return 0
    except Exception as exc:
        return fail(f"YARA rule could not be imported: {exc}", 27)


def yara_set_active(name: str, digest: str) -> int:
    try:
        from app.yara_manager import set_active

        base_dir, _, database = data_paths()
        result = set_active(base_dir, name, digest or None)
        database.audit("yara_rule_state_changed", outcome="enabled" if digest else "disabled", details={"name": name})
        emit(result)
        return 0
    except Exception as exc:
        return fail(f"YARA rule state could not be changed: {exc}", 28)


def ui_bootstrap() -> int:
    """Return the read-mostly UI state in one engine startup."""
    try:
        base_dir, _, database = data_paths()
        history = database.list()
        latest = database.get(history[0]["analysis_id"]) if history else None
        if latest is not None:
            latest["case"] = database.case(str(latest.get("analysis_id", "")))
        emit({
            "engine": {
                "status": "ok",
                "engineVersion": ENGINE_VERSION,
                "transport": "stdio-utf8",
                "socTools": tools_status(run_versions=False),
            },
            "history": history,
            "stats": database.stats(),
            "settings": load_settings(base_dir),
            "latest_analysis": latest,
        })
        return 0
    except Exception as exc:
        return fail(f"Application data could not be initialized: {exc}", 19)


def export_analysis(analysis_id: str, output_path: str, report_format: str) -> int:
    try:
        import base64, csv, html
        _, _, database = data_paths()
        result = database.get(analysis_id)
        if result is None:
            return fail("Analysis was not found.", 7)
        result["case"] = database.case(analysis_id)
        path = Path(output_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        fmt = report_format.lower()
        if path.suffix.lower() != f".{fmt}":
            path = path.with_suffix(f".{fmt}")
        if fmt == "json":
            path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8-sig")
        elif fmt == "csv":
            with path.open("w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(["Type", "Value", "Scope", "Source"])
                for i in result.get("iocs", []):
                    w.writerow([i.get("type",""), i.get("normalized_value",""), i.get("classification",{}).get("scope",""), i.get("source",{}).get("location","")])
        elif fmt == "html":
            path.write_text(build_html_report(result), encoding="utf-8")
            emit({"saved": True, "path": str(path), "format": fmt})
            return 0
            email = result.get("email", {})
            risk = result.get("risk", {})
            findings = "".join(f"<article class='finding {html.escape(str(x.get('severity','info')))}'><b>{html.escape(str(x.get('title','')))}</b><span>{html.escape(str(x.get('severity','')).upper())}</span><p>{html.escape(str(x.get('description','')))}</p><code>{html.escape(str(x.get('evidence','')))}</code></article>" for x in result.get("findings", [])) or "<p>No findings.</p>"
            icon_paths = {
                "online_status": "<path d='M5 12.5a7 7 0 0 1 14 0'/><path d='M8.5 12.5a3.5 3.5 0 0 1 7 0'/><circle cx='12' cy='17' r='1'/>",
                "urlhaus": "<path d='M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1'/><path d='M14 11a5 5 0 0 0-7.1-.1l-2 2A5 5 0 0 0 12 20l1.1-1.1'/>",
                "urlscan": "<circle cx='11' cy='11' r='7'/><path d='m16 16 4 4'/><path d='M8 11h6M11 8v6'/>",
                "circl_hashlookup": "<ellipse cx='12' cy='5' rx='7' ry='3'/><path d='M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5'/><path d='M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6'/>",
                "threatfox": "<path d='M12 3l7 4v5c0 4.6-3 7.8-7 9-4-1.2-7-4.4-7-9V7z'/><path d='M9 12h6'/><path d='M12 9v6'/>",
                "malwarebazaar": "<rect x='6' y='7' width='12' height='12' rx='2'/><path d='M9 3v4M15 3v4M3 10h3M18 10h3M3 16h3M18 16h3'/><path d='M9 11h.01M15 11h.01M9 15h6'/>",
                "virustotal": "<path d='M12 3l8 4.5v5c0 4.4-2.9 7.4-8 9.5-5.1-2.1-8-5.1-8-9.5v-5z'/><path d='M9 12l2 2 4-5'/>",
                "otx": "<path d='M7 18a4 4 0 1 1 .5-8A6 6 0 0 1 19 12.5 3.5 3.5 0 0 1 18 19H7z'/><path d='M9 14h6'/><path d='M12 11v6'/>",
                "abuseipdb": "<ellipse cx='12' cy='5' rx='7' ry='3'/><path d='M5 5v6c0 1.7 3.1 3 7 3s7-1.3 7-3V5'/><path d='M5 11v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6'/>",
            }
            provider_files = {
                "urlhaus": "urlhaus.png",
                "urlscan": "urlscan.png",
                "circl_hashlookup": "circl.png",
                "threatfox": "threatfox.svg",
                "malwarebazaar": "malwarebazaar.png",
                "virustotal": "virustotal.png",
                "otx": "otx.png",
                "abuseipdb": "abuseipdb.png",
            }
            icon_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
            icon_root = icon_root / ("provider_icons" if getattr(sys, "frozen", False) else "assets/provider_icons")
            def tool_icon(tool_id: str) -> str:
                provider_file = provider_files.get(tool_id)
                if provider_file:
                    icon_file = icon_root / provider_file
                    if icon_file.is_file():
                        encoded = base64.b64encode(icon_file.read_bytes()).decode("ascii")
                        mime = "image/svg+xml" if icon_file.suffix.lower() == ".svg" else "image/png"
                        return f"<img src='data:{mime};base64,{encoded}' alt=''/>"
                paths = icon_paths.get(tool_id, "<circle cx='12' cy='12' r='8'/><path d='M12 8v8M8 12h8'/>")
                return f"<svg viewBox='0 0 24 24' aria-hidden='true'>{paths}</svg>"
            def tool_card(tool: dict) -> str:
                metrics = "".join(
                    f"<li><b>{html.escape(str(key).replace('_',' ').title())}:</b> {html.escape(str(value))}</li>"
                    for key, value in tool.get("metrics", {}).items()
                )
                details = "".join(f"<li>{html.escape(str(value))}</li>" for value in tool.get("details", [])[:20])
                extra = (f"<ul class='tool-metrics'>{metrics}</ul>" if metrics else "") + (f"<details><summary>Details</summary><ul>{details}</ul></details>" if details else "")
                return f"<article class='tool'><div class='tool-icon provider-{html.escape(str(tool.get('tool_id','')))}'>{tool_icon(str(tool.get('tool_id','')))}</div><div class='tool-body'><b>{html.escape(str(tool.get('name','')))}</b><span>{html.escape(str(tool.get('status','')).upper())}</span><p>{html.escape(str(tool.get('summary','')))}</p>{extra}</div></article>"
            tools = "".join(tool_card(x) for x in result.get("tool_reports", []))
            ioc_rows = "".join(f"<tr><td>{html.escape(str(i.get('type','')))}</td><td><code>{html.escape(str(i.get('normalized_value','')))}</code></td><td>{html.escape(str(i.get('classification',{}).get('scope','')))}</td></tr>" for i in result.get("iocs", []))
            document = f"""<!doctype html><html><head><meta charset='utf-8'><title>MailScope Report</title><style>
        body{{font-family:Segoe UI,Arial;background:#0b1017;color:#e8edf5;padding:32px;max-width:1200px;margin:auto}}h1,h2{{margin-top:28px}}.meta,.tool,.finding{{background:#111a25;border:1px solid #293547;border-radius:8px;padding:16px;margin:10px 0}}.risk{{font-size:28px;font-weight:700}}.tool{{display:flex;gap:14px;align-items:flex-start}}.tool-icon{{width:40px;height:40px;min-width:40px;border:1px solid #344760;border-radius:9px;overflow:hidden;display:grid;place-items:center;color:#60a5fa;background:#f8fafc}}.tool-icon img{{width:100%;height:100%;object-fit:contain;padding:2px;border-radius:7px;box-sizing:border-box}}.tool-icon.provider-threatfox{{background:#07090d}}.tool-icon.provider-threatfox img{{padding:4px}}.tool-icon svg{{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}}.tool-body{{flex:1;min-width:0}}.tool span,.finding span{{float:right;color:#8ab4f8}}.tool-metrics{{display:flex;flex-wrap:wrap;gap:8px 18px;padding:0;margin:10px 0;list-style:none;color:#aebdd0;font-size:13px}}details{{margin-top:9px;color:#aebdd0}}details summary{{cursor:pointer;color:#8ab4f8}}details li{{margin:5px 0;word-break:break-word}}table{{width:100%;border-collapse:collapse}}td,th{{padding:8px;border-bottom:1px solid #293547;text-align:left}}code{{word-break:break-all;color:#c7dcff}}.high,.critical{{border-color:#7f1d1d}}.medium{{border-color:#92400e}}</style></head><body>
<h1>MailScope Analysis Report</h1><div class='meta'><p><b>File:</b> {html.escape(result.get('source',{}).get('file_name',''))}</p><p><b>Subject:</b> {html.escape(email.get('subject',''))}</p><p><b>From:</b> {html.escape(email.get('from',{}).get('address',''))}</p><p><b>Created:</b> {html.escape(result.get('created_at',''))}</p><p><b>SHA-256:</b> <code>{html.escape(result.get('source',{}).get('sha256',''))}</code></p><p class='risk'>Risk: {risk.get('score',0)}/100 · {html.escape(str(risk.get('level',''))).upper()}</p></div>
<h2>Analysis Tools</h2>{tools}<h2>Findings</h2>{findings}<h2>Indicators</h2><table><thead><tr><th>Type</th><th>Value</th><th>Scope</th></tr></thead><tbody>{ioc_rows}</tbody></table></body></html>"""
            path.write_text(document, encoding="utf-8")
        else:
            return fail("Unsupported report format.", 13)
        emit({"saved": True, "path": str(path), "format": fmt})
        return 0
    except Exception as exc:
        return fail(f"Report could not be exported: {exc}", 14)


def get_settings() -> int:
    try:
        base_dir, _, _ = data_paths()
        emit(load_settings(base_dir))
        return 0
    except Exception as exc:
        return fail(f"Settings could not be loaded: {exc}", 15)

def put_settings(settings_json: str) -> int:
    try:
        base_dir, workspace, database = data_paths()
        settings = json.loads(settings_json)
        saved = save_settings(base_dir, settings)
        _apply_retention(base_dir, workspace, database)
        emit(saved)
        return 0
    except Exception as exc:
        return fail(f"Settings could not be saved: {exc}", 16)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mailscope-engine")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("version")
    subparsers.add_parser("ui-bootstrap")
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("file_path")
    subparsers.add_parser("history")
    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("analysis_id")
    refresh_parser = subparsers.add_parser("refresh-intelligence")
    refresh_parser.add_argument("analysis_id")
    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("analysis_id")
    subparsers.add_parser("stats")
    subparsers.add_parser("iocs")
    subparsers.add_parser("tools-status")
    case_get_parser = subparsers.add_parser("case-get")
    case_get_parser.add_argument("analysis_id")
    case_put_parser = subparsers.add_parser("case-put")
    case_put_parser.add_argument("analysis_id")
    case_put_parser.add_argument("changes_json")
    audit_parser = subparsers.add_parser("audit")
    audit_parser.add_argument("limit", type=int, nargs="?", default=200)
    backup_create_parser = subparsers.add_parser("backup-create")
    backup_create_parser.add_argument("output_path")
    backup_restore_parser = subparsers.add_parser("backup-restore")
    backup_restore_parser.add_argument("input_path")
    subparsers.add_parser("yara-status")
    yara_import_parser = subparsers.add_parser("yara-import")
    yara_import_parser.add_argument("path")
    yara_active_parser = subparsers.add_parser("yara-set-active")
    yara_active_parser.add_argument("name")
    yara_active_parser.add_argument("digest")
    export_parser = subparsers.add_parser("export")
    export_parser.add_argument("analysis_id")
    export_parser.add_argument("output_path")
    export_parser.add_argument("report_format", choices=["json", "html", "csv"])
    subparsers.add_parser("settings-get")
    settings_put = subparsers.add_parser("settings-put")
    settings_put.add_argument("settings_json")
    return parser


def main() -> int:
    if len(sys.argv) >= 2 and sys.argv[1] == "static-worker":
        if len(sys.argv) != 4:
            return fail("Static worker expected an attachment path and detected type.", 20)
        from app.static_tools import scan_attachment_direct

        emit(scan_attachment_direct(Path(sys.argv[2]).resolve(), sys.argv[3]))
        return 0
    args = build_parser().parse_args()
    if args.command == "version":
        emit({"status": "ok", "engineVersion": ENGINE_VERSION, "transport": "stdio-utf8", "socTools": tools_status(run_versions=False)})
        return 0
    if args.command == "ui-bootstrap":
        return ui_bootstrap()
    if args.command == "analyze":
        return analyze(args.file_path)
    if args.command == "history":
        return list_history()
    if args.command == "get":
        return get_analysis(args.analysis_id)
    if args.command == "refresh-intelligence":
        return refresh_intelligence(args.analysis_id)
    if args.command == "delete":
        return delete_analysis(args.analysis_id)
    if args.command == "stats":
        return get_stats()
    if args.command == "iocs":
        return list_iocs()
    if args.command == "tools-status":
        return get_tools_status()
    if args.command == "case-get":
        return get_case(args.analysis_id)
    if args.command == "case-put":
        return put_case(args.analysis_id, args.changes_json)
    if args.command == "audit":
        return list_audit(args.limit)
    if args.command == "backup-create":
        return backup_create(args.output_path)
    if args.command == "backup-restore":
        return backup_restore(args.input_path)
    if args.command == "yara-status":
        return yara_status()
    if args.command == "yara-import":
        return yara_import(args.path)
    if args.command == "yara-set-active":
        return yara_set_active(args.name, args.digest)
    if args.command == "export":
        return export_analysis(args.analysis_id, args.output_path, args.report_format)
    if args.command == "settings-get":
        return get_settings()
    if args.command == "settings-put":
        return put_settings(args.settings_json)
    return fail("Unknown command.", 9)


if __name__ == "__main__":
    raise SystemExit(main())
