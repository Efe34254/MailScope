from __future__ import annotations

import base64
import html
import json
import sys
from pathlib import Path
from typing import Any


ONLINE_TOOL_IDS = {
    "online_status", "urlhaus", "threatfox", "malwarebazaar", "urlscan",
    "circl_hashlookup", "virustotal", "otx", "abuseipdb",
}
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
VERDICT_RANK = {
    "malicious": 6,
    "suspicious": 5,
    "context": 4,
    "no_detection": 3,
    "not_found": 2,
    "clean": 2,  # Legacy reports only; current providers do not issue clean verdicts.
    "unrated": 1,
}
PROVIDER_FILES = {
    "urlhaus": "urlhaus.png",
    "urlscan": "urlscan.png",
    "circl_hashlookup": "circl.png",
    "threatfox": "threatfox.svg",
    "malwarebazaar": "malwarebazaar.png",
    "virustotal": "virustotal.png",
    "otx": "otx.png",
    "abuseipdb": "abuseipdb.png",
}


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _icon_root() -> Path:
    root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
    return root / ("provider_icons" if getattr(sys, "frozen", False) else "assets/provider_icons")


def _tool_icon(tool_id: str) -> str:
    provider_file = PROVIDER_FILES.get(tool_id)
    if provider_file:
        icon_file = _icon_root() / provider_file
        if icon_file.is_file():
            encoded = base64.b64encode(icon_file.read_bytes()).decode("ascii")
            mime = "image/svg+xml" if icon_file.suffix.lower() == ".svg" else "image/png"
            return f"<img src='data:{mime};base64,{encoded}' alt=''/>"
    return "<svg viewBox='0 0 24 24' aria-hidden='true'><circle cx='12' cy='12' r='8'/><path d='M12 8v8M8 12h8'/></svg>"


def _tool_card(tool: dict[str, Any]) -> str:
    tool_id = str(tool.get("tool_id", ""))
    metrics = "".join(
        f"<li><b>{_escape(str(key).replace('_', ' ').title())}:</b> {_escape(value)}</li>"
        for key, value in tool.get("metrics", {}).items()
    )
    details = "".join(f"<li>{_escape(value)}</li>" for value in tool.get("details", [])[:30])
    extra = (f"<ul class='metrics'>{metrics}</ul>" if metrics else "") + (
        f"<details><summary>Details</summary><ul>{details}</ul></details>" if details else ""
    )
    return (
        f"<article class='tool status-{_escape(tool.get('status', 'info'))}'>"
        f"<div class='tool-icon provider-{_escape(tool_id)}'>{_tool_icon(tool_id)}</div>"
        f"<div class='tool-body'><div class='tool-title'><b>{_escape(tool.get('name', tool_id))}</b>"
        f"<span>{_escape(str(tool.get('status', 'info')).upper())}</span></div>"
        f"<p>{_escape(tool.get('summary', ''))}</p>{extra}</div></article>"
    )


def _finding_card(finding: dict[str, Any]) -> str:
    points = finding.get("risk_points")
    points_label = f" · +{int(points)} points" if isinstance(points, int) and points > 0 else ""
    evidence = f"<code>{_escape(finding.get('evidence', ''))}</code>" if finding.get("evidence") else ""
    return (
        f"<article class='finding severity-{_escape(finding.get('severity', 'info'))}'>"
        f"<div><b>{_escape(finding.get('title', 'Finding'))}</b>"
        f"<span>{_escape(str(finding.get('severity', 'info')).upper())}{points_label}</span></div>"
        f"<p>{_escape(finding.get('description', ''))}</p>{evidence}"
        f"<small>Source: {_escape(finding.get('tool_id', 'unknown'))}</small></article>"
    )


def _prioritized_iocs(result: dict[str, Any]) -> list[dict[str, Any]]:
    verdicts = result.get("intelligence", {}).get("indicator_verdicts", [])
    by_value: dict[str, list[dict[str, Any]]] = {}
    for verdict in verdicts:
        by_value.setdefault(str(verdict.get("value", "")).lower(), []).append(verdict)
    rows: list[dict[str, Any]] = []
    for ioc in result.get("iocs", []):
        value = str(ioc.get("normalized_value", ""))
        matches = by_value.get(value.lower(), [])
        best = max(matches, key=lambda item: VERDICT_RANK.get(str(item.get("verdict", "unrated")), 1), default=None)
        rows.append({
            "type": ioc.get("type", ""),
            "value": value,
            "scope": ioc.get("classification", {}).get("scope", "unknown"),
            "verdict": best.get("verdict", "unrated") if best else "unrated",
            "providers": ", ".join(sorted({str(item.get("provider", "")) for item in matches if item.get("provider")})),
            "evidence": best.get("evidence", "No provider verdict recorded") if best else "No provider verdict recorded",
        })
    return sorted(rows, key=lambda item: (-VERDICT_RANK.get(str(item["verdict"]), 1), str(item["type"]), str(item["value"])))


def build_html_report(result: dict[str, Any]) -> str:
    email = result.get("email", {})
    source = result.get("source", {})
    risk = result.get("risk", {})
    coverage = risk.get("coverage") or risk.get("confidence") or "unknown"
    intelligence = result.get("intelligence", {})
    case = result.get("case") or {}
    findings = sorted(
        result.get("findings", []),
        key=lambda item: (-(int(item.get("risk_points") or 0)), -SEVERITY_RANK.get(str(item.get("severity", "info")), 1)),
    )
    tools = result.get("tool_reports", [])
    online_tools = [tool for tool in tools if tool.get("tool_id") in ONLINE_TOOL_IDS]
    auth_ids = {"auth_headers", "auth_verification", "identity_guard"}
    auth_tools = [tool for tool in tools if tool.get("tool_id") in auth_ids]
    local_tools = [tool for tool in tools if tool.get("tool_id") not in ONLINE_TOOL_IDS | auth_ids]

    reasons = risk.get("reasons", [])[:3]
    reason_items = "".join(f"<li>{_escape(reason)}</li>" for reason in reasons) or "<li>No elevated risk reason was produced.</li>"
    actions = risk.get("recommended_actions", [])
    action_items = "".join(f"<li>{_escape(action)}</li>" for action in actions) or "<li>Apply normal organizational email-handling policy.</li>"
    incomplete = risk.get("incomplete_checks", [])
    incomplete_box = (
        "<div class='callout warning'><b>Incomplete checks:</b> " + ", ".join(_escape(value) for value in incomplete) + "</div>"
        if incomplete else "<div class='callout success'><b>Coverage:</b> No failed or unavailable checks were recorded.</div>"
    )

    breakdown_rows = "".join(
        f"<tr><td>{_escape(item.get('title', ''))}</td><td>{_escape(item.get('source', ''))}</td>"
        f"<td>{_escape(item.get('category', ''))}</td><td>{_escape(str(item.get('severity', '')).upper())}</td>"
        f"<td>{_escape(item.get('raw_points', item.get('points', 0)))}</td><td class='points'>+{_escape(item.get('points', 0))}</td></tr>"
        for item in risk.get("score_breakdown", [])
    ) or "<tr><td colspan='6'>No score-producing findings.</td></tr>"

    category_rows = "".join(
        f"<tr><td>{_escape(item.get('category', ''))}</td><td>{_escape(item.get('evidence_count', 0))}</td>"
        f"<td>{_escape(item.get('raw_points', 0))}</td><td>{_escape(item.get('cap', 0))}</td>"
        f"<td class='points'>{_escape(item.get('credited_points', 0))}</td></tr>"
        for item in risk.get("category_breakdown", [])
    ) or "<tr><td colspan='5'>No risk categories contributed points.</td></tr>"

    attachment_rows = "".join(
        "<tr>"
        f"<td><b>{'&nbsp;' * (int(item.get('depth', 0)) * 4)}{_escape('↳ ' if item.get('is_embedded') else '')}{_escape(item.get('file_name', ''))}</b><small>{_escape(item.get('declared_content_type', ''))}</small></td>"
        f"<td>{_escape(item.get('detected_type', 'unknown'))}</td><td>{_escape(item.get('size', 0))}</td>"
        f"<td>{_escape(str(item.get('analysis_status', 'analyzed')).replace('_', ' ').upper())}</td>"
        f"<td><code>{_escape(item.get('hashes', {}).get('sha256', ''))}</code></td>"
        f"<td>{_escape('; '.join(item.get('static_flags', []) + item.get('extraction_notes', [])) or 'No static flags')}</td></tr>"
        for item in result.get("attachments", [])
    ) or "<tr><td colspan='6'>No attachments were found.</td></tr>"

    ioc_rows = "".join(
        f"<tr class='verdict-{_escape(item['verdict'])}'><td><span class='verdict'>{_escape(str(item['verdict']).upper())}</span></td>"
        f"<td>{_escape(item['type'])}</td><td><code>{_escape(item['value'])}</code></td>"
        f"<td>{_escape(item['scope'])}</td><td>{_escape(item['providers'] or '—')}</td><td>{_escape(item['evidence'])}</td></tr>"
        for item in _prioritized_iocs(result)
    ) or "<tr><td colspan='6'>No indicators were extracted.</td></tr>"

    findings_html = "".join(_finding_card(item) for item in findings) or "<p>No heuristic or intelligence findings were produced.</p>"
    online_html = "".join(_tool_card(item) for item in online_tools) or "<p>Online intelligence was not recorded.</p>"
    auth_html = "".join(_tool_card(item) for item in auth_tools) or "<p>No sender-authentication evidence was recorded.</p>"
    local_html = "".join(_tool_card(item) for item in local_tools) or "<p>No local tool reports were recorded.</p>"
    refreshed_at = intelligence.get("refreshed_at", "Not recorded")
    online_status = next((item for item in online_tools if item.get("tool_id") == "online_status"), {})
    online_metrics = online_status.get("metrics", {})
    cache_verdicts = sum(1 for item in intelligence.get("indicator_verdicts", []) if item.get("cache", {}).get("hit"))
    case_events = "".join(
        f"<li><b>{_escape(event.get('event_type', '').replace('_', ' ').title())}</b> · {_escape(event.get('created_at', ''))}"
        f"<small>{_escape(json.dumps(event.get('details', {}), ensure_ascii=False))}</small></li>"
        for event in case.get("events", [])[:20]
    ) if case else ""

    return f"""<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>MailScope SOC Report</title><style>
:root{{--bg:#0b1017;--panel:#111923;--line:#2a3748;--text:#e8edf5;--muted:#9babc0;--blue:#6aa8ff;--green:#59d6a8;--amber:#f2b84b;--red:#ff6b73}}
*{{box-sizing:border-box}}body{{font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);padding:30px;max-width:1250px;margin:auto;line-height:1.45}}h1{{font-size:30px;margin:0}}h2{{margin:34px 0 12px;font-size:19px}}h3{{margin:0 0 10px}}p{{color:var(--muted)}}small{{display:block;color:var(--muted);margin-top:4px}}code{{color:#c7dcff;word-break:break-all}}.eyebrow{{color:var(--blue);font-size:11px;letter-spacing:1.5px}}.header{{display:flex;justify-content:space-between;gap:24px;border-bottom:1px solid var(--line);padding-bottom:22px}}.header-meta{{text-align:right;color:var(--muted);font-size:12px}}.summary-grid{{display:grid;grid-template-columns:1.1fr 2fr;gap:14px;margin-top:20px}}.verdict-card,.panel,.tool,.finding,.callout{{background:var(--panel);border:1px solid var(--line);padding:17px}}.score{{font-size:54px;font-weight:700;line-height:1}}.score small{{display:inline;font-size:15px}}.risk-label{{font-size:18px;color:var(--amber);margin-top:8px}}.coverage{{margin-top:12px;color:var(--blue);font-size:12px}}.decision ul,.actions{{margin:8px 0;padding-left:20px}}.callout{{margin-top:12px}}.callout.warning{{border-color:#7b5a28;color:#ffd98a}}.callout.success{{border-color:#245d4d;color:#8ce6c5}}table{{width:100%;border-collapse:collapse;background:var(--panel);font-size:12px}}th,td{{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{color:#a9bdd8;background:#0e151f}}td.points{{font-weight:700;color:var(--amber)}}.finding{{margin:9px 0;border-left:4px solid var(--line)}}.finding>div,.tool-title{{display:flex;justify-content:space-between;gap:15px}}.finding span,.tool-title span{{color:var(--blue);font-size:11px}}.severity-high,.severity-critical{{border-left-color:var(--red)}}.severity-medium{{border-left-color:var(--amber)}}.severity-low{{border-left-color:var(--blue)}}.finding code{{display:block;margin:9px 0}}.tool-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}.tool{{display:flex;gap:12px;min-width:0}}.tool-icon{{width:42px;height:42px;min-width:42px;background:#f7f8fa;border-radius:8px;display:grid;place-items:center;overflow:hidden}}.tool-icon img{{width:100%;height:100%;object-fit:contain;padding:3px}}.tool-icon svg{{width:22px;fill:none;stroke:#286fc8;stroke-width:1.8}}.tool-body{{min-width:0;flex:1}}.tool-body p{{font-size:12px;margin:7px 0}}.metrics{{display:flex;flex-wrap:wrap;gap:5px 15px;list-style:none;padding:0;font-size:11px;color:var(--muted)}}details{{color:var(--muted);font-size:11px}}details summary{{cursor:pointer;color:var(--blue)}}.verdict{{font-weight:700;font-size:10px}}.verdict-malicious .verdict{{color:var(--red)}}.verdict-suspicious .verdict{{color:var(--amber)}}.verdict-context .verdict{{color:var(--blue)}}.verdict-no_detection .verdict,.verdict-not_found .verdict{{color:var(--muted)}}.verdict-clean .verdict{{color:var(--green)}}.section-note{{color:var(--muted);font-size:12px;margin-top:-7px}}.disclaimer{{margin:35px 0 10px;color:var(--muted);font-size:11px;border-top:1px solid var(--line);padding-top:14px}}
@media(max-width:850px){{.summary-grid,.tool-grid{{grid-template-columns:1fr}}.header{{display:block}}.header-meta{{text-align:left;margin-top:12px}}body{{padding:16px}}table{{display:block;overflow-x:auto}}}}
@media print{{:root{{--bg:#fff;--panel:#fff;--line:#ccd3dc;--text:#111827;--muted:#475569;--blue:#1d4ed8}}body{{padding:0;max-width:none}}.tool,.finding,.panel,.verdict-card,.callout{{break-inside:avoid}}details{{display:block}}details>ul{{display:block}}}}
</style></head><body>
<header class='header'><div><div class='eyebrow'>MAILSCOPE · SOC REPORT V3</div><h1>Email Static Analysis Report</h1><p>{_escape(email.get('subject', 'No subject'))}</p></div><div class='header-meta'><b>Analysis ID</b><br>{_escape(result.get('analysis_id', ''))}<br><b>Generated from</b><br>MailScope 1.1.0</div></header>
<section class='summary-grid'><div class='verdict-card'><div class='eyebrow'>FINAL VERDICT</div><div class='score'>{_escape(risk.get('score', 0))}<small>/100</small></div><div class='risk-label'>{_escape(str(risk.get('level', 'informational')).upper())}</div><div class='coverage'>Analysis coverage: {_escape(str(coverage).upper())}</div></div><div class='panel decision'><h3>Why this verdict</h3><ul>{reason_items}</ul><p>This verdict combines local static evidence with recorded reputation-provider results. A provider's NOT FOUND or NO DETECTION result does not prove that an indicator is safe.</p>{incomplete_box}</div></section>
<section class='panel' style='margin-top:14px'><h3>Case metadata</h3><table><tr><th>File</th><td>{_escape(source.get('file_name', ''))}</td><th>Created</th><td>{_escape(result.get('created_at', ''))}</td></tr><tr><th>From</th><td>{_escape(email.get('from', {}).get('address', ''))}</td><th>Message-ID</th><td><code>{_escape(email.get('message_id', ''))}</code></td></tr><tr><th>SHA-256</th><td colspan='3'><code>{_escape(source.get('sha256', ''))}</code></td></tr></table></section>
<h2>Analyst case workflow</h2><section class='panel'><table><tr><th>State</th><td>{_escape(case.get('state', 'New'))}</td><th>Assigned analyst</th><td>{_escape(case.get('assigned_analyst', '') or 'Unassigned')}</td></tr><tr><th>Decision</th><td>{_escape(case.get('analyst_decision', '') or 'Not recorded')}</td><th>Tags</th><td>{_escape(', '.join(case.get('tags', [])) or 'None')}</td></tr><tr><th>Closure reason</th><td colspan='3'>{_escape(case.get('closure_reason', '') or 'Not recorded')}</td></tr></table>{f"<details><summary>Case event history</summary><ul>{case_events}</ul></details>" if case_events else '<p>No case workflow events were recorded.</p>'}</section>
<h2>Recommended analyst actions</h2><section class='panel'><ol class='actions'>{action_items}</ol></section>
<h2>Risk score breakdown</h2><p class='section-note'>Risk model {_escape(risk.get('model_version', 'legacy'))}. Category caps prevent correlated evidence from multiplying without limit.</p><table><thead><tr><th>Evidence</th><th>Source</th><th>Category</th><th>Severity</th><th>Raw</th><th>Credited</th></tr></thead><tbody>{breakdown_rows}</tbody></table>
<h2>Risk category caps</h2><table><thead><tr><th>Category</th><th>Evidence count</th><th>Raw points</th><th>Cap</th><th>Credited</th></tr></thead><tbody>{category_rows}</tbody></table>
<h2>Priority findings</h2>{findings_html}
<h2>Sender identity and authentication</h2><div class='tool-grid'>{auth_html}</div>
<h2>Attachment inventory and embedded objects</h2><table><thead><tr><th>File tree</th><th>Detected type</th><th>Bytes</th><th>Analysis status</th><th>SHA-256</th><th>Static flags / limits</th></tr></thead><tbody>{attachment_rows}</tbody></table>
<h2>Privacy and query coverage</h2><section class='panel'><table><tr><th>Complete email uploads</th><td>{_escape(intelligence.get('email_uploads', 0))}</td><th>Attachment uploads</th><td>{_escape(intelligence.get('file_uploads', 0))}</td></tr><tr><th>Private indicators blocked</th><td>{_escape(online_metrics.get('privacy_filtered', 0))}</td><th>URLs sanitized</th><td>{_escape(online_metrics.get('sanitized_urls', 0))}</td></tr><tr><th>Cached verdicts</th><td>{_escape(cache_verdicts)}</td><th>Forced refresh</th><td>{_escape(online_metrics.get('force_refresh', False))}</td></tr></table></section>
<h2>Threat intelligence</h2><p class='section-note'>Last refreshed: {_escape(refreshed_at)} · Complete emails and attachment contents were not uploaded. Cached and live verdicts remain distinguishable in JSON evidence.</p><div class='tool-grid'>{online_html}</div>
<h2>Prioritized indicators</h2><p class='section-note'>Indicators are ordered by the strongest recorded provider verdict. NOT FOUND and NO DETECTION are coverage outcomes, not clean verdicts. OTX pulse membership is context, not proof of malware.</p><table><thead><tr><th>Verdict</th><th>Type</th><th>Value</th><th>Scope</th><th>Providers</th><th>Evidence</th></tr></thead><tbody>{ioc_rows}</tbody></table>
<h2>Technical appendix · Local analysis tools</h2><div class='tool-grid'>{local_html}</div>
<p class='disclaimer'>MailScope performs static analysis only. Provider results can change over time; refresh intelligence before final case closure when current reputation is important.</p>
</body></html>"""
