from __future__ import annotations

import json
import ipaddress
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .secret_store import protect_secret, unprotect_secret
from .risk_engine import assess_risk

DEFAULT_SETTINGS = {
    "online_intelligence": True,
    "verify_email_authentication": True,
    "query_hashes": True,
    "query_urls": True,
    "query_domains": True,
    "query_ips": True,
    "upload_attachments": False,
    "upload_emails": False,
    "abusech_auth_key": "",
    "urlscan_api_key": "",
    "virustotal_api_key": "",
    "otx_api_key": "",
    "abuseipdb_api_key": "",
    "max_queries_per_provider": 8,
    "history_retention_days": 30,
    "trusted_authserv_ids": [],
}

SECRET_KEYS = ("abusech_auth_key", "urlscan_api_key", "virustotal_api_key", "otx_api_key", "abuseipdb_api_key")
RETRY_POLICY = Retry(
    total=2,
    connect=2,
    read=2,
    status=2,
    backoff_factor=0.35,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset({"GET", "HEAD", "POST"}),
    respect_retry_after_header=True,
)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "MailScope/1.1.0 SOC-Triage"})
SESSION.mount("https://", HTTPAdapter(max_retries=RETRY_POLICY))

ONLINE_TOOL_IDS = {
    "online_status", "urlhaus", "threatfox", "malwarebazaar", "urlscan",
    "circl_hashlookup", "virustotal", "otx", "abuseipdb",
}
PRIVATE_DOMAIN_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".home", ".test", ".invalid", ".localhost", ".example")


def settings_path(base_dir: Path) -> Path:
    return base_dir / "settings.json"


def _normalize_settings(settings: dict[str, Any] | None) -> dict[str, Any]:
    source = settings or {}
    safe = dict(DEFAULT_SETTINGS)
    for key in ("online_intelligence", "verify_email_authentication", "query_hashes", "query_urls", "query_domains", "query_ips"):
        value = source.get(key, safe[key])
        safe[key] = value if isinstance(value, bool) else safe[key]
    for key in SECRET_KEYS:
        safe[key] = str(source.get(key, "")).strip()
    try:
        safe["max_queries_per_provider"] = max(1, min(int(source.get("max_queries_per_provider", 8)), 25))
    except (TypeError, ValueError):
        safe["max_queries_per_provider"] = 8
    try:
        retention = int(source.get("history_retention_days", 30))
    except (TypeError, ValueError):
        retention = 30
    safe["history_retention_days"] = retention if retention in {0, 30, 90} else 30
    trusted_source = source.get("trusted_authserv_ids", [])
    if isinstance(trusted_source, str):
        trusted_source = trusted_source.split(",")
    if not isinstance(trusted_source, list):
        trusted_source = []
    safe["trusted_authserv_ids"] = sorted({
        str(value).strip().lower().rstrip(".")
        for value in trusted_source
        if str(value).strip() and len(str(value).strip()) <= 253
    })[:20]
    # MailScope v1 never enables automatic content uploads.
    safe["upload_attachments"] = False
    safe["upload_emails"] = False
    return safe


def load_settings(base_dir: Path) -> dict[str, Any]:
    path = settings_path(base_dir)
    if not path.exists():
        return dict(DEFAULT_SETTINGS)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for key in SECRET_KEYS:
                data[key] = unprotect_secret(str(data.get(key, "")))
        return _normalize_settings(data if isinstance(data, dict) else {})
    except Exception:
        return dict(DEFAULT_SETTINGS)


def save_settings(base_dir: Path, settings: dict[str, Any]) -> dict[str, Any]:
    base_dir.mkdir(parents=True, exist_ok=True)
    safe = _normalize_settings(settings)
    stored = dict(safe)
    for key in SECRET_KEYS:
        stored[key] = protect_secret(str(stored.get(key, "")))
    path = settings_path(base_dir)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(stored, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)
    return safe


def internet_available(timeout: float = 1.8) -> bool:
    try:
        # HTTPS respects enterprise proxy configuration, unlike a raw socket probe.
        SESSION.head("https://urlhaus-api.abuse.ch/", timeout=(timeout, timeout), allow_redirects=True)
        return True
    except requests.RequestException:
        return False


def _public_host(value: str) -> bool:
    host = value.strip().lower().rstrip(".")
    if not host or host == "localhost" or "." not in host or host.endswith(PRIVATE_DOMAIN_SUFFIXES):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        labels = host.split(".")
        return all(
            label and len(label) <= 63 and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label, re.I)
            for label in labels
        )


def _privacy_safe_url(value: str) -> str:
    """Return a public URL without credentials, query parameters, or fragments."""
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if parsed.scheme.lower() not in {"http", "https"} or not _public_host(host):
            return ""
        normalized_host = host.lower()
        try:
            if ipaddress.ip_address(normalized_host).version == 6:
                normalized_host = f"[{normalized_host}]"
        except ValueError:
            pass
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit((parsed.scheme.lower(), normalized_host + port, parsed.path or "", "", ""))
    except (TypeError, ValueError):
        return ""


def _safe_indicator_value(ioc: dict[str, Any]) -> str:
    value = str(ioc.get("normalized_value", "")).strip()
    indicator_type = str(ioc.get("type", ""))
    if not value or ioc.get("classification", {}).get("is_safe_to_query") is False:
        return ""
    if indicator_type == "url":
        return _privacy_safe_url(value)
    if indicator_type == "domain":
        return value.lower().rstrip(".") if _public_host(value) else ""
    if indicator_type in {"ipv4", "ipv6"}:
        try:
            return str(ipaddress.ip_address(value)) if ipaddress.ip_address(value).is_global else ""
        except ValueError:
            return ""
    return ""


def _report(tool_id: str, name: str, status: str, summary: str, metrics=None, details=None) -> dict[str, Any]:
    return {"tool_id": tool_id, "name": name, "category": "Threat Intelligence", "status": status,
            "summary": summary, "metrics": metrics or {}, "details": details or []}


def _finalize_intelligence(payload: dict[str, Any], verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    findings = [
        finding for finding in payload.get("findings", [])
        if not str(finding.get("finding_id", "")).startswith("fnd_online_")
    ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for verdict in verdicts:
        grouped.setdefault(str(verdict.get("provider_id", "unknown")), []).append(verdict)

    rules = {
        "urlhaus": ("URLhaus listed an extracted URL", 35, "A URL extracted from the message is listed by URLhaus."),
        "threatfox": ("ThreatFox matched an extracted indicator", 30, "An extracted indicator matched ThreatFox malware intelligence."),
        "malwarebazaar": ("MalwareBazaar recognized an attachment hash", 55, "An attachment hash is present in MalwareBazaar."),
        "urlscan": ("urlscan.io returned malicious historical evidence", 30, "Historical urlscan.io results marked an extracted domain as malicious."),
        "virustotal": ("VirusTotal engines flagged an extracted indicator", 20, "At least one extracted indicator received malicious or suspicious engine detections."),
        "abuseipdb": ("AbuseIPDB reported elevated IP reputation", 15, "An extracted IP address has an elevated abuse confidence score."),
        "circl_hashlookup": ("CIRCL reported low-trust known-file context", 5, "A known-file hash was returned with a low trust value; this is context, not proof of malware."),
        "otx": ("AlienVault OTX pulse context is available", 0, "An indicator appears in one or more OTX pulses. Pulse membership alone is not proof of maliciousness."),
    }
    for provider_id, title_rule in rules.items():
        entries = grouped.get(provider_id, [])
        accepted = {"context"} if provider_id == "otx" else {"suspicious"} if provider_id == "circl_hashlookup" else {"malicious", "suspicious"}
        relevant = [entry for entry in entries if entry.get("verdict") in accepted]
        if not relevant:
            continue
        title, default_points, description = title_rule
        points = default_points
        if provider_id == "virustotal":
            detections = max(int(entry.get("detections", 0) or 0) for entry in relevant)
            points = 15 if detections <= 1 else 30 if detections <= 4 else 45 if detections <= 9 else 60
        elif provider_id == "abuseipdb":
            confidence = max(int(entry.get("score", 0) or 0) for entry in relevant)
            points = 10 if confidence < 50 else 20 if confidence < 80 else 30
        severity = "critical" if points >= 40 else "high" if points >= 25 else "medium" if points >= 15 else "low" if points else "info"
        evidence = "; ".join(
            f"{entry.get('provider')}: {entry.get('value')} ({entry.get('evidence')})"
            for entry in relevant[:3]
        )
        findings.append({
            "finding_id": f"fnd_online_{provider_id}",
            "severity": severity,
            "category": "threat_intelligence",
            "title": title,
            "description": description,
            "evidence": evidence,
            "tool_id": provider_id,
            "risk_points": points,
        })

    reports = payload.get("tool_reports", [])
    provider_errors = [
        {"provider": report.get("name", report.get("tool_id", "Unknown")), "status": report.get("status", "error"), "summary": report.get("summary", "")}
        for report in reports
        if report.get("tool_id") in ONLINE_TOOL_IDS and report.get("status") in {"error", "offline", "unavailable"}
    ]
    payload["findings"] = findings
    payload["risk"] = assess_risk(findings, reports)
    payload["intelligence"] = {
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
        "indicator_verdicts": verdicts,
        "provider_errors": provider_errors,
        "file_uploads": 0,
        "email_uploads": 0,
    }
    return payload


def _request(method: str, url: str, **kwargs):
    started = time.perf_counter()
    response = SESSION.request(method, url, timeout=(3.5, 9), **kwargs)
    elapsed = int((time.perf_counter() - started) * 1000)
    response.raise_for_status()
    return response, elapsed


def _safe_request_error(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    status_code = getattr(response, "status_code", None)
    if status_code:
        reason = str(getattr(response, "reason", "")).strip()
        return f"HTTP {status_code}" + (f" {reason}" if reason else "")
    if isinstance(exc, requests.Timeout):
        return "Request timed out"
    if isinstance(exc, requests.ConnectionError):
        return "Connection failed"
    return type(exc).__name__


def _urlscan_domain_candidates(domains: list[str], urls: list[str], limit: int) -> list[str]:
    candidates = list(domains)
    for value in urls:
        try:
            hostname = (urlsplit(value).hostname or "").lower()
        except ValueError:
            hostname = ""
        if hostname:
            candidates.append(hostname)
    normalized: list[str] = []
    for value in candidates:
        domain = re.sub(r"[^a-z0-9.-]", "", str(value).lower().strip("."))
        if domain and domain not in normalized:
            normalized.append(domain)
    return normalized[:limit]


def _urlscan_result_is_malicious(result: dict[str, Any]) -> bool:
    verdicts = result.get("verdicts", {})
    if not isinstance(verdicts, dict):
        return False
    if verdicts.get("malicious") is True:
        return True
    return any(
        isinstance(verdicts.get(source), dict) and verdicts[source].get("malicious") is True
        for source in ("overall", "urlscan", "community", "engines")
    )


def enrich(payload: dict[str, Any], base_dir: Path, force_refresh: bool = False) -> dict[str, Any]:
    from .database import AnalysisDatabase

    database = AnalysisDatabase(base_dir / "mailscope.db")
    database.prune_provider_cache()
    settings = load_settings(base_dir)
    payload["tool_reports"] = [
        report for report in payload.get("tool_reports", [])
        if report.get("tool_id") not in ONLINE_TOOL_IDS
    ]
    reports = payload.setdefault("tool_reports", [])
    verdicts: list[dict[str, Any]] = []
    cache_hits: dict[str, int] = {}

    def cached(provider_id: str, indicator_type: str, query_value: str, display_value: str | None = None) -> dict[str, Any] | None:
        if force_refresh:
            return None
        entry = database.cache_get(provider_id, indicator_type, query_value)
        if entry is None:
            return None
        entry["value"] = display_value if display_value is not None else query_value
        if display_value is not None and display_value != query_value:
            entry["queried_value"] = query_value
        cache_hits[provider_id] = cache_hits.get(provider_id, 0) + 1
        return entry

    def add_fresh(entry: dict[str, Any], query_value: str) -> None:
        verdicts.append(entry)
        ttl = 6 if entry.get("verdict") in {"malicious", "suspicious"} else 24
        database.cache_put(
            str(entry.get("provider_id", "")), str(entry.get("type", "")), query_value, entry, ttl
        )

    def finish() -> dict[str, Any]:
        online_report = next(
            (item for item in reports if item.get("tool_id") == "online_status"), None
        )
        if online_report is not None:
            online_report.setdefault("metrics", {})["cache_hits"] = sum(cache_hits.values())
            online_report["metrics"]["force_refresh"] = force_refresh
        finalized = _finalize_intelligence(payload, verdicts)
        for entry in verdicts:
            cache = entry.get("cache", {})
            database.audit(
                "provider_cache_hit" if cache.get("hit") else "provider_query",
                provider_id=str(entry.get("provider_id", "")),
                indicator_type=str(entry.get("type", "")),
                indicator_value=str(entry.get("queried_value") or entry.get("value", "")),
                outcome=str(entry.get("verdict", "")),
                details={
                    "cache_hit": bool(cache.get("hit")),
                    "url_sanitized": bool(entry.get("queried_value") and entry.get("queried_value") != entry.get("value")),
                    "full_content_uploaded": False,
                },
            )
        return finalized

    if not settings.get("online_intelligence", True):
        reports.append(_report("online_status", "Online Intelligence", "disabled", "Disabled in Settings."))
        database.audit("online_intelligence", outcome="disabled", details={"full_content_uploaded": False})
        return finish()
    if not internet_available():
        reports.append(_report("online_status", "Online Intelligence", "offline", "No internet connection. Local analysis completed normally."))
        database.audit("online_intelligence", outcome="offline", details={"full_content_uploaded": False})
        return finish()

    max_q = max(1, min(int(settings.get("max_queries_per_provider", 8)), 25))
    iocs = payload.get("iocs", [])
    url_entries: list[tuple[str, str]] = []
    domains: list[str] = []
    ips: list[str] = []
    privacy_filtered = 0
    sanitized_urls = 0
    seen_queries: set[tuple[str, str]] = set()
    for ioc in iocs:
        indicator_type = str(ioc.get("type", ""))
        enabled = (
            settings.get("query_urls") if indicator_type == "url" else
            settings.get("query_domains") if indicator_type == "domain" else
            settings.get("query_ips") if indicator_type in {"ipv4", "ipv6"} else
            False
        )
        if not enabled:
            continue
        original = str(ioc.get("normalized_value", "")).strip()
        safe_value = _safe_indicator_value(ioc)
        if not safe_value:
            privacy_filtered += 1
            continue
        key = (indicator_type, safe_value.lower())
        if key in seen_queries:
            continue
        seen_queries.add(key)
        if indicator_type == "url" and len(url_entries) < max_q:
            url_entries.append((original, safe_value))
            sanitized_urls += int(original != safe_value)
        elif indicator_type == "domain" and len(domains) < max_q:
            domains.append(safe_value)
        elif indicator_type in {"ipv4", "ipv6"} and len(ips) < max_q:
            ips.append(safe_value)
    urls = [safe for _, safe in url_entries]
    original_url = {safe: original for original, safe in url_entries}
    hashes = ([a.get("hashes", {}).get("sha256", "") for a in payload.get("attachments", [])
               if a.get("hashes", {}).get("sha256")][:max_q]
               if settings.get("query_hashes") else [])
    urlscan_domains = _urlscan_domain_candidates(domains, urls, max_q)
    reports.append(_report(
        "online_status", "Online Intelligence", "completed",
        "Internet available; public indicators and attachment hashes are eligible for reputation lookups.",
        {"file_uploads": 0, "email_uploads": 0, "privacy_filtered": privacy_filtered, "sanitized_urls": sanitized_urls},
        ["Complete emails and attachments are not uploaded.", "Private indicators are blocked; URL credentials, query parameters, and fragments are removed."],
    ))
    abusech_key=str(settings.get("abusech_auth_key","")).strip()
    abusech_headers={"Auth-Key":abusech_key}

    # abuse.ch uses one account Auth-Key for URLhaus, ThreatFox, and MalwareBazaar.
    if not urls:
        reports.append(_report("urlhaus", "URLhaus", "skipped", "No URL indicators or URL queries disabled."))
    elif not abusech_key:
        reports.append(_report("urlhaus", "URLhaus", "unavailable", "Shared abuse.ch Auth-Key is not configured."))
    else:
        hits, errors, elapsed = 0, 0, 0
        details = []
        for value in urls:
            cached_entry = cached("urlhaus", "url", value, original_url.get(value, value))
            if cached_entry is not None:
                verdicts.append(cached_entry)
                if cached_entry.get("verdict") == "malicious": hits += 1
                continue
            try:
                r, ms = _request("POST", "https://urlhaus-api.abuse.ch/v1/url/", headers=abusech_headers, data={"url": value})
                elapsed += ms; data = r.json()
                listed = data.get("query_status") == "ok"
                if listed: hits += 1; details.append(f"Listed: {value}")
                add_fresh({"provider_id":"urlhaus","provider":"URLhaus","type":"url","value":original_url.get(value, value),"queried_value":value,"verdict":"malicious" if listed else "not_found","confidence":"high" if listed else "low","evidence":"listed URL" if listed else "not present in provider dataset"}, value)
            except Exception as exc: errors += 1; details.append(f"Lookup error: {_safe_request_error(exc)}")
        reports.append(_report("urlhaus", "URLhaus", "suspicious" if hits else ("error" if errors == len(urls) else "warning" if errors else "info"),
                               f"Provider request failed for all {len(urls)} URL(s); no verdict was obtained." if errors == len(urls) else f"Checked {len(urls)} URL(s); {hits} listed.", {"queried": len(urls), "listed": hits, "errors": errors, "duration_ms": elapsed, "cache_hits": cache_hits.get("urlhaus",0)}, details[:8]))

    candidates = (domains + ips + hashes)[:max_q]
    if not candidates:
        reports.append(_report("threatfox", "ThreatFox", "skipped", "No supported IOC values found."))
    elif not abusech_key:
        reports.append(_report("threatfox", "ThreatFox", "unavailable", "Shared abuse.ch Auth-Key is not configured."))
    else:
        hits, errors = 0, 0; details=[]
        for value in candidates:
            value_type = "sha256" if value in hashes else "ip" if value in ips else "domain"
            cached_entry = cached("threatfox", value_type, value)
            if cached_entry is not None:
                verdicts.append(cached_entry)
                if cached_entry.get("verdict") == "malicious": hits += 1
                continue
            try:
                r, _ = _request("POST", "https://threatfox-api.abuse.ch/api/v1/", headers=abusech_headers, json={"query": "search_ioc", "search_term": value})
                data=r.json()
                matched = data.get("query_status") == "ok" and bool(data.get("data"))
                if matched: hits += 1; details.append(f"Match: {value}")
                add_fresh({"provider_id":"threatfox","provider":"ThreatFox","type":value_type,"value":value,"verdict":"malicious" if matched else "not_found","confidence":"high" if matched else "low","evidence":"IOC match" if matched else "not present in provider dataset"}, value)
            except Exception as exc: errors += 1; details.append(f"Lookup error: {_safe_request_error(exc)}")
        reports.append(_report("threatfox", "ThreatFox", "suspicious" if hits else ("error" if errors == len(candidates) else "warning" if errors else "info"),
                               f"Provider request failed for all {len(candidates)} IOC(s); no verdict was obtained." if errors == len(candidates) else f"Checked {len(candidates)} IOC(s); {hits} matched.", {"queried":len(candidates),"matches":hits,"errors":errors,"cache_hits":cache_hits.get("threatfox",0)}, details[:8]))

    if not hashes:
        reports.append(_report("malwarebazaar","MalwareBazaar","skipped","No attachment hashes or hash queries disabled."))
    elif not abusech_key:
        reports.append(_report("malwarebazaar", "MalwareBazaar", "unavailable", "Shared abuse.ch Auth-Key is not configured."))
    else:
        hits, errors=0,0; details=[]
        for value in hashes:
            cached_entry = cached("malwarebazaar", "sha256", value)
            if cached_entry is not None:
                verdicts.append(cached_entry)
                if cached_entry.get("verdict") == "malicious": hits += 1
                continue
            try:
                r,_=_request("POST","https://mb-api.abuse.ch/api/v1/",headers=abusech_headers,data={"query":"get_info","hash":value})
                data=r.json()
                matched = data.get("query_status") == "ok"
                if matched: hits+=1; details.append(f"Known sample: {value}")
                add_fresh({"provider_id":"malwarebazaar","provider":"MalwareBazaar","type":"sha256","value":value,"verdict":"malicious" if matched else "not_found","confidence":"high" if matched else "low","evidence":"known sample hash" if matched else "not present in provider dataset"}, value)
            except Exception as exc: errors+=1; details.append(f"Lookup error: {_safe_request_error(exc)}")
        reports.append(_report("malwarebazaar","MalwareBazaar","suspicious" if hits else ("error" if errors==len(hashes) else "warning" if errors else "info"),
                               f"Provider request failed for all {len(hashes)} attachment hash(es); no verdict was obtained." if errors == len(hashes) else f"Checked {len(hashes)} attachment hash(es); {hits} known.",{"queried":len(hashes),"matches":hits,"errors":errors,"cache_hits":cache_hits.get("malwarebazaar",0)},details[:8]))

    # Search-only urlscan.io integration. MailScope never submits URLs for scanning.
    urlscan_key = str(settings.get("urlscan_api_key", "")).strip()
    if not urlscan_domains:
        reports.append(_report("urlscan", "urlscan.io", "skipped", "No domain indicators or URL/domain queries disabled.", {"submissions": 0}))
    elif not urlscan_key:
        reports.append(_report("urlscan", "urlscan.io", "unavailable", "API key is not configured; no URL was submitted.", {"submissions": 0}))
    else:
        malicious, errors, scans_reviewed = 0, 0, 0
        details = ["Search-only mode; MailScope did not submit any URL for scanning."]
        for domain in urlscan_domains:
            cached_entry = cached("urlscan", "domain", domain)
            if cached_entry is not None:
                verdicts.append(cached_entry)
                if cached_entry.get("verdict") == "suspicious": malicious += 1
                continue
            try:
                r, _ = _request(
                    "GET",
                    "https://urlscan.io/api/v1/search/",
                    headers={"API-Key": urlscan_key},
                    params={"q": f"page.domain:{domain} AND date:>now-90d", "size": 5},
                )
                results = r.json().get("results", [])
                if not isinstance(results, list):
                    results = []
                scans_reviewed += len(results)
                domain_hits = sum(1 for item in results if isinstance(item, dict) and _urlscan_result_is_malicious(item))
                malicious += domain_hits
                if domain_hits:
                    details.append(f"Malicious historical result(s) {domain_hits}: {domain}")
                add_fresh({"provider_id":"urlscan","provider":"urlscan.io","type":"domain","value":domain,"verdict":"suspicious" if domain_hits else "no_detection" if results else "not_found","confidence":"high" if domain_hits else "low","evidence":f"{domain_hits} malicious historical result(s)" if domain_hits else f"{len(results)} historical result(s), none malicious" if results else "no historical result found"}, domain)
            except Exception as exc:
                errors += 1
                details.append(f"Lookup error for {domain}: {_safe_request_error(exc)}")
        status = "suspicious" if malicious else ("error" if errors == len(urlscan_domains) else "warning" if errors else "info")
        summary = (
            f"Provider request failed for all {len(urlscan_domains)} domain(s); no verdict was obtained."
            if errors == len(urlscan_domains)
            else f"Searched {len(urlscan_domains)} domain(s); reviewed {scans_reviewed} historical scan(s), {malicious} malicious result(s)."
        )
        reports.append(_report("urlscan", "urlscan.io", status, summary,
                               {"queried": len(urlscan_domains), "scans_reviewed": scans_reviewed, "malicious_results": malicious, "errors": errors, "submissions": 0, "cache_hits":cache_hits.get("urlscan",0)}, details[:8]))

    # CIRCL Hashlookup provides known-file context; a match is not automatically malicious.
    if not hashes:
        reports.append(_report("circl_hashlookup", "CIRCL Hashlookup", "skipped", "No attachment hashes or hash queries disabled."))
    else:
        known, unknown, low_trust, errors = 0, 0, 0, 0
        details = []
        for value in hashes:
            cached_entry = cached("circl_hashlookup", "sha256", value)
            if cached_entry is not None:
                verdicts.append(cached_entry)
                if cached_entry.get("verdict") in {"context","suspicious"}: known += 1
                else: unknown += 1
                if cached_entry.get("verdict") == "suspicious": low_trust += 1
                continue
            try:
                r, _ = _request("GET", f"https://hashlookup.circl.lu/lookup/sha256/{value}", headers={"Accept": "application/json"})
                response_data = r.json()
                data = response_data if isinstance(response_data, dict) else {}
                known += 1
                trust = int(data.get("hashlookup:trust", 50))
                if trust < 50:
                    low_trust += 1
                source = str(data.get("source") or data.get("db") or "known-file dataset")
                filename = str(data.get("FileName") or "unknown name")
                details.append(f"Known file · trust {trust} · {source} · {filename}")
                add_fresh({"provider_id":"circl_hashlookup","provider":"CIRCL Hashlookup","type":"sha256","value":value,"verdict":"suspicious" if trust < 50 else "context","confidence":"medium","evidence":f"known-file trust {trust}"}, value)
            except requests.HTTPError as exc:
                if getattr(exc.response, "status_code", None) == 404:
                    unknown += 1
                    add_fresh({"provider_id":"circl_hashlookup","provider":"CIRCL Hashlookup","type":"sha256","value":value,"verdict":"unrated","confidence":"medium","evidence":"not present in known-file datasets"}, value)
                else:
                    errors += 1
                    details.append(f"Lookup error: {_safe_request_error(exc)}")
            except Exception as exc:
                errors += 1
                details.append(f"Lookup error: {_safe_request_error(exc)}")
        status = "error" if errors == len(hashes) else ("warning" if low_trust or errors else "info")
        summary = (
            f"Provider request failed for all {len(hashes)} attachment hash(es); no context was obtained."
            if errors == len(hashes)
            else f"Checked {len(hashes)} attachment hash(es); {known} known, {unknown} not present in known-file datasets."
        )
        reports.append(_report("circl_hashlookup", "CIRCL Hashlookup", status, summary,
                               {"queried": len(hashes), "known": known, "unknown": unknown, "low_trust": low_trust, "errors": errors, "cache_hits":cache_hits.get("circl_hashlookup",0)}, details[:8]))

    # Keyed providers. Missing keys are explicit, not presented as successful scans.
    vt_key=str(settings.get("virustotal_api_key","")).strip()
    vt_values=(hashes + domains + ips)[:max_q]
    if vt_key and vt_values:
        malicious=0; errors=0; max_detections=0; details=[]
        for value in vt_values:
            kind="files" if len(value)==64 else ("ip_addresses" if value in ips else "domains")
            value_type="sha256" if len(value)==64 else "ip" if value in ips else "domain"
            cached_entry = cached("virustotal", value_type, value)
            if cached_entry is not None:
                verdicts.append(cached_entry)
                score=int(cached_entry.get("detections",0) or 0)
                max_detections=max(max_detections,score)
                if score: malicious+=1
                continue
            try:
                r,_=_request("GET",f"https://www.virustotal.com/api/v3/{kind}/{value}",headers={"x-apikey":vt_key})
                stats=r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
                score=int(stats.get("malicious",0))+int(stats.get("suspicious",0))
                max_detections=max(max_detections,score)
                if score: malicious+=1; details.append(f"Detections {score}: {value}")
                add_fresh({"provider_id":"virustotal","provider":"VirusTotal","type":value_type,"value":value,"verdict":"malicious" if score>=5 else "suspicious" if score else "no_detection","confidence":"high" if score else "medium","evidence":f"{score} malicious/suspicious engine detection(s); zero detections is not proof of safety" if not score else f"{score} malicious/suspicious engine detection(s)","detections":score}, value)
            except Exception as exc: errors+=1; details.append(f"Lookup error: {type(exc).__name__}")
        reports.append(_report("virustotal","VirusTotal","suspicious" if malicious else ("error" if errors==len(vt_values) else "warning" if errors else "info"),f"Checked {len(vt_values)} value(s); {malicious} flagged. No detections is not a clean verdict.",{"queried":len(vt_values),"flagged":malicious,"max_detections":max_detections,"errors":errors,"cache_hits":cache_hits.get("virustotal",0)},details[:8]))
    elif not vt_key: reports.append(_report("virustotal","VirusTotal","unavailable","API key is not configured."))
    else: reports.append(_report("virustotal","VirusTotal","skipped","No supported indicators found."))

    otx_key=str(settings.get("otx_api_key","")).strip()
    otx_values=(domains+ips+hashes)[:max_q]
    if otx_key and otx_values:
        hits=0; errors=0; details=[]
        for value in otx_values:
            typ="file" if len(value)==64 else ("IPv4" if value in ips else "domain")
            value_type="sha256" if len(value)==64 else "ip" if value in ips else "domain"
            cached_entry = cached("otx", value_type, value)
            if cached_entry is not None:
                verdicts.append(cached_entry)
                if cached_entry.get("verdict") == "context": hits += 1
                continue
            try:
                r,_=_request("GET",f"https://otx.alienvault.com/api/v1/indicators/{typ}/{value}/general",headers={"X-OTX-API-KEY":otx_key})
                count=int(r.json().get("pulse_info",{}).get("count",0))
                if count: hits+=1; details.append(f"{count} pulse(s): {value}")
                add_fresh({"provider_id":"otx","provider":"AlienVault OTX","type":value_type,"value":value,"verdict":"context" if count else "not_found","confidence":"medium" if count else "low","evidence":f"linked to {count} pulse(s)" if count else "no pulse links found"}, value)
            except Exception as exc: errors+=1; details.append(f"Lookup error: {type(exc).__name__}")
        reports.append(_report("otx","AlienVault OTX","info" if hits or not errors else ("error" if errors==len(otx_values) else "warning"),f"Checked {len(otx_values)} IOC(s); {hits} linked to pulses (context only, not a malware verdict).",{"queried":len(otx_values),"matches":hits,"errors":errors,"cache_hits":cache_hits.get("otx",0)},details[:8]))
    elif not otx_key: reports.append(_report("otx","AlienVault OTX","unavailable","API key is not configured."))
    else: reports.append(_report("otx","AlienVault OTX","skipped","No supported indicators found."))

    abuseipdb_key=str(settings.get("abuseipdb_api_key","")).strip()
    if abuseipdb_key and ips:
        flagged=0; errors=0; max_confidence=0; details=[]
        for value in ips:
            cached_entry = cached("abuseipdb", "ip", value)
            if cached_entry is not None:
                verdicts.append(cached_entry)
                score=int(cached_entry.get("score",0) or 0)
                max_confidence=max(max_confidence,score)
                if score>=25: flagged+=1
                continue
            try:
                r,_=_request("GET","https://api.abuseipdb.com/api/v2/check",headers={"Key":abuseipdb_key,"Accept":"application/json"},params={"ipAddress":value,"maxAgeInDays":90})
                score=int(r.json().get("data",{}).get("abuseConfidenceScore",0))
                max_confidence=max(max_confidence,score)
                if score>=25: flagged+=1; details.append(f"Confidence {score}%: {value}")
                add_fresh({"provider_id":"abuseipdb","provider":"AbuseIPDB","type":"ip","value":value,"verdict":"suspicious" if score>=25 else "no_detection","confidence":"high" if score>=25 else "medium","evidence":f"abuse confidence {score}%; below threshold is not proof of safety","score":score}, value)
            except Exception as exc: errors+=1; details.append(f"Lookup error: {type(exc).__name__}")
        reports.append(_report("abuseipdb","AbuseIPDB","suspicious" if flagged else ("error" if errors==len(ips) else "warning" if errors else "info"),f"Checked {len(ips)} IP(s); {flagged} elevated. Below-threshold results are not clean verdicts.",{"queried":len(ips),"flagged":flagged,"max_confidence":max_confidence,"errors":errors,"cache_hits":cache_hits.get("abuseipdb",0)},details[:8]))
    elif not abuseipdb_key: reports.append(_report("abuseipdb","AbuseIPDB","unavailable","API key is not configured."))
    else: reports.append(_report("abuseipdb","AbuseIPDB","skipped","No IP indicators found."))
    return finish()
