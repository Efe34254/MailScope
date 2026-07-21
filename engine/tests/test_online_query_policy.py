from __future__ import annotations

from pathlib import Path

from app import online_intel
from app.database import AnalysisDatabase


def _payload() -> dict:
    return {
        "iocs": [
            {"type": "url", "normalized_value": "https://example.org/path"},
            {"type": "domain", "normalized_value": "example.org"},
            {"type": "ipv4", "normalized_value": "8.8.8.8"},
        ],
        "attachments": [{"hashes": {"sha256": "a" * 64}}],
        "tool_reports": [],
    }


def test_disabled_query_types_never_reach_any_provider(tmp_path: Path, monkeypatch) -> None:
    online_intel.save_settings(tmp_path, {
        "online_intelligence": True,
        "query_urls": False,
        "query_domains": False,
        "query_ips": False,
        "query_hashes": False,
        "abusech_auth_key": "configured",
        "urlscan_api_key": "configured",
        "virustotal_api_key": "configured",
        "otx_api_key": "configured",
        "abuseipdb_api_key": "configured",
    })
    requests: list[tuple[str, str]] = []
    monkeypatch.setattr(online_intel, "internet_available", lambda: True)
    monkeypatch.setattr(
        online_intel,
        "_request",
        lambda method, url, **kwargs: requests.append((method, url)),
    )

    enriched = online_intel.enrich(_payload(), tmp_path)

    assert requests == []
    provider_reports = {item["tool_id"]: item for item in enriched["tool_reports"]}
    assert provider_reports["urlhaus"]["status"] == "skipped"
    assert provider_reports["threatfox"]["status"] == "skipped"
    assert provider_reports["malwarebazaar"]["status"] == "skipped"
    assert provider_reports["urlscan"]["status"] == "skipped"
    assert provider_reports["circl_hashlookup"]["status"] == "skipped"
    assert provider_reports["virustotal"]["status"] == "skipped"
    assert provider_reports["otx"]["status"] == "skipped"
    assert provider_reports["abuseipdb"]["status"] == "skipped"


def test_url_permission_does_not_leak_other_indicator_types(tmp_path: Path, monkeypatch) -> None:
    online_intel.save_settings(tmp_path, {
        "online_intelligence": True,
        "query_urls": True,
        "query_domains": False,
        "query_ips": False,
        "query_hashes": False,
        "abusech_auth_key": "configured",
        "virustotal_api_key": "configured",
        "otx_api_key": "configured",
        "abuseipdb_api_key": "configured",
    })
    requests: list[tuple[str, str, dict]] = []

    class Response:
        def json(self) -> dict:
            return {"query_status": "no_results"}

    def fake_request(method: str, url: str, **kwargs):
        requests.append((method, url, kwargs))
        return Response(), 1

    monkeypatch.setattr(online_intel, "internet_available", lambda: True)
    monkeypatch.setattr(online_intel, "_request", fake_request)

    online_intel.enrich(_payload(), tmp_path)

    assert len(requests) == 1
    assert "urlhaus" in requests[0][1]
    assert requests[0][2]["data"] == {"url": "https://example.org/path"}
    assert requests[0][2]["headers"] == {"Auth-Key": "configured"}


def test_abusech_providers_are_unavailable_without_shared_auth_key(tmp_path: Path, monkeypatch) -> None:
    online_intel.save_settings(tmp_path, {
        "online_intelligence": True,
        "query_urls": True,
        "query_domains": True,
        "query_ips": True,
        "query_hashes": True,
    })
    requests: list[tuple[str, str]] = []
    monkeypatch.setattr(online_intel, "internet_available", lambda: True)
    monkeypatch.setattr(online_intel, "_request", lambda method, url, **kwargs: requests.append((method, url)))

    enriched = online_intel.enrich(_payload(), tmp_path)

    assert all("abuse.ch" not in url for _, url in requests)
    reports = {item["tool_id"]: item for item in enriched["tool_reports"]}
    for provider in ("urlhaus", "threatfox", "malwarebazaar"):
        assert reports[provider]["status"] == "unavailable"
        assert "Auth-Key" in reports[provider]["summary"]


def test_urlscan_searches_existing_results_without_submitting_urls(tmp_path: Path, monkeypatch) -> None:
    online_intel.save_settings(tmp_path, {
        "online_intelligence": True,
        "query_urls": False,
        "query_domains": True,
        "query_ips": False,
        "query_hashes": False,
        "urlscan_api_key": "urlscan-key",
    })
    requests: list[tuple[str, str, dict]] = []

    class Response:
        def json(self) -> dict:
            return {"results": [{"verdicts": {"malicious": True}}]}

    def fake_request(method: str, url: str, **kwargs):
        requests.append((method, url, kwargs))
        return Response(), 1

    monkeypatch.setattr(online_intel, "internet_available", lambda: True)
    monkeypatch.setattr(online_intel, "_request", fake_request)

    enriched = online_intel.enrich(_payload(), tmp_path)

    assert len(requests) == 1
    method, url, kwargs = requests[0]
    assert method == "GET"
    assert url == "https://urlscan.io/api/v1/search/"
    assert "/scan/" not in url
    assert kwargs["headers"] == {"API-Key": "urlscan-key"}
    assert kwargs["params"]["q"] == "page.domain:example.org AND date:>now-90d"
    report = next(item for item in enriched["tool_reports"] if item["tool_id"] == "urlscan")
    assert report["status"] == "suspicious"
    assert report["metrics"]["submissions"] == 0


def test_circl_hashlookup_adds_known_file_context_without_calling_it_malware(tmp_path: Path, monkeypatch) -> None:
    online_intel.save_settings(tmp_path, {
        "online_intelligence": True,
        "query_urls": False,
        "query_domains": False,
        "query_ips": False,
        "query_hashes": True,
    })
    requests: list[tuple[str, str, dict]] = []

    class Response:
        def json(self) -> dict:
            return {"hashlookup:trust": 80, "source": "NSRL", "FileName": "known-file.dll"}

    def fake_request(method: str, url: str, **kwargs):
        requests.append((method, url, kwargs))
        return Response(), 1

    monkeypatch.setattr(online_intel, "internet_available", lambda: True)
    monkeypatch.setattr(online_intel, "_request", fake_request)

    enriched = online_intel.enrich(_payload(), tmp_path)

    assert requests == [("GET", f"https://hashlookup.circl.lu/lookup/sha256/{'a' * 64}", {"headers": {"Accept": "application/json"}})]
    report = next(item for item in enriched["tool_reports"] if item["tool_id"] == "circl_hashlookup")
    assert report["status"] == "info"
    assert report["metrics"]["known"] == 1
    assert "malicious" not in report["summary"].lower()


def test_private_iocs_are_blocked_and_public_urls_are_sanitized(tmp_path: Path, monkeypatch) -> None:
    online_intel.save_settings(tmp_path, {
        "online_intelligence": True,
        "query_urls": True,
        "query_domains": False,
        "query_ips": False,
        "query_hashes": False,
        "abusech_auth_key": "configured",
    })
    requests: list[tuple[str, str, dict]] = []

    class Response:
        def json(self) -> dict:
            return {"query_status": "no_results"}

    def fake_request(method: str, url: str, **kwargs):
        requests.append((method, url, kwargs))
        return Response(), 1

    monkeypatch.setattr(online_intel, "internet_available", lambda: True)
    monkeypatch.setattr(online_intel, "_request", fake_request)
    payload = {
        "iocs": [
            {
                "type": "url",
                "normalized_value": "https://user:password@example.org/reset?token=secret#account",
                "classification": {"is_safe_to_query": True},
            },
            {
                "type": "url",
                "normalized_value": "http://127.0.0.1/admin?token=private",
                "classification": {"is_safe_to_query": False},
            },
            {
                "type": "url",
                "normalized_value": "http://mail.internal/login?session=private",
                "classification": {"is_safe_to_query": False},
            },
        ],
        "attachments": [],
        "tool_reports": [],
    }

    enriched = online_intel.enrich(payload, tmp_path)

    assert len(requests) == 1
    assert requests[0][2]["data"] == {"url": "https://example.org/reset"}
    request_text = str(requests)
    assert "secret" not in request_text
    assert "password" not in request_text
    assert "127.0.0.1" not in request_text
    assert "mail.internal" not in request_text
    status = next(item for item in enriched["tool_reports"] if item["tool_id"] == "online_status")
    assert status["metrics"]["privacy_filtered"] == 2
    assert status["metrics"]["sanitized_urls"] == 1
    verdict = enriched["intelligence"]["indicator_verdicts"][0]
    assert verdict["value"].endswith("?token=secret#account")
    assert verdict["queried_value"] == "https://example.org/reset"
    assert verdict["verdict"] == "not_found"
    assert all(item["status"] != "clean" for item in enriched["tool_reports"] if item["tool_id"] == "urlhaus")


def test_provider_cache_reuses_sanitized_ioc_without_storing_url_secret(tmp_path: Path, monkeypatch) -> None:
    online_intel.save_settings(tmp_path, {
        "online_intelligence": True,
        "query_urls": True,
        "query_domains": False,
        "query_ips": False,
        "query_hashes": False,
        "abusech_auth_key": "configured",
    })
    requests: list[str] = []

    class Response:
        def json(self) -> dict:
            return {"query_status": "no_results"}

    def fake_request(method: str, url: str, **kwargs):
        requests.append(str(kwargs.get("data", {})))
        return Response(), 1

    monkeypatch.setattr(online_intel, "internet_available", lambda: True)
    monkeypatch.setattr(online_intel, "_request", fake_request)
    payload = {
        "iocs": [{
            "type": "url",
            "normalized_value": "https://example.org/reset?token=never-store-this#private",
            "classification": {"is_safe_to_query": True},
        }],
        "attachments": [],
        "tool_reports": [],
    }

    first = online_intel.enrich(dict(payload), tmp_path)
    second = online_intel.enrich(dict(payload), tmp_path)

    assert len(requests) == 1
    assert second["intelligence"]["indicator_verdicts"][0]["cache"]["hit"] is True
    online_status = next(item for item in second["tool_reports"] if item["tool_id"] == "online_status")
    assert online_status["metrics"]["cache_hits"] == 1
    database_bytes = (tmp_path / "mailscope.db").read_bytes()
    assert b"never-store-this" not in database_bytes
    audit = AnalysisDatabase(tmp_path / "mailscope.db").audit_entries()
    assert any(item["event_type"] == "provider_cache_hit" for item in audit)
    assert all("never-store-this" not in str(item) for item in audit)
    assert first["intelligence"]["file_uploads"] == 0


def test_virustotal_detection_contributes_to_explainable_risk(tmp_path: Path, monkeypatch) -> None:
    online_intel.save_settings(tmp_path, {
        "online_intelligence": True,
        "query_urls": False,
        "query_domains": True,
        "query_ips": False,
        "query_hashes": False,
        "virustotal_api_key": "vt-key",
    })

    class Response:
        def json(self) -> dict:
            return {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0}}}}

    monkeypatch.setattr(online_intel, "internet_available", lambda: True)
    monkeypatch.setattr(online_intel, "_request", lambda method, url, **kwargs: (Response(), 1))
    payload = {"iocs": [{"type": "domain", "normalized_value": "example.org"}], "attachments": [], "findings": [], "tool_reports": []}

    enriched = online_intel.enrich(payload, tmp_path)

    finding = next(item for item in enriched["findings"] if item["tool_id"] == "virustotal")
    assert finding["risk_points"] == 15
    assert enriched["risk"]["score"] == 15
    assert enriched["risk"]["score_breakdown"][0]["source"] == "virustotal"
    assert enriched["intelligence"]["indicator_verdicts"][0]["verdict"] == "suspicious"


def test_otx_pulse_membership_is_context_without_risk_points(tmp_path: Path, monkeypatch) -> None:
    online_intel.save_settings(tmp_path, {
        "online_intelligence": True,
        "query_urls": False,
        "query_domains": True,
        "query_ips": False,
        "query_hashes": False,
        "otx_api_key": "otx-key",
    })

    class Response:
        def json(self) -> dict:
            return {"pulse_info": {"count": 12}}

    monkeypatch.setattr(online_intel, "internet_available", lambda: True)
    monkeypatch.setattr(online_intel, "_request", lambda method, url, **kwargs: (Response(), 1))
    payload = {"iocs": [{"type": "domain", "normalized_value": "example.org"}], "attachments": [], "findings": [], "tool_reports": []}

    enriched = online_intel.enrich(payload, tmp_path)

    report = next(item for item in enriched["tool_reports"] if item["tool_id"] == "otx")
    finding = next(item for item in enriched["findings"] if item["tool_id"] == "otx")
    assert report["status"] == "info"
    assert finding["risk_points"] == 0
    assert enriched["risk"]["score"] == 0
