from pathlib import Path

from app import analyzer
from app.analyzer import analyze_eml


def test_analyze_eml(tmp_path: Path) -> None:
    sample = tmp_path / "sample.eml"
    sample.write_text(
        "From: Sender <sender@example.com>\n"
        "To: analyst@company.test\n"
        "Subject: Test message\n"
        "Message-ID: <123@example.com>\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Visit https://example.org/path and contact user@example.org.\n",
        encoding="utf-8",
    )

    result = analyze_eml(sample, tmp_path / "workspace")
    assert result.status == "completed"
    assert result.email.subject == "Test message"
    assert result.email.raw_source_preview.startswith("From: Sender <sender@example.com>")
    assert "https://example.org/path" in result.email.raw_source_preview
    assert any(ioc.type == "url" for ioc in result.iocs)
    assert any(ioc.type == "domain" and ioc.normalized_value == "example.org" for ioc in result.iocs)
    identity = next(report for report in result.tool_reports if report.tool_id == "identity_guard")
    assert identity.metrics["authentication_source"] == "not_verified"


def test_claimed_and_independently_verified_authentication_are_separate(tmp_path: Path, monkeypatch) -> None:
    sample = tmp_path / "auth.eml"
    sample.write_text(
        "From: Sender <sender@example.com>\n"
        "Reply-To: replies@vendor.example\n"
        "To: analyst@example.net\n"
        "Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Authenticated test.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(analyzer, "verify_email_authentication", lambda raw, message: {
        "dkim": {"result": "pass", "signature_count": 1, "valid_domains": ["example.com"]},
        "spf": {"result": "not_verifiable", "client_ip": "", "domain": ""},
        "dmarc": {"result": "pass", "policy": "reject", "policy_domain": "example.com", "dkim_aligned": True, "spf_aligned": False},
        "details": ["Test verification evidence"],
    })

    result = analyzer.analyze_eml(sample, tmp_path / "workspace", revalidate_auth=True)
    reports = {report.tool_id: report for report in result.tool_reports}

    assert reports["auth_headers"].metrics["trust"] == "unverified_header_claim"
    assert reports["auth_verification"].status == "clean"
    assert reports["auth_verification"].metrics["dmarc"] == "pass"
    assert reports["identity_guard"].metrics["authentication_source"] == "independent_dmarc"


def test_only_configured_authserv_id_can_supply_trusted_header_results(tmp_path: Path) -> None:
    sample = tmp_path / "trusted-auth.eml"
    sample.write_text(
        "From: Sender <sender@example.com>\n"
        "Reply-To: replies@vendor.example\n"
        "To: analyst@example.net\n"
        "Authentication-Results: trusted.gateway.example; spf=pass; dkim=pass; dmarc=pass\n"
        "Content-Type: text/plain; charset=utf-8\n\nTrusted gateway test.\n",
        encoding="utf-8",
    )

    untrusted = analyzer.analyze_eml(sample, tmp_path / "untrusted", revalidate_auth=False)
    trusted = analyzer.analyze_eml(
        sample,
        tmp_path / "trusted",
        revalidate_auth=False,
        trusted_authserv_ids=["trusted.gateway.example"],
    )

    untrusted_identity = next(item for item in untrusted.tool_reports if item.tool_id == "identity_guard")
    trusted_identity = next(item for item in trusted.tool_reports if item.tool_id == "identity_guard")
    assert untrusted_identity.metrics["authentication_source"] == "unverified_header_claim"
    assert trusted_identity.metrics["authentication_source"] == "trusted_gateway"
    assert untrusted.risk.score == 15
    assert trusted.risk.score == 5
