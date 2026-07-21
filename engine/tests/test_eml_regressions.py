from __future__ import annotations

import os
from email.message import EmailMessage
from pathlib import Path

from app.analyzer import _entropy_is_suspicious, analyze_eml


def test_decoded_mime_urls_pdf_entropy_and_authenticated_reply_to(tmp_path: Path) -> None:
    message = EmailMessage()
    message["From"] = "Billing <billing@notification.example.com>"
    message["To"] = "analyst@example.net"
    message["Reply-To"] = "finance@vendor.example"
    message["Subject"] = "Invoice reminder"
    message["Authentication-Results"] = (
        "mx.example.net; spf=pass smtp.mailfrom=notification.example.com; "
        "dkim=pass header.d=notification.example.com; dmarc=pass header.from=notification.example.com"
    )
    message.set_content("Invoice attached.")
    long_url = "https://links.example.org/click?token=" + ("a" * 180)
    message.add_alternative(
        f"<html><body><a href='{long_url}'>View invoice</a></body></html>",
        subtype="html",
        cte="quoted-printable",
    )
    high_entropy_pdf = b"%PDF-1.7\n" + os.urandom(8192)
    message.add_attachment(
        high_entropy_pdf,
        maintype="application",
        subtype="pdf",
        filename="invoice.pdf",
    )
    eml = tmp_path / "invoice.eml"
    eml.write_bytes(message.as_bytes())

    result = analyze_eml(eml, tmp_path / "workspace")
    urls = [item.normalized_value for item in result.iocs if item.type == "url"]

    assert urls == [long_url]
    assert not any(url.endswith("=") for url in urls)
    assert result.attachments[0].detected_type == "PDF document"
    assert result.attachments[0].static_flags == []
    mismatch = next(item for item in result.findings if item.tool_id == "identity_guard")
    assert mismatch.severity == "medium"
    assert result.risk.score == 15
    identity = next(item for item in result.tool_reports if item.tool_id == "identity_guard")
    assert identity.metrics["authentication_passed"] is False
    assert identity.metrics["authentication_source"] == "unverified_header_claim"


def test_entropy_heuristic_is_type_aware() -> None:
    assert not _entropy_is_suspicious("PDF document", ".pdf", 7.9)
    assert not _entropy_is_suspicious("PNG image", ".png", 7.9)
    assert _entropy_is_suspicious("PE executable", ".exe", 7.9)
    assert _entropy_is_suspicious("unknown", ".bin", 7.9)
