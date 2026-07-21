from __future__ import annotations

import base64
from email import policy
from email.parser import BytesParser

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.auth_verifier import _evaluate_dmarc, _verify_dkim, _verify_spf


def _signed_message() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = (
        b"From: sender@example.com\r\n"
        b"To: analyst@example.net\r\n"
        b"Subject: Signed message\r\n"
        b"Date: Sun, 19 Jul 2026 12:00:00 +0000\r\n"
        b"Message-ID: <signed@example.com>\r\n"
        b"\r\n"
        b"Original body\r\n"
    )
    signature = dkim.sign(
        raw,
        selector=b"mailscope",
        domain=b"example.com",
        privkey=private_pem,
        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"],
    )
    record = b"v=DKIM1; k=rsa; p=" + base64.b64encode(public_der)
    return signature + raw, record


def test_dkim_is_cryptographically_verified_and_body_changes_fail() -> None:
    signed, record = _signed_message()

    def dnsfunc(name: bytes, timeout: int = 3) -> bytes | None:
        assert name == b"mailscope._domainkey.example.com."
        return record

    message = BytesParser(policy=policy.default).parsebytes(signed)
    passed = _verify_dkim(signed, message, dnsfunc)
    tampered = signed.replace(b"Original body", b"Tampered body")
    failed = _verify_dkim(tampered, BytesParser(policy=policy.default).parsebytes(tampered), dnsfunc)

    assert passed["result"] == "pass"
    assert passed["valid_domains"] == ["example.com"]
    assert failed["result"] == "fail"


def test_spf_revalidation_requires_recorded_smtp_evidence() -> None:
    raw = (
        b"From: sender@example.com\r\n"
        b"Return-Path: <bounce@example.com>\r\n"
        b"Received-SPF: pass; client-ip=203.0.113.9; envelope-from=bounce@example.com; helo=mail.example.com\r\n\r\n"
    )
    message = BytesParser(policy=policy.default).parsebytes(raw)
    calls = []

    def checker(**kwargs):
        calls.append(kwargs)
        return "pass", "authorized sender"

    result = _verify_spf(message, checker)
    missing = _verify_spf(BytesParser(policy=policy.default).parsebytes(b"From: sender@example.com\r\n\r\n"), checker)

    assert result["result"] == "pass"
    assert result["domain"] == "example.com"
    assert calls[0]["i"] == "203.0.113.9"
    assert missing["result"] == "not_verifiable"


def test_dmarc_requires_alignment_and_uses_dns_tree_walk() -> None:
    records = {
        "_dmarc.a.example.com": [],
        "_dmarc.b.example.com": [],
        "_dmarc.example.com": ["v=DMARC1; p=reject; adkim=r; aspf=r"],
    }
    lookup = lambda name: records.get(name, [])
    dkim_result = {"result": "pass", "valid_domains": ["b.example.com"]}
    spf_result = {"result": "fail", "domain": "other.test"}

    passed = _evaluate_dmarc("a.example.com", dkim_result, spf_result, lookup)
    failed = _evaluate_dmarc("a.example.com", {"result": "fail", "valid_domains": []}, spf_result, lookup)

    assert passed["result"] == "pass"
    assert passed["dkim_aligned"] is True
    assert passed["policy"] == "reject"
    assert failed["result"] == "fail"


def test_dmarc_strict_alignment_rejects_subdomain_difference() -> None:
    lookup = lambda name: ["v=DMARC1; p=reject; adkim=s; aspf=s"] if name == "_dmarc.example.com" else []
    result = _evaluate_dmarc(
        "example.com",
        {"result": "pass", "valid_domains": ["mail.example.com"]},
        {"result": "pass", "domain": "bounce.example.com"},
        lookup,
    )

    assert result["result"] == "fail"
    assert result["dkim_aligned"] is False
    assert result["spf_aligned"] is False
