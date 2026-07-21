import json
from pathlib import Path

from app.analyzer import analyze_eml


def test_unicode_content_survives_json_serialization(tmp_path: Path) -> None:
    sample = tmp_path / "unicode.eml"
    sample.write_bytes(
        (
            "From: Güvenlik <security@example.com>\r\n"
            "To: analyst@example.org\r\n"
            "Subject: =?utf-8?b?VFlOT1JJWCDihpIgSGFmdGFuxLFuIMO2emV0aQ==?=\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
            "Sipariş → doğrulama bağlantısı: https://example.org/özel\r\n"
        ).encode("utf-8")
    )

    result = analyze_eml(sample, tmp_path / "workspace")
    serialized = json.dumps(result.model_dump(by_alias=True), ensure_ascii=False).encode("utf-8")

    assert "→" in serialized.decode("utf-8")
    assert "Güvenlik" in serialized.decode("utf-8")
