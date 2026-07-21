from __future__ import annotations

from pathlib import Path

from app.static_tools import yara_scan


def test_managed_yara_pack_loads_and_detects_encoded_powershell(tmp_path: Path) -> None:
    sample = tmp_path / "payload.ps1"
    sample.write_text("powershell.exe -EncodedCommand SQBFAFgA", encoding="utf-8")

    result = yara_scan(sample)
    names = {match["rule"] for match in result["matches"]}

    assert result["available"] is True
    assert result["metrics"]["rules_loaded"] >= 17
    assert result["metrics"]["rule_files"] >= 4
    assert result["metrics"]["ruleset_version"] == "2026.07.1"
    assert "Script_PowerShell_Encoded_Command" in names


def test_managed_yara_pack_does_not_flag_plain_pdf(tmp_path: Path) -> None:
    sample = tmp_path / "plain.pdf"
    sample.write_bytes(b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF")

    result = yara_scan(sample)

    assert result["available"] is True
    assert result["matches"] == []
