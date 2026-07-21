from __future__ import annotations

from pathlib import Path

from app.database import AnalysisDatabase
from app.main import export_analysis


def test_html_report_contains_tool_metrics_and_escaped_details(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("MAILSCOPE_DATA_DIR", str(tmp_path))
    AnalysisDatabase(tmp_path / "mailscope.db").save({
        "analysis_id": "anl_report",
        "created_at": "2026-07-19T00:00:00+00:00",
        "status": "completed",
        "source": {"file_name": "sample.eml", "sha256": "a" * 64},
        "email": {"subject": "Report test", "from": {"address": "sender@example.org"}},
        "risk": {"score": 10, "level": "low", "coverage": "medium"},
        "findings": [],
        "iocs": [],
        "tool_reports": [{
            "tool_id": "urlhaus",
            "name": "URLhaus",
            "status": "clean",
            "summary": "Checked one URL.",
            "metrics": {"queried": 1, "listed": 0},
            "details": ["Literal <script>alert(1)</script> evidence"],
        }],
    })
    output = tmp_path / "report.html"

    assert export_analysis("anl_report", str(output), "html") == 0
    document = output.read_text(encoding="utf-8")

    assert "Queried:" in document
    assert "<summary>Details</summary>" in document
    assert "Literal &lt;script&gt;alert(1)&lt;/script&gt; evidence" in document
    assert "Literal <script>" not in document
    assert "Why this verdict" in document
    assert "Analysis coverage: MEDIUM" in document
    assert "does not prove that an indicator is safe" in document
    assert "Recommended analyst actions" in document
    assert "Risk score breakdown" in document
    assert "Attachment inventory" in document
    assert "Prioritized indicators" in document
    assert "@media print" in document
