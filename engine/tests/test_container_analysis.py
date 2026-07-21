from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

from app.container_analysis import expand_nested_attachments
from app.process_isolation import run_contained_json_worker
from app.static_tools import scan_attachment


def _root(path: Path) -> dict:
    return {
        "attachment_id": "att_root",
        "file_name": path.name,
        "stored_path": str(path),
        "detected_type": "ZIP/Office archive",
        "depth": 0,
    }


def test_nested_zip_is_extracted_without_path_traversal(tmp_path: Path) -> None:
    nested_bytes = io.BytesIO()
    with zipfile.ZipFile(nested_bytes, "w", zipfile.ZIP_DEFLATED) as nested:
        nested.writestr("payload.ps1", b"Write-Output 'static only'")
    root = tmp_path / "root.zip"
    with zipfile.ZipFile(root, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../../nested.zip", nested_bytes.getvalue())

    result = expand_nested_attachments([_root(root)], tmp_path / "out")

    assert len(result["artifacts"]) == 2
    first, second = result["artifacts"]
    assert Path(first["stored_path"]).parent == tmp_path / "out"
    assert ".." not in Path(first["stored_path"]).name
    assert second["depth"] == 2
    assert second["parent_attachment_id"] == first["attachment_id"]
    assert "Potentially dangerous embedded attachment extension" in second["static_flags"]


def test_compression_bomb_ratio_is_blocked(tmp_path: Path) -> None:
    root = tmp_path / "bomb.zip"
    with zipfile.ZipFile(root, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("huge.txt", b"A" * (1024 * 1024))

    result = expand_nested_attachments([_root(root)], tmp_path / "out")

    assert result["artifacts"] == []
    assert result["metrics"]["blocked_items"] == 1
    assert result["updates"]["att_root"]["analysis_status"] == "blocked_by_safety_limit"


def test_static_analyzers_run_in_a_contained_worker(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("safe static test", encoding="utf-8")

    result = scan_attachment(sample, "text/script")

    isolation = result["worker_isolation"]
    assert isolation["success"] is True
    assert isolation["metrics"]["wall_timeout_seconds"] == 240
    assert isolation["metrics"]["process_tree"] in {"windows_job_object", "separate_process"}


def test_contained_worker_is_terminated_at_wall_timeout(tmp_path: Path) -> None:
    result = run_contained_json_worker(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_seconds=0.15,
        memory_limit_mb=128,
        cwd=tmp_path,
    )

    assert result["success"] is False
    assert result["timed_out"] is True
    assert result["return_code"] is None
