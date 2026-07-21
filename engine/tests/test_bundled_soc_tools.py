from __future__ import annotations

from app.static_tools import tools_status


def test_bundled_soc_tools_have_verified_integrity() -> None:
    status = tools_status(run_versions=False)

    assert set(status) == {"capa", "floss", "exiftool"}
    assert status["capa"]["version"] == "9.4.0"
    assert status["floss"]["version"] == "3.1.1"
    assert status["exiftool"]["version"] == "13.59"
    assert all(tool["available"] for tool in status.values())
    assert all(tool["integrity"] == "verified" for tool in status.values())
