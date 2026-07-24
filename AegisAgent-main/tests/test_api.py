from __future__ import annotations

import time
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

from agent_sandbox.main import app


def test_frontend_index_and_assets_are_served() -> None:
    client = TestClient(app)

    response = client.get("/")
    script = client.get("/static/app.js")

    assert response.status_code == 200
    assert "AegisAgent" in response.text
    assert "镜像储备状态" in response.text
    assert script.status_code == 200
    assert "buildProviders" in script.text
    assert "/api/image-reserve" in script.text
    assert "delete_build_image_after_run" in script.text
    assert "agent-sandbox-build:*" in response.text


def test_image_reserve_endpoint_reports_local_cache_status(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_sandbox.main.image_reserve_status",
        lambda: {
            "version": "test",
            "summary": {"local_reserve_ready": 1, "cached_public_fallback_ready": 1, "public_pull_required": 1, "missing_policy": 0},
            "languages": {"python": {"selected_layer": "local_reserve"}},
        },
    )
    client = TestClient(app)

    response = client.get("/api/image-reserve")

    assert response.status_code == 200
    assert response.json()["summary"]["local_reserve_ready"] == 1
    assert response.json()["languages"]["python"]["selected_layer"] == "local_reserve"


def test_upload_run_generates_report_without_llm(tmp_path: Path) -> None:
    zip_path = tmp_path / "agent.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.writestr("repo/main.py", "import os\nprint('hello')\nprint(os.getenv('OPENAI_API_KEY'))\n")

    client = TestClient(app)
    with zip_path.open("rb") as fh:
        response = client.post("/api/runs", files={"file": ("agent.zip", fh, "application/zip")})

    assert response.status_code == 200
    run_id = response.json()["id"]

    for _ in range(30):
        status = client.get(f"/api/runs/{run_id}").json()
        if status["status"] in {"completed", "failed"}:
            break
        time.sleep(0.05)

    report_response = client.get(f"/api/runs/{run_id}/report")
    assert report_response.status_code == 200
    report = report_response.json()
    assert report["llm_status"] == "llm_disabled"
    assert report["profile"]["languages"]
    assert report["dynamic_status"] in {"dynamic_completed", "dynamic_failed", "docker_unavailable", "static_only"}
    assert report["markdown_report"].startswith("# AegisAgent")

    markdown_response = client.get(f"/api/runs/{run_id}/report.md")
    assert markdown_response.status_code == 200
    assert "text/markdown" in markdown_response.headers["content-type"]
    assert "AegisAgent" in markdown_response.text
    assert "attachment" in markdown_response.headers["content-disposition"]
