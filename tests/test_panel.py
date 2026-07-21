"""Contract tests for the firmware-facing panel API.

These pin the behaviours the real panel depends on: both trailing-slash
spellings, the MAC allowlist on /api/setup, the Access-Token check on
/api/display, unguessable image paths, and a token-gated browser preview.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

os.environ.setdefault("TRMNL_DB_PATH", "/tmp/trmnl-test-panel/trmnl.db")

from trmnl_server import config as config_module  # noqa: E402
from trmnl_server.config import Config  # noqa: E402
from trmnl_server.main import create_app  # noqa: E402
from trmnl_server import models  # noqa: E402

MAC = "E0:72:A1:FA:42:F0"
TOKEN = "test-token"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = tmp_path / "trmnl.db"
    monkeypatch.setattr(config_module, "DATABASE_PATH", str(db))
    models.init_db()

    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)
    cfg = Config()
    cfg.state_dir = str(tmp_path / "frames")
    cfg.allowed_devices = ["e072a1fa42f0"]
    cfg.token_file = str(token_file)
    cfg.base_url = "https://trmnl.example"
    cfg.synthetic = True
    with TestClient(create_app(cfg)) as c:
        yield c


def test_healthz(client):
    assert client.get("/healthz").status_code == 200


@pytest.mark.parametrize("path", ["/api/setup", "/api/setup/"])
def test_setup_both_slash_forms(client, path):
    resp = client.get(path, headers={"ID": MAC})
    assert resp.status_code == 200
    body = resp.json()
    assert body["api_key"] == TOKEN
    assert body["friendly_id"] == "FA42F0"


def test_setup_rejects_unknown_device(client):
    resp = client.get("/api/setup/", headers={"ID": "11:22:33:44:55:66"})
    assert resp.status_code == 403


def test_display_requires_token(client):
    resp = client.get("/api/display", headers={"ID": MAC})
    assert resp.status_code == 401


def test_display_rejects_unknown_device(client):
    resp = client.get(
        "/api/display",
        headers={"ID": "11:22:33:44:55:66", "Access-Token": TOKEN},
    )
    assert resp.status_code == 403


def test_display_cycle_serves_1bit_bmp(client):
    resp = client.get(
        "/api/display", headers={"ID": MAC, "Access-Token": TOKEN}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["refresh_rate"] == 1800
    name = body["filename"]
    assert body["image_url"] == f"https://trmnl.example/image/{name}"

    img = client.get(f"/image/{name}")
    assert img.status_code == 200
    assert img.headers["content-type"] == "image/bmp"
    from io import BytesIO

    frame = Image.open(BytesIO(img.content))
    assert frame.mode == "1"
    assert frame.size == (800, 480)


def test_image_route_rejects_predictable_paths(client):
    assert client.get("/image/screen.bmp").status_code == 404
    assert client.get("/image/screen-001-deadbeef.bmp").status_code == 404


def test_battery_headers_recorded(client):
    resp = client.get(
        "/api/display",
        headers={
            "ID": MAC,
            "Access-Token": TOKEN,
            "Battery-Voltage": "3.892",
            "RSSI": "-62",
        },
    )
    assert resp.status_code == 200
    history = models.get_battery_history(limit=1)
    assert history and history[0].voltage == pytest.approx(3.892)
    assert history[0].rssi == -62


def test_log_endpoint_accepts_both_spellings(client):
    assert client.post("/api/log", content=b"{}").status_code == 204
    assert client.post("/api/logs/", content=b"{}").status_code == 204


def test_preview_requires_token(client):
    assert client.get("/preview/readiness.png").status_code == 401


def test_preview_renders_png(client):
    resp = client.get(
        "/preview/readiness.png", headers={"Access-Token": TOKEN}
    )
    assert resp.status_code == 200
    from io import BytesIO

    frame = Image.open(BytesIO(resp.content))
    assert frame.size == (800, 480)


def test_preview_unknown_screen_404s(client):
    resp = client.get(
        "/preview/nope.png", headers={"Access-Token": TOKEN}
    )
    assert resp.status_code == 404
    assert "readiness" in resp.json()["screens"]
