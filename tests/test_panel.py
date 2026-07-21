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

from trmnl_server import config as config_module  # noqa: E402
from trmnl_server.config import Config  # noqa: E402
from trmnl_server.main import create_app  # noqa: E402
from trmnl_server import models  # noqa: E402

MAC = "E0:72:A1:FA:42:F0"
TOKEN = "test-token"
UI_TOKEN = "test-ui-token"


def _reset_process_state() -> None:
    """Clear the module-global rotation/plugin caches between apps.

    `services.state` is process-global and the plugin scheduler caches
    `PluginOutput` paths in it. Production runs one app per process, but the
    suite builds several, and pytest keeps the last few tmp_path trees alive
    — so a stale cache entry whose files still exist on disk passes the
    scheduler's `_assets_exist()` staleness check, the plugin never re-runs
    under the new generated root, and `path_to_web_url()` returns None for
    every rotation entry. Cheaper to reset than to make the cache
    root-aware.
    """
    from trmnl_server.services import state as state_module

    with state_module.STATE_LOCK:
        state_module.global_state['plugins'] = {}
        state_module.global_state['rotation_master'] = {
            'bmp_entries': [],
            'png_entries': [],
            'hashes': [],
            'meta': [],
            'selected_ids': [],
            'version': 0,
            'has_persistent_playlist': False,
        }
        state_module.global_state['devices'] = {}
        state_module.global_state['device_playlists'] = {}
        state_module.global_state['named_playlists'] = {}
        state_module.global_state['device_playlist_bindings'] = {}
        # Profiles are cached in front of SQLite, and each test gets a fresh
        # database — so without this a refresh_interval written by one test
        # is still in memory for the next one, whose DB has never seen it.
        state_module.global_state['device_profiles'] = {}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # pin_database_path, not a plain assignment: create_app() calls
    # pin_generated_assets_dir(), which refreshes every path constant and
    # would otherwise recompute DATABASE_PATH back to $PWD/var/db.
    config_module.pin_database_path(str(tmp_path / "trmnl.db"))
    models.init_db()
    _reset_process_state()

    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)
    ui_token_file = tmp_path / "ui-token"
    ui_token_file.write_text(UI_TOKEN)
    cfg = Config()
    cfg.state_dir = str(tmp_path / "frames")
    cfg.allowed_devices = ["e072a1fa42f0"]
    cfg.token_file = str(token_file)
    cfg.ui_token_file = str(ui_token_file)
    cfg.base_url = "https://trmnl.example"
    cfg.synthetic = True
    # Same origin as cfg.base_url, and https: the session cookie carries
    # Secure whenever the deployment is TLS, so an http test client would
    # silently drop it and every control-plane test would pass for the wrong
    # reason.
    with TestClient(create_app(cfg), base_url="https://trmnl.example") as c:
        yield c


@pytest.fixture()
def ui_client(client):
    """A client holding a valid control-plane session cookie."""
    resp = client.post("/auth/session", json={"token": UI_TOKEN})
    assert resp.status_code == 204
    return client


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


def test_log_endpoint_rejects_oversized_body(client):
    from trmnl_server.routes import panel as panel_routes

    body = b"x" * (panel_routes._LOG_MAX_BODY + 1)
    assert client.post("/api/log", content=body).status_code == 413


def test_log_endpoint_truncates_what_it_persists(client):
    from trmnl_server.routes import panel as panel_routes

    body = b"y" * (panel_routes._LOG_MAX_BODY - 1)
    assert client.post("/api/log", content=body).status_code == 204
    stored = models.get_logs(limit=1)[-1]
    assert len(stored.info) == panel_routes._LOG_MAX_STORED


def test_log_endpoint_rate_limits_per_device(client):
    from trmnl_server.routes import panel as panel_routes

    panel_routes._log_buckets.clear()
    headers = {"ID": MAC}
    accepted = 0
    for _ in range(panel_routes._LOG_RATE_LIMIT + 5):
        resp = client.post("/api/log", content=b"spam", headers=headers)
        if resp.status_code == 204:
            accepted += 1
        else:
            assert resp.status_code == 429
    assert accepted == panel_routes._LOG_RATE_LIMIT
    panel_routes._log_buckets.clear()


def test_log_table_is_row_capped(client, monkeypatch):
    """An unauthenticated writer must not be able to grow the table forever."""
    monkeypatch.setattr(models, "LOG_ROW_CAP", 40)
    monkeypatch.setattr(models, "_LOG_TRIM_SLACK", 10)
    for i in range(300):
        models.add_log_entry("test", f"entry {i}")
    with models.SessionLocal() as db:
        from sqlalchemy import func, select as sa_select

        total = db.execute(
            sa_select(func.count()).select_from(models.LogEntry)
        ).scalar_one()
    assert total <= 40 + 10
    # Oldest-first eviction: the newest entry survives, the first does not.
    infos = [entry.info for entry in models.get_logs(limit=200)]
    assert "entry 299" in infos
    assert "entry 0" not in infos


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


# --- F1: the log DB must never republish a capability ----------------------


def test_display_log_entry_omits_the_frame_nonce(ui_client):
    """The frame name is the only thing guarding /image/<name>.

    The firmware fetches that URL with no auth header, so an unguessable
    path is the whole capability. If /api/display writes it into the `logs`
    table, two requests — read the log, fetch the frame — yield the panel's
    health data anonymously.
    """
    resp = ui_client.get("/api/display", headers={"ID": MAC, "Access-Token": TOKEN})
    name = resp.json()["filename"]
    assert name  # sanity: there is a nonce to leak

    text = ui_client.get("/server/log?limit=200").text
    assert name not in text
    assert ".bmp" not in text
    # The useful half is still there.
    assert "screen=readiness" in text


def test_log_entries_do_not_carry_the_full_mac(ui_client):
    """The MAC is the credential /api/setup checks; the log gets a handle."""
    ui_client.get("/api/setup", headers={"ID": MAC})
    ui_client.get("/api/display", headers={"ID": MAC, "Access-Token": TOKEN})
    text = ui_client.get("/server/log?limit=200").text
    assert "e072a1fa42f0" not in text.lower()
    assert MAC.lower() not in text.lower()
    assert "FA42F0" in text  # the friendly handle survives


# --- F2/F5: the control plane is app-authenticated -------------------------


CONTROL_PLANE_READS = [
    "/rotation",
    "/devices",
    "/devices/default",
    "/server/log",
    "/server/battery",
    "/status",
]

CONTROL_PLANE_WRITES = [
    ("POST", "/rotation", {"playlist": []}),
    ("POST", "/playlists", {"name": "x", "playlist": []}),
    ("DELETE", "/playlists/x", None),
    ("DELETE", "/rotation/somedevice", None),
    ("PATCH", "/devices/default", {"friendly_name": "x"}),
]


@pytest.mark.parametrize("path", CONTROL_PLANE_READS)
def test_control_plane_reads_require_a_session(client, path):
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("method,path,body", CONTROL_PLANE_WRITES)
def test_control_plane_writes_require_a_session(client, method, path, body):
    resp = client.request(method, path, json=body)
    assert resp.status_code == 401


@pytest.mark.parametrize("path", CONTROL_PLANE_READS)
def test_control_plane_reads_succeed_with_a_session(ui_client, path):
    assert ui_client.get(path).status_code == 200


def test_session_mint_rejects_a_wrong_token(client):
    assert client.post("/auth/session", json={"token": "nope"}).status_code == 401
    assert client.post("/auth/session").status_code == 401
    assert client.get("/rotation").status_code == 401


def test_session_mint_accepts_the_header_form(client):
    resp = client.post("/auth/session", headers={"X-TRMNL-UI-Token": UI_TOKEN})
    assert resp.status_code == 204
    assert client.get("/rotation").status_code == 200


def test_panel_access_token_is_not_a_control_plane_credential(client):
    """The two secrets must not be interchangeable in either direction."""
    assert client.post("/auth/session", json={"token": TOKEN}).status_code == 401
    assert client.get("/status", headers={"Access-Token": TOKEN}).status_code == 401


def test_session_cookie_attributes(client):
    resp = client.post("/auth/session", json={"token": UI_TOKEN})
    cookie = resp.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "secure" in cookie  # base_url is https:// in the fixture


def test_session_can_be_cleared(ui_client):
    assert ui_client.get("/rotation").status_code == 200
    assert ui_client.delete("/auth/session").status_code == 204
    assert ui_client.get("/rotation").status_code == 401


def test_rotating_the_ui_secret_invalidates_sessions(ui_client, tmp_path):
    from trmnl_server.config import panel_config

    assert ui_client.get("/rotation").status_code == 200
    with open(panel_config().ui_token_file, "w", encoding="utf-8") as fh:
        fh.write("a-different-secret")
    assert ui_client.get("/rotation").status_code == 401


def test_cross_origin_write_is_refused(ui_client):
    """CSRF layer 2: Origin/Sec-Fetch-Site pinning on mutating methods."""
    resp = ui_client.post(
        "/rotation",
        json={"playlist": []},
        headers={"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"},
    )
    assert resp.status_code == 403
    resp = ui_client.post(
        "/rotation",
        json={"playlist": []},
        headers={"Origin": "https://trmnl.example", "Sec-Fetch-Site": "same-origin"},
    )
    assert resp.status_code == 200


def test_no_cors_middleware_is_installed(client):
    """Its absence is load-bearing — see the comment in main.py."""
    names = {type(m.cls).__name__ for m in client.app.user_middleware}
    names |= {getattr(m.cls, "__name__", "") for m in client.app.user_middleware}
    assert "CORSMiddleware" not in names


def test_refresh_interval_is_clamped(ui_client):
    """Even a valid session must not be able to destroy the battery."""
    for bad in (1, 30, 86400, 21601):
        resp = ui_client.patch(f"/devices/{MAC}", json={"refresh_interval": bad})
        assert resp.status_code == 400, bad
    ok = ui_client.patch(f"/devices/{MAC}", json={"refresh_interval": 900})
    assert ok.status_code == 200
    assert ok.json()["profile"]["refresh_interval"] == 900


# --- F3: /generated is an allowlist, not a directory -----------------------


def test_generated_static_mount_is_gone(client):
    """A future re-mount must fail CI rather than quietly re-open the tree."""
    names = {getattr(route, "name", None) for route in client.app.routes}
    assert "generated-static" not in names


def test_generated_serves_current_rotation_members(ui_client):
    entries = ui_client.get("/rotation").json()["entries"]
    assert entries, "the lifespan render should have produced a rotation entry"
    url_png = entries[0]["url_png"]
    assert url_png.startswith("/generated/")
    resp = ui_client.get(url_png)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/png"

    resp_bmp = ui_client.get(entries[0]["url_bmp"])
    assert resp_bmp.status_code == 200
    assert resp_bmp.headers["content-type"] == "image/bmp"


def test_generated_refuses_anything_not_in_the_rotation(client):
    assert client.get("/generated/garmin/nothing.png").status_code == 404
    assert client.get("/generated/../trmnl.db").status_code == 404
    assert client.get("/generated/trmnl.db").status_code == 404
    assert client.get("/generated/garmin/readiness.png/../../trmnl.db").status_code == 404


# --- LATENT: nothing but the device surface may live under /api/ -----------


def test_only_known_device_routes_live_under_api(client):
    from trmnl_server.main import _DEVICE_API_PATHS

    under_api = {
        route.path
        for route in client.app.routes
        if getattr(route, "path", "").startswith("/api/")
    }
    assert under_api <= _DEVICE_API_PATHS
    # And the device surface is actually registered, so this cannot pass by
    # the routes having silently disappeared.
    assert {"/api/setup", "/api/setup/", "/api/display"} <= under_api


def test_registering_a_control_plane_route_under_api_fails_the_build(client):
    """The comment "do not put a browser endpoint under /api/" is executable."""
    from fastapi import APIRouter

    from trmnl_server.main import _assert_route_invariants

    stray = APIRouter()

    @stray.get("/api/rotation")
    def _stray():  # pragma: no cover - never called
        return {}

    client.app.include_router(stray)
    with pytest.raises(RuntimeError, match="registered under /api/"):
        _assert_route_invariants(client.app)


# --- A: the device-log body cap must fit a real firmware batch -------------


def _firmware_log_note(log_id: int, message: str) -> str:
    """One entry of firmware 1.5.12's `logs_array`, envelope and all.

    Shape taken from usetrmnl/trmnl-firmware v1.5.12 `submitLog()`: a
    `device_status_stamp` block plus the note's own fields. The envelope is
    ~325 B, which is what makes a 10-note batch of long messages ~13.8 KB.
    """
    return (
        '{"creation_timestamp":1718000000,'
        '"device_status_stamp":{"wifi_status":"connected",'
        '"wakeup_reason":"timer","current_fw_version":"1.5.12",'
        '"special_function":"sleep","refresh_rate":1800,'
        '"time_since_last_sleep_start":1800,"battery_voltage":3.89,'
        '"wifi_rssi_level":-62,"free_heap_size":123456,'
        '"max_alloc_size":98304,"wakeup_reason_code":4,'
        '"filesystem_ok":true,"battery_percent":74},'
        f'"log_id":{log_id},"log_message":"{message}",'
        '"log_codeline":1991,"log_sourcefile":"src/bl.cpp",'
        '"log_retry":1,"additional_info":{"retry_attempt":1,'
        '"filename_new":"","filename_current":""}}'
    )


def _firmware_log_batch(message_len: int, notes: int = 10) -> bytes:
    """The single body `submitStoredLogs()` posts for a batch of `notes`."""
    joined = ",".join(
        _firmware_log_note(i, "E" * message_len) for i in range(notes)
    )
    return ('{"log":{"logs_array":[' + joined + "]}}").encode("utf-8")


def test_log_endpoint_accepts_a_full_firmware_batch(client):
    """10 notes x a full char[1024] message is real post-outage traffic.

    LOG_MAX_NOTES_NUMBER is 10 and the NVS store is only cleared on a
    successful submit, so a 413 here is permanent: the device re-posts the
    same oversized batch forever.
    """
    from trmnl_server.routes import panel as panel_routes

    panel_routes._log_buckets.clear()
    body = _firmware_log_batch(1023)
    assert 13000 <= len(body) <= panel_routes._LOG_MAX_BODY, len(body)
    assert client.post("/api/log", content=body).status_code == 204


def test_log_endpoint_still_rejects_an_absurd_body(client):
    from trmnl_server.routes import panel as panel_routes

    panel_routes._log_buckets.clear()
    body = b"x" * (1024 * 1024)
    assert client.post("/api/log", content=body).status_code == 413
    # Chunked / lying Content-Length takes the streaming path, same answer.
    assert client.post(
        "/api/log", content=iter([b"x" * 8192] * 32)
    ).status_code == 413


# --- B: the refresh clamp holds on READ, not only on write ----------------


def test_display_clamps_a_hostile_row_written_straight_into_the_db(client):
    """A row that never passed PATCH must still not reach the panel.

    The write-side check only ever sees values that arrive through it. This
    writes 1 second directly into `device_profiles`, exactly as a skeptic
    with the SQLite file (or an older build whose PATCH was unauthenticated)
    would, and asserts the panel is not told to poll every second.
    """
    from trmnl_server.config import MIN_REFRESH_INTERVAL
    from trmnl_server.services import state as state_module

    device_id = MAC
    models.update_device_profile(device_id, refresh_interval=1)
    with state_module.STATE_LOCK:
        state_module.global_state.get('device_profiles', {}).pop(device_id, None)
    state_module.refresh_device_profile(device_id)
    assert models.get_device_profile(device_id)["refresh_interval"] == 1

    resp = client.get(
        "/api/display", headers={"ID": MAC, "Access-Token": TOKEN}
    )
    assert resp.status_code == 200
    assert resp.json()["refresh_rate"] == MIN_REFRESH_INTERVAL


def test_display_clamps_an_absurdly_long_interval(client):
    from trmnl_server.config import MAX_REFRESH_INTERVAL
    from trmnl_server.services import state as state_module

    models.update_device_profile(MAC, refresh_interval=86400)
    state_module.refresh_device_profile(MAC)
    resp = client.get(
        "/api/display", headers={"ID": MAC, "Access-Token": TOKEN}
    )
    assert resp.json()["refresh_rate"] == MAX_REFRESH_INTERVAL


def test_display_honours_an_in_range_interval(client):
    """The clamp must not flatten the knob it is protecting."""
    from trmnl_server.services import state as state_module

    models.update_device_profile(MAC, refresh_interval=900)
    state_module.refresh_device_profile(MAC)
    resp = client.get(
        "/api/display", headers={"ID": MAC, "Access-Token": TOKEN}
    )
    assert resp.json()["refresh_rate"] == 900


# --- C: a non-ASCII credential is a 401, never a 500 ----------------------


NON_ASCII = "café-ÿ-中文"
# Header values have to go on the wire as raw bytes: httpx refuses to encode
# a non-ASCII `str` into a header, while a real client just sends the bytes
# and Starlette decodes them latin-1 into exactly the non-ASCII `str` that
# `hmac.compare_digest` refuses to compare.
NON_ASCII_HEADER = NON_ASCII.encode("utf-8")


def test_non_ascii_access_token_is_rejected_not_a_500(client):
    """`hmac.compare_digest` raises TypeError on non-ASCII str.

    /api/* bypasses the edge's SSO, so this is reachable from the open
    internet: it must be a 401, not an unhandled exception.
    """
    resp = client.get(
        "/api/display", headers={"ID": MAC, "Access-Token": NON_ASCII_HEADER}
    )
    assert resp.status_code == 401


def test_non_ascii_access_token_on_preview_is_rejected(client):
    resp = client.get(
        "/preview/readiness.png", headers={"Access-Token": NON_ASCII_HEADER}
    )
    assert resp.status_code == 401


def test_non_ascii_ui_token_is_rejected_not_a_500(client):
    assert client.post(
        "/auth/session", json={"token": NON_ASCII}
    ).status_code == 401
    assert client.post(
        "/auth/session", headers={"X-TRMNL-UI-Token": NON_ASCII_HEADER}
    ).status_code == 401


def test_lone_surrogate_ui_token_is_rejected_not_a_500(client):
    """What a JSON body can decode to, and what utf-8 refuses to encode."""
    resp = client.post(
        "/auth/session",
        content=b'{"token": "\\ud800"}',
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_non_ascii_session_cookie_is_rejected_not_a_500(client):
    resp = client.get(
        "/rotation",
        headers={"Cookie": "trmnl_ui=v1.9999999999.aabbccdd.caf\xc3\xa9".encode("latin-1")},
    )
    assert resp.status_code == 401


def test_secret_equal_never_raises():
    from trmnl_server.credentials import secret_equal

    assert secret_equal("a", "a") is True
    assert secret_equal("café", "café") is True
    assert secret_equal("café", "a") is False
    assert secret_equal(None, "a") is False
    assert secret_equal("a", None) is False
    assert secret_equal("a", "") is False
    assert secret_equal(b"a", "a") is True
    assert secret_equal(42, "a") is False
    # A lone surrogate: what a JSON body can decode to, and what plain
    # utf-8 encoding refuses.
    assert secret_equal("\ud800", "a") is False


# --- D: an unreadable token file fails CLOSED ----------------------------


def test_unreadable_token_file_denies_instead_of_opening_up(client, tmp_path):
    """"Configured but unreadable" is a fault, not "no token required"."""
    from trmnl_server.config import panel_config

    token_path = Path(panel_config().token_file)
    assert client.get(
        "/api/display", headers={"ID": MAC, "Access-Token": TOKEN}
    ).status_code == 200

    token_path.chmod(0o000)
    try:
        if os.access(token_path, os.R_OK):  # pragma: no cover - running as root
            pytest.skip("cannot make a file unreadable as this user")
        assert client.get(
            "/api/display", headers={"ID": MAC, "Access-Token": TOKEN}
        ).status_code == 401
        assert client.get("/api/display", headers={"ID": MAC}).status_code == 401
        assert client.get(
            "/preview/readiness.png", headers={"Access-Token": TOKEN}
        ).status_code == 401
        # Enrolment cannot hand out a token it cannot read, and must not
        # hand out an empty one.
        setup = client.get("/api/setup", headers={"ID": MAC})
        assert setup.status_code == 503
    finally:
        token_path.chmod(0o600)

    assert client.get(
        "/api/display", headers={"ID": MAC, "Access-Token": TOKEN}
    ).status_code == 200


def test_empty_token_file_fails_closed(client):
    from trmnl_server.config import panel_config

    token_path = Path(panel_config().token_file)
    token_path.write_text("   \n")
    try:
        assert client.get(
            "/api/display", headers={"ID": MAC, "Access-Token": ""}
        ).status_code == 401
        assert client.get("/api/setup", headers={"ID": MAC}).status_code == 503
    finally:
        token_path.write_text(TOKEN)


def test_no_token_file_configured_still_means_no_token_required(client):
    """The LAN-only deployment shape must keep working."""
    from trmnl_server.config import panel_config

    cfg = panel_config()
    original = cfg.token_file
    cfg.token_file = ""
    try:
        assert client.get(
            "/api/display", headers={"ID": MAC}
        ).status_code == 200
        assert client.get("/preview/readiness.png").status_code == 200
    finally:
        cfg.token_file = original
