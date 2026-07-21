"""The BYOS HTTP surface the TRMNL firmware talks to.

Three endpoints are all the stock firmware needs:

    GET  /api/setup    first contact — hand back an access token
    GET  /api/display  "what should I show, and when do I ask again?"
    POST /api/log      device-side error reports

Rendering happens on request rather than on a timer, and the result is
cached until `refresh_seconds` elapses. That means the panel never shows
an image built from data older than its own refresh interval, and a
device that goes offline for a day doesn't leave a stale BMP behind.

Auth shape, and why it is what it is: the panel is an ESP32 sending a
static header, so there is no SSO. The gate is a MAC allowlist on
/api/setup (enrolment necessarily predates the device holding a token),
an Access-Token header on /api/display, and unguessable image paths —
the firmware fetches image_url as a plain GET with no auth header, so
the random nonce in the filename is the only thing keeping health data
off the open web. Old frames are deleted each render, so a leaked URL
dies at the next refresh. Preserve all three properties.
"""

from __future__ import annotations

import hmac
import re
import secrets
import threading
import time
from io import BytesIO
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response

from .. import models
from ..config import Config, normalise_mac, panel_config
from ..render import render_notice, render_screen
from ..screens import available as available_screens
from .. import config as config_module

logger = config_module.logger

# The firmware treats a changed filename as "there is something new to
# draw", so the name has to move whenever the image does. The random half
# does double duty as a capability: see the module docstring.
_IMAGE_NAME = "screen-{n:03d}-{nonce}.bmp"
_IMAGE_RE = re.compile(r"^screen-\d{3}-[0-9a-f]{16}\.bmp$")

# How long a failure screen stays up before the next attempt.
_ERROR_RETRY = 300

# Device IDs already reported, so the journal gets one line per panel
# rather than one per poll.
_SEEN_DEVICES: set[str] = set()

router = APIRouter()


class Renderer:
    """Renders the playlist on demand and caches the most recent frame."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.state_dir = Path(config.state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._index = 0
        self._counter = 0
        self._expires_at = 0.0
        self._current: tuple[str, int] | None = None

    def current(self) -> tuple[str, int]:
        """Return (filename, refresh_seconds), rendering if stale."""
        with self._lock:
            now = time.monotonic()
            if self._current is not None and now < self._expires_at:
                return self._current

            slug = self.config.playlist[self._index % len(self.config.playlist)]
            self._index += 1
            self._counter += 1
            name = _IMAGE_NAME.format(
                n=self._counter % 1000, nonce=secrets.token_hex(8)
            )

            try:
                canvas, refresh = render_screen(slug, self.config)
            except Exception as exc:
                logger.exception("render of screen %r failed", slug)
                # Put the failure on the glass rather than leaving the last
                # good frame up: a stale dashboard looks exactly like a
                # healthy one, and this device has no other way to say it
                # is broken. Retry sooner than a normal refresh.
                canvas = render_notice(
                    self.config,
                    f"{slug} unavailable",
                    f"{type(exc).__name__}: {exc}\n\n"
                    f"Retrying every {_ERROR_RETRY // 60} minutes. "
                    f"Check: journalctl -u trmnl -n 50",
                )
                refresh = _ERROR_RETRY

            canvas.save(self.state_dir / name, fmt="bmp")

            self._prune(keep=name)
            self._current = (name, refresh)
            self._expires_at = now + refresh
            logger.info("rendered %s -> %s (refresh %ss)", slug, name, refresh)
            return self._current

    def _prune(self, *, keep: str) -> None:
        for old in self.state_dir.glob("screen-*.bmp"):
            if old.name != keep:
                old.unlink(missing_ok=True)


_RENDERER: Renderer | None = None


def configure(cfg: Config) -> None:
    """Bind the router to an explicit config (serve mode and tests)."""
    global _RENDERER
    _RENDERER = Renderer(cfg)


def _renderer() -> Renderer:
    global _RENDERER
    if _RENDERER is None:
        _RENDERER = Renderer(panel_config())
    return _RENDERER


def _config() -> Config:
    return _renderer().config


def _authorised(request: Request) -> bool:
    expected = _config().token()
    if not expected:
        return True
    supplied = request.headers.get("Access-Token") or ""
    # compare_digest, not ==, so a wrong token cannot be recovered a byte
    # at a time from response timing.
    return hmac.compare_digest(supplied.strip(), expected)


def _note_device(device: str | None) -> None:
    """Log each device ID once, loudly.

    Enrolment is a chicken-and-egg problem: `allowedDevices` wants a MAC
    that the panel only reveals in a captive-portal screen shown for a
    second or two. Pointing the panel at this server with an empty
    allowlist and reading the address out of the journal is the reliable
    way to get it — and it prints the normalised form the allowlist
    actually compares, so it cannot be mistranscribed.
    """
    if not device or device in _SEEN_DEVICES:
        return
    _SEEN_DEVICES.add(device)
    logger.info(
        "device seen: ID=%r -> allowedDevices entry: %s",
        device, normalise_mac(device),
    )


def _record_battery(request: Request) -> None:
    """Stash battery/RSSI headers the firmware volunteers on each poll.

    Surfacing these as Prometheus metrics puts panel health in Grafana
    beside everything else; the SQLite history is the raw material.
    """
    voltage = request.headers.get("Battery-Voltage")
    rssi = request.headers.get("RSSI")
    if voltage is None or rssi is None:
        return
    try:
        models.add_battery_status(float(voltage), int(rssi))
    except (ValueError, TypeError):
        logger.warning("unparseable battery headers: %s V, %s dBm", voltage, rssi)


# Firmware 1.5.12 requests `/api/setup/` — WITH the trailing slash — while
# every published example omits it. Exact-string routing 404s enrolment,
# the panel never receives a token, and every later /api/display answers
# 401 forever. Both spellings are registered explicitly rather than relying
# on redirect_slashes, because the firmware's redirect handling is not to
# be trusted without verification against the device.


@router.get("/api/setup")
@router.get("/api/setup/")
def api_setup(request: Request) -> JSONResponse:
    # Enrolment happens before the device holds a token, so the allowlist
    # — not the token — is what guards this route.
    device = request.headers.get("ID")
    _note_device(device)
    cfg = _config()
    if not cfg.device_allowed(device):
        logger.warning("refused setup for unknown device %r", device)
        return JSONResponse(
            {"status": 403, "error": "unknown device"}, status_code=403
        )
    token = cfg.token()
    return JSONResponse({
        "status": 200,
        "api_key": token or "",
        # Strip separators before slicing — the raw header is
        # colon-delimited, so a naive slice yields ":EE:FF".
        "friendly_id": normalise_mac(device or "TRMNL")[-6:].upper(),
        "message": "Welcome to the hive",
    })


@router.get("/api/display")
@router.get("/api/display/")
def api_display(request: Request) -> JSONResponse:
    cfg = _config()
    _note_device(request.headers.get("ID"))
    if not cfg.device_allowed(request.headers.get("ID")):
        return JSONResponse(
            {"status": 403, "error": "unknown device"}, status_code=403
        )
    if not _authorised(request):
        return JSONResponse(
            {"status": 401, "error": "bad access token"}, status_code=401
        )
    _record_battery(request)
    name, refresh = _renderer().current()
    return JSONResponse({
        "status": 0,
        "filename": name,
        "image_url": f"{cfg.base_url}/image/{name}",
        "refresh_rate": refresh,
        "reset_firmware": False,
        "update_firmware": False,
        "special_function": "sleep",
    })


@router.post("/api/log")
@router.post("/api/log/")
@router.post("/api/logs")
@router.post("/api/logs/")
async def api_log(request: Request) -> Response:
    body = await request.body()
    logger.warning("device log: %s", body.decode("utf-8", "replace")[:2000])
    return Response(status_code=204)


@router.get("/image/{name}")
def serve_image(name: str) -> Response:
    # Serve only generated frames, matched against the exact generated
    # shape, from the state directory — never a caller-supplied path.
    if not _IMAGE_RE.match(name):
        return JSONResponse(
            {"status": 404, "error": "not found"}, status_code=404
        )
    path = Path(_config().state_dir) / name
    if not path.is_file():
        return JSONResponse(
            {"status": 404, "error": "not found"}, status_code=404
        )
    return Response(
        content=path.read_bytes(),
        media_type="image/bmp",
        headers={"Cache-Control": "no-store"},
    )


@router.get("/healthz")
def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@router.get("/preview/{slug}.png")
def preview(slug: str, request: Request) -> Response:
    """Render one screen to PNG for a browser.

    This is the fast iteration loop: deploy nothing, refresh a tab. It
    shows exactly what the panel will show, error screens included. The
    route is behind the same Access-Token check as /api/display whenever a
    token is configured — a browser preview of health data must not become
    the easiest way to read it off a publicly-exposed deployment.
    """
    if not _authorised(request):
        return JSONResponse(
            {"status": 401, "error": "bad access token"}, status_code=401
        )
    cfg = _config()
    synthetic = "synthetic" in request.query_params
    try:
        canvas, _refresh = render_screen(slug, cfg, synthetic=synthetic)
    except LookupError:
        return JSONResponse(
            {"status": 404, "error": f"unknown screen {slug!r}",
             "screens": available_screens()},
            status_code=404,
        )
    except Exception as exc:
        logger.exception("preview render of screen %r failed", slug)
        canvas = render_notice(
            cfg, f"{slug} unavailable", f"{type(exc).__name__}: {exc}"
        )
    buf = BytesIO()
    canvas.image.save(buf, format="PNG", optimize=True)
    return Response(content=buf.getvalue(), media_type="image/png")
