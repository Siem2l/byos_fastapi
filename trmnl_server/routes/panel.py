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

Relationship to the restored web UI: the UI's Playlists tab edits
`services.state`'s rotation, and this module reads that selection to
decide *which* screens to draw and in what order — but it keeps rendering
them itself, on request. Serving the plugin scheduler's cached frames
instead would have been less code, at the cost of the property this
module was built around: the panel never shows an image built from data
older than its own refresh interval, and a screen that fails renders a
legible notice rather than leaving yesterday's dashboard up. When the
rotation is empty (no plugin has produced a frame yet) the selection
falls back to TRMNL_PLAYLIST, so the panel works before the UI has ever
been opened.
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
from ..plugins.garmin import SLUG_BY_PLUGIN
from ..render import render_notice, render_screen
from ..screens import available as available_screens
from ..services import state
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

# --- POST /api/log limits -------------------------------------------------
#
# This endpoint is unauthenticated by necessity: the firmware posts device
# errors here with no credential of any kind, and it sits inside the edge's
# /api/* SSO bypass, so it is reachable from the open internet by anyone.
# It cannot be gated, so it is bounded instead. Every number below exists to
# keep an anonymous caller from filling the filesystem that holds trmnl.db
# and the rendered frames, or from evicting the enrolment audit trail.
_LOG_MAX_BODY = 4096          # bytes accepted at all; larger -> 413
_LOG_MAX_STORED = 500         # characters actually persisted
_LOG_RATE_WINDOW = 300.0      # seconds
_LOG_RATE_LIMIT = 12          # accepted posts per window per source
_LOG_RATE_MAX_SOURCES = 512   # distinct sources tracked, to bound the bucket
_log_buckets: dict[str, list[float]] = {}
_log_bucket_lock = threading.Lock()

router = APIRouter()


def rotation_entry_for_slug(slug: str) -> dict | None:
    """The rotation entry a screen slug produced, if the plugin has run."""
    for entry in state.rotation_master().get("meta") or []:
        if SLUG_BY_PLUGIN.get(entry.get("plugin") or "") == slug:
            return entry
    return None


def _rotation_slugs(device_id: str | None) -> list[str]:
    """Screen slugs in the order the UI's rotation playlist selects them.

    Entries whose plugin is not a screen adapter, and selections naming an
    entry that no longer exists, are skipped rather than treated as an
    error — the playlist is user-editable and outlives any single set of
    rotation entries.
    """
    entries = {
        entry.get("id"): entry
        for entry in state.rotation_master().get("meta") or []
        if entry.get("id")
    }
    slugs: list[str] = []
    for token in state.get_playlist_selection(device_id):
        entry = entries.get(state.playlist_base_id(token))
        if entry is None:
            continue
        slug = SLUG_BY_PLUGIN.get(entry.get("plugin") or "")
        if slug:
            slugs.append(slug)
    return slugs


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
        self._playlist: list[str] = []
        self._slug: str | None = None

    def playlist_for(self, device_id: str | None) -> list[str]:
        """What to draw, newest source of truth first.

        The UI's rotation wins when it resolves to at least one screen;
        otherwise TRMNL_PLAYLIST, which is what the NixOS module sets and
        what a fresh deployment has before any plugin has run.
        """
        try:
            slugs = _rotation_slugs(device_id)
        except Exception:  # noqa: BLE001 - rotation must never break the panel
            logger.exception("rotation lookup failed; falling back to TRMNL_PLAYLIST")
            slugs = []
        return slugs or list(self.config.playlist)

    def current(self, device_id: str | None = None) -> tuple[str, int]:
        """Return (filename, refresh_seconds), rendering if stale."""
        with self._lock:
            now = time.monotonic()
            playlist = self.playlist_for(device_id)
            # A playlist edit in the UI has to take effect on the next poll,
            # not whenever the current frame happens to expire.
            if (
                self._current is not None
                and now < self._expires_at
                and playlist == self._playlist
            ):
                return self._current
            if playlist != self._playlist:
                self._playlist = playlist
                self._index = 0

            slug = playlist[self._index % len(playlist)]
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
            self._slug = slug
            logger.info("rendered %s -> %s (refresh %ss)", slug, name, refresh)
            return self._current

    @property
    def slug(self) -> str | None:
        """The screen most recently drawn, for the UI's 'Now showing'."""
        return self._slug

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


def authorised(request: Request) -> bool:
    """Access-Token header check. Also used by routes/images.py."""
    expected = _config().token()
    if not expected:
        return True
    supplied = request.headers.get("Access-Token") or ""
    # compare_digest, not ==, so a wrong token cannot be recovered a byte
    # at a time from response timing.
    return hmac.compare_digest(supplied.strip(), expected)


def _device_label(device: str | None) -> str:
    """A short, non-credential handle for a panel, safe to persist.

    The raw device ID is the panel's MAC, and the MAC *is* the credential
    that `/api/setup` checks — `allowedDevices` is the only thing standing
    between a passer-by and a free copy of the access token, since enrolment
    necessarily predates the device holding one. Writing it into the `logs`
    table would publish that credential to every reader of `/server/log`.

    So the log DB gets the same six hex digits the firmware already displays
    as its friendly_id: enough to tell two panels apart in an audit trail,
    not enough to enrol. The full MAC still goes to the journal via
    `_note_device()`, which is root-readable only and is where the operator
    is told to look when transcribing it into `allowedDevices`.
    """
    normalised = normalise_mac(device or '')
    return normalised[-6:].upper() if normalised else 'unknown'


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


def _record_battery(request: Request, device_id: str) -> None:
    """Stash battery/RSSI headers the firmware volunteers on each poll.

    Surfacing these as Prometheus metrics puts panel health in Grafana
    beside everything else; the SQLite history is the raw material. The
    same numbers are pushed into `services.state` because that is what the
    UI reads: /status only lists a device once its `last_contact` is
    non-zero, so without this the Devices tab stays empty even while the
    panel is polling happily.
    """
    voltage = request.headers.get("Battery-Voltage")
    rssi = request.headers.get("RSSI")
    refresh = request.headers.get("Refresh-Rate")

    parsed_voltage: float | None = None
    parsed_rssi: int | None = None
    parsed_refresh: int | None = None
    try:
        if voltage is not None:
            parsed_voltage = float(voltage)
        if rssi is not None:
            parsed_rssi = int(rssi)
        if refresh is not None:
            parsed_refresh = int(refresh)
    except (ValueError, TypeError):
        logger.warning("unparseable device headers: %s V, %s dBm, %s s",
                       voltage, rssi, refresh)

    state.update_client_metrics(
        device_id,
        refresh_rate=parsed_refresh,
        battery_voltage=parsed_voltage,
        rssi=parsed_rssi,
    )
    models.touch_device_last_seen(device_id)

    if parsed_voltage is not None and parsed_rssi is not None:
        models.add_battery_status(parsed_voltage, parsed_rssi)


def _publish_to_ui(device_id: str, slug: str | None) -> None:
    """Tell the web UI which screen this device was just handed.

    Feeds the device card's "Now showing" line and its thumbnail. The
    thumbnail points at the plugin scheduler's copy of the same screen
    under /generated/... rather than at /preview/<slug>.png, because a
    browser cannot attach the Access-Token header that route requires —
    and /generated is behind the same edge SSO as the rest of the UI, so
    nothing is exposed by doing so. It may lag the panel by up to one
    plugin TTL; `hash` is the cache-buster the UI appends, so it updates
    as soon as the scheduler re-renders.
    """
    if not slug:
        return
    try:
        device_state = state.get_device_state(device_id)
        entry = rotation_entry_for_slug(slug)
        with state.STATE_LOCK:
            if entry is None:
                device_state["last_entry_plugin"] = slug
                return
            device_state["last_entry_hash"] = entry.get("id")
            device_state["last_entry_plugin"] = entry.get("plugin")
            device_state["current_preview_url"] = entry.get("url_png")
            device_state["current_preview_token"] = (entry.get("hash") or "")[:16]
    except Exception:  # noqa: BLE001 - UI bookkeeping must never 500 the panel
        logger.exception("failed to publish rotation state for %s", device_id)


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
    models.add_log_entry("/api/setup", f"enrolled device {_device_label(device)}")
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
    device = request.headers.get("ID")
    _note_device(device)
    if not cfg.device_allowed(device):
        return JSONResponse(
            {"status": 403, "error": "unknown device"}, status_code=403
        )
    if not authorised(request):
        return JSONResponse(
            {"status": 401, "error": "bad access token"}, status_code=401
        )

    device_id = (device or "").strip() or state.DEFAULT_DEVICE_ID
    _record_battery(request, device_id)

    renderer = _renderer()
    name, refresh = renderer.current(device_id)
    _publish_to_ui(device_id, renderer.slug)

    # A per-device refresh interval set in the UI overrides the screen's own
    # cadence — it is the only knob the panel's owner has for trading
    # freshness against battery, and it is what upstream's Devices tab
    # writes. The screen's declared interval remains the default.
    override = state.ensure_device_profile(device_id).get("refresh_interval")
    if isinstance(override, int) and override > 0:
        refresh = override

    # NEVER put `name` in here. It is the live frame nonce, and that nonce is
    # the *only* thing protecting `/image/<name>` — the firmware fetches the
    # image with no auth header at all, so an unguessable path is the whole
    # capability. Logging it would mean two requests (poll the log, fetch the
    # frame) yields the panel's health data, which is exactly the exposure
    # the nonce exists to prevent. The screen slug and the refresh interval
    # are what an operator actually needs from this line.
    models.add_log_entry(
        "/api/display",
        f"device={_device_label(device)} screen={renderer.slug} refresh={refresh}s",
    )
    return JSONResponse({
        "status": 0,
        "filename": name,
        "image_url": f"{cfg.base_url}/image/{name}",
        "refresh_rate": refresh,
        "reset_firmware": False,
        "update_firmware": False,
        "special_function": "sleep",
    })


def _log_rate_ok(source: str) -> bool:
    """Sliding-window limiter, keyed on the device ID the poster claims.

    The key is self-asserted, so this is not an authorisation control — it
    bounds a cooperative firmware's chatter and forces a determined abuser to
    rotate the ID header, which then hits `_LOG_RATE_MAX_SOURCES`. Combined
    with the row cap in `models.add_log_entry()`, the worst case is bounded
    write pressure on a table that can no longer grow.
    """
    now = time.monotonic()
    cutoff = now - _LOG_RATE_WINDOW
    with _log_bucket_lock:
        if len(_log_buckets) > _LOG_RATE_MAX_SOURCES:
            # Drop sources with nothing left in the window, then, if that was
            # not enough, drop the lot rather than grow without bound.
            for key in [k for k, v in _log_buckets.items() if not v or v[-1] < cutoff]:
                del _log_buckets[key]
            if len(_log_buckets) > _LOG_RATE_MAX_SOURCES:
                _log_buckets.clear()
        hits = [t for t in _log_buckets.get(source, []) if t >= cutoff]
        if len(hits) >= _LOG_RATE_LIMIT:
            _log_buckets[source] = hits
            return False
        hits.append(now)
        _log_buckets[source] = hits
        return True


@router.post("/api/log")
@router.post("/api/log/")
@router.post("/api/logs")
@router.post("/api/logs/")
async def api_log(request: Request) -> Response:
    """Device-side error reports. Unauthenticated, and necessarily so.

    The firmware posts here with no credential, and `/api/*` is bypassed at
    the edge, so this is an open write endpoint on the public internet. It
    persists to the same SQLite file that sits beside the rendered frames, so
    an unbounded version of this route is a filesystem-exhaustion primitive
    that also evicts the enrolment audit trail. Three bounds, none of which
    change the firmware's happy path: a body cap, a stored-text cap, and a
    per-source rate limit. The table itself is capped in `models`.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > _LOG_MAX_BODY:
                return Response(status_code=413)
        except ValueError:
            return Response(status_code=400)

    # Content-Length is a claim, not a fact (and chunked requests omit it),
    # so read incrementally and abandon the moment the cap is passed rather
    # than buffering whatever the peer decides to send.
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > _LOG_MAX_BODY:
            return Response(status_code=413)
        chunks.append(chunk)

    source = _device_label(request.headers.get("ID"))
    if not _log_rate_ok(source):
        logger.warning("device log rate limit hit for %s", source)
        return Response(status_code=429)

    text = b"".join(chunks).decode("utf-8", "replace")
    # Collapse newlines: the UI's log view is one row per entry, and a body
    # full of them would otherwise stretch one report across the whole pane.
    text = " ".join(text.split())[:_LOG_MAX_STORED]
    logger.warning("device log from %s: %s", source, text)
    # Also to SQLite, which is what the UI's Server Logs tab reads.
    models.add_log_entry("device log", text or "<empty>")
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
    if not authorised(request):
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
