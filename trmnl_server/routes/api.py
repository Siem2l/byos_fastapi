"""Control-plane routes for the browser UI (`web/js/app.js`).

Upstream's `api.py`, minus every route the firmware talks to. `/api/display`,
`/api/setup` and `/api/log` are owned by `routes/panel.py` in this fork,
which gates them on the MAC allowlist and the Access-Token header; upstream's
versions do neither — its `/api/setup` hands `config.SETUP_API_KEY` to any
caller. FastAPI resolves routes in registration order with no warning on
collision, so leaving those here would have made the include order in
`main.py` the thing standing between the panel's access token and the open
internet. They are deleted rather than reordered.

Everything that remains is browser-facing and lives *outside* the `/api/`
namespace, which is load-bearing: any reverse proxy in front of this server
has to bypass authentication for `/api/*` and `/image/*` precisely because
the ESP32 cannot follow an SSO redirect. Do not move a browser endpoint under
`/api/` — it would silently lose that outer gate. That is no longer a
convention held up by this
comment: `main.py::_assert_route_invariants()` refuses to build the app if
any route outside the firmware's fixed device surface appears under `/api/`.

Authorisation is attached to the *router*, not to individual routes — see
`routes/auth.py` for why an edge's SSO cannot be relied on alone (it
typically forwards no identity, and the backend cannot distinguish an SSO'd
request from a bypassed one). Every route below therefore requires an app-owned
session cookie, and every mutating one additionally requires a same-origin
request. Routes added to this router inherit both automatically; nobody has
to remember a decorator. None of these is a "safe read": `/server/log` and
`/status` both carry frame-preview capabilities.

`/settings`, `/settings/refreshtime` and `/settings/imagepath` are also gone:
this fork is env-var driven (the deployment's unit or compose file owns
every knob) and never calls `config.apply_persisted_config()`, so those writes would have
persisted rows that nothing reads back.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from os import cpu_count, getloadavg
from typing import Any, Dict, Optional

from time import time
from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import JSONResponse, Response

from .. import config, models, utils
from ..services import state
from .auth import require_ui_session

try:  # pragma: no cover - exercised by which wheel happens to be installed
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

router = APIRouter(dependencies=[Depends(require_ui_session)])
logger = config.logger

# What a device's refresh interval may be set to, in seconds. Auth is the
# gate; this rejection is the blast radius, and it holds even for a caller
# holding a valid session. The bounds live in `config` because
# `routes/panel.py::api_display` enforces the same pair on the way *out* —
# see the comment there for why a write-side check on its own is worthless.
MIN_REFRESH_INTERVAL = config.MIN_REFRESH_INTERVAL
MAX_REFRESH_INTERVAL = config.MAX_REFRESH_INTERVAL


def _cpu_load_percent() -> float:
    """Server CPU load for the Home tab's gauge.

    psutil is upstream's only use of a sixth runtime dependency, for this one
    number. Falling back to the 1-minute load average scaled by core count
    keeps the gauge meaningful without adding psutil to the Nix closure.
    """
    if psutil is not None:
        return float(psutil.cpu_percent(interval=None))
    try:
        load1 = getloadavg()[0]
    except (OSError, AttributeError):  # pragma: no cover - no /proc/loadavg
        return 0.0
    return round(min(100.0, load1 / max(1, cpu_count() or 1) * 100.0), 1)


def _screen_title_for_plugin(plugin_name: Optional[str]) -> Optional[str]:
    """Human title of the screen a rotation plugin renders, for "Now showing".

    Imported lazily for the same reason `main.py` defers the plugin import:
    building the registry instantiates every plugin class.
    """
    if not plugin_name:
        return None
    try:
        from ..plugins.garmin import SLUG_BY_PLUGIN
        from ..screens import base as screens_base

        slug = SLUG_BY_PLUGIN.get(plugin_name)
        if not slug:
            return None
        screen_cls = screens_base.REGISTRY.get(slug)
        return (getattr(screen_cls, 'title', '') or slug) if screen_cls else slug
    except Exception:  # noqa: BLE001 - a label must never break /status
        logger.warning("could not resolve screen title for %r", plugin_name)
        return None


def _wifi_percent(rssi: Any) -> Optional[int]:
    """RSSI dBm as a 0-100 gauge value, or None when there is no reading.

    A real RSSI is a negative dBm; 0, None or a positive value all mean the
    panel has not reported signal, and must not render as full bars.
    """
    if not isinstance(rssi, (int, float)) or rssi >= 0:
        return None
    return utils.get_wifi_signal_strength(int(rssi))


def _next_refresh_at(last_contact: Any, refresh_interval: Optional[int]) -> Optional[str]:
    """When the panel is next due to poll, or None if it never has.

    Advisory only. The ESP32 sleeps on its own timer and wakes late as often
    as not, so the UI treats a passed deadline as "due now", never as a
    negative countdown.
    """
    if not isinstance(last_contact, (int, float)) or last_contact <= 0:
        return None
    if not isinstance(refresh_interval, (int, float)) or refresh_interval <= 0:
        return None
    return utils.to_iso_timestamp(last_contact + refresh_interval)


def _serialize_device_payload(device_id: str) -> Dict[str, Any]:
    profile = state.ensure_device_profile(device_id)
    metrics = state.get_client_metrics(device_id)
    device_state = state.get_device_state(device_id)
    playlist = state.get_playlist_selection(device_id)
    binding_name = state.get_device_playlist_binding_name(device_id) or state.DEFAULT_DEVICE_ID
    current_entry_hash = device_state.get('last_entry_hash')
    # No fallback to /preview/<device_id>: that upstream route is not
    # registered here (see routes/images.py). When rotation has not yet
    # placed a frame the UI renders "No preview yet", which is honest.
    preview_url = device_state.get('current_preview_url')
    preview_token = device_state.get('current_preview_token')
    return {
        'device_id': device_id,
        'friendly_name': profile.get('friendly_name') or device_id,
        'refresh_interval': state.get_refresh_interval(device_id),
        'playlist_name': binding_name,
        'playlist': playlist,
        'metrics': {
            'refresh_rate': metrics.get('refresh_rate'),
            'battery_voltage': metrics.get('battery_voltage'),
            'battery_state': utils.get_battery_state(metrics.get('battery_voltage')),
            'rssi': metrics.get('rssi'),
            # 0-100 for a gauge, mirroring battery_state. None rather than a
            # misleading 100% when there is no reading: a real RSSI is always a
            # negative dBm, so 0/None/positive means "the panel never reported",
            # and get_wifi_signal_strength(0) would otherwise read as full bars.
            'wifi_signal_strength': _wifi_percent(metrics.get('rssi')),
            'last_contact': utils.to_iso_timestamp(metrics.get('last_contact'))
        },
        'profile': {
            'refresh_interval': profile.get('refresh_interval'),
            'time_zone': profile.get('time_zone'),
            'last_seen': utils.to_iso_datetime(profile.get('last_seen')) if profile.get('last_seen') else None
        },
        'state': {
            'supports_grayscale': device_state.get('supports_grayscale'),
            'current_entry_hash': current_entry_hash,
            'current_plugin_id': device_state.get('last_entry_plugin'),
            'current_preview_url': preview_url,
            'current_preview_token': preview_token
        }
    }


@router.get('/rotation')
def get_rotation_playlist() -> JSONResponse:
    """Expose the current rotation entries and default playlist selection."""
    snapshot = state.build_rotation_snapshot()
    return JSONResponse(snapshot)


@router.post('/rotation')
def update_rotation_playlist(data: Dict[str, Any] = Body(...)) -> JSONResponse:
    """Update the default or per-device rotation playlist using entry IDs."""
    playlist_ids = data.get('playlist')
    device_id = data.get('device_id')

    if not isinstance(playlist_ids, list) or not all(isinstance(pid, str) for pid in playlist_ids):
        return JSONResponse({'status': 'error', 'message': 'playlist must be a list of IDs'}, status_code=400)

    try:
        if device_id:
            state.set_device_playlist(device_id, playlist_ids)
        else:
            state.set_default_playlist(playlist_ids)
    except ValueError as exc:
        return JSONResponse({'status': 'error', 'message': str(exc)}, status_code=400)

    snapshot = state.build_rotation_snapshot()
    return JSONResponse(snapshot)


@router.post('/playlists')
def upsert_named_playlist(data: Dict[str, Any] = Body(...)) -> JSONResponse:
    """Create or update a named rotation playlist entity."""
    name = data.get('name')
    playlist_ids = data.get('playlist')

    if not isinstance(name, str) or not name.strip() or name.strip() == state.DEFAULT_DEVICE_ID:
        return JSONResponse({'status': 'error', 'message': 'name must be a non-default string'}, status_code=400)
    if not isinstance(playlist_ids, list) or not all(isinstance(pid, str) for pid in playlist_ids):
        return JSONResponse({'status': 'error', 'message': 'playlist must be a list of IDs'}, status_code=400)

    try:
        state.set_named_playlist(name.strip(), playlist_ids)
    except ValueError as exc:
        return JSONResponse({'status': 'error', 'message': str(exc)}, status_code=400)

    snapshot = state.build_rotation_snapshot()
    return JSONResponse(snapshot)


@router.delete('/playlists/{name}')
def delete_named_playlist(name: str) -> JSONResponse:
    """Delete a named playlist and unbind any devices using it."""
    if not name or name.strip() == state.DEFAULT_DEVICE_ID:
        return JSONResponse({'status': 'error', 'message': 'default playlist cannot be deleted'}, status_code=400)
    try:
        state.delete_named_playlist(name.strip())
    except ValueError as exc:
        return JSONResponse({'status': 'error', 'message': str(exc)}, status_code=400)
    snapshot = state.build_rotation_snapshot()
    return JSONResponse(snapshot)


@router.delete('/rotation/{device_id}')
def delete_rotation_playlist(device_id: str) -> JSONResponse:
    """Remove a per-device playlist override and fall back to the default selection."""
    normalized = (device_id or '').strip() or state.DEFAULT_DEVICE_ID
    if normalized == state.DEFAULT_DEVICE_ID:
        return JSONResponse({'status': 'error', 'message': 'default playlist cannot be deleted'}, status_code=400)

    state.clear_device_playlist(normalized)
    snapshot = state.build_rotation_snapshot()
    return JSONResponse(snapshot)


@router.get('/devices')
def list_devices(include_default: bool = Query(True, alias='include_default')) -> JSONResponse:
    """List known devices along with their profiles, metrics, and playlists."""
    device_ids = state.known_device_ids(include_default=include_default)
    devices = [_serialize_device_payload(device_id) for device_id in device_ids]
    return JSONResponse({'devices': devices})


@router.get('/devices/{device_id}')
def get_device(device_id: str) -> JSONResponse:
    """Return metadata and metrics for a specific device."""
    normalized_id = device_id.strip() or state.DEFAULT_DEVICE_ID
    payload = _serialize_device_payload(normalized_id)
    return JSONResponse(payload)


@router.patch('/devices/{device_id}')
def update_device(
    device_id: str,
    data: Dict[str, Any] = Body(...)
) -> JSONResponse:
    """Update device profile fields and optionally override its playlist."""
    normalized_id = device_id.strip() or state.DEFAULT_DEVICE_ID
    friendly_name = data.get('friendly_name')
    refresh_interval = data.get('refresh_interval')
    time_zone = data.get('time_zone')
    playlist_ids = data.get('playlist')
    has_playlist_name = 'playlist_name' in data
    playlist_name = data.get('playlist_name')

    refresh_override: Optional[int] = None
    if refresh_interval is not None:
        # bool is an int subclass; `True` must not become a 1-second poll.
        if isinstance(refresh_interval, bool) or not isinstance(refresh_interval, int) or refresh_interval <= 0:
            return JSONResponse({'status': 'error', 'message': 'refresh_interval must be a positive integer'}, status_code=400)
        if not MIN_REFRESH_INTERVAL <= refresh_interval <= MAX_REFRESH_INTERVAL:
            return JSONResponse(
                {
                    'status': 'error',
                    'message': (
                        'refresh_interval must be between '
                        f'{MIN_REFRESH_INTERVAL} and {MAX_REFRESH_INTERVAL} seconds'
                    ),
                },
                status_code=400,
            )
        refresh_override = refresh_interval

    if playlist_ids is not None:
        if not isinstance(playlist_ids, list) or not all(isinstance(pid, str) for pid in playlist_ids):
            return JSONResponse({'status': 'error', 'message': 'playlist must be a list of IDs'}, status_code=400)

    state.update_device_profile(
        normalized_id,
        friendly_name=friendly_name,
        refresh_interval=refresh_override,
        time_zone=time_zone
    )

    if playlist_ids is not None:
        try:
            state.set_device_playlist(normalized_id, playlist_ids)
        except ValueError as exc:
            return JSONResponse({'status': 'error', 'message': str(exc)}, status_code=400)

    if has_playlist_name:
        if playlist_name is not None and not isinstance(playlist_name, str):
            return JSONResponse({'status': 'error', 'message': 'playlist_name must be a string or null'}, status_code=400)
        try:
            state.set_device_playlist_binding(normalized_id, playlist_name)
        except ValueError as exc:
            return JSONResponse({'status': 'error', 'message': str(exc)}, status_code=400)

    payload = _serialize_device_payload(normalized_id)
    return JSONResponse(payload)


@router.get('/server/log')
def log_view(
    request: Request,
    limit: int = Query(30, ge=1, le=200),
    after: Optional[int] = Query(None),
    response_format: str = Query('text', alias='format')
) -> Response:
    """Return recent logs with optional cursor-based pagination."""
    logs = models.get_logs_after(after, limit) if after is not None else models.get_logs(limit=limit)

    wants_json = 'application/json' in (request.headers.get('accept') or '').lower() or response_format.lower() == 'json'
    if wants_json:
        payload = [
            {
                'id': log.id,
                'timestamp': utils.to_iso_datetime(log.timestamp),
                'context': log.context,
                'info': log.info
            }
            for log in logs
        ]
        return JSONResponse(payload)

    formatted_logs = '\n'.join([f"{log.timestamp} -- [{log.context}] -- {log.info}" for log in logs])
    response = Response(content=formatted_logs, media_type='text/plain')
    if logs:
        response.headers['X-Log-Last-Id'] = str(logs[-1].id)
    return response


@router.get('/server/battery')
def battery_view(
    all_data: Optional[str] = Query(None, alias='all'),
    from_date: Optional[str] = Query(None, alias='from'),
    to_date: Optional[str] = Query(None, alias='to')
) -> JSONResponse:
    """Fetch battery data from the client database and return it in JSON format."""
    from_dt = None
    to_dt = None
    if from_date:
        try:
            from_dt = datetime.strptime(from_date, '%Y-%m-%d')
        except ValueError:
            pass
    if to_date:
        try:
            to_dt = datetime.strptime(to_date, '%Y-%m-%d')
        except ValueError:
            pass

    if not all_data and not from_dt and not to_dt:
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        from_dt = today
        to_dt = today + timedelta(days=1)

    limit = None if all_data else 1000
    history = models.get_battery_history(limit=limit, from_date=from_dt, to_date=to_dt)

    response_data = [
        {
            'timestamp': utils.to_iso_datetime(entry.timestamp),
            'battery_voltage': entry.voltage,
            'rssi': entry.rssi
        }
        for entry in history
    ]
    response_data.sort(key=lambda x: x['timestamp'])

    return JSONResponse(response_data)


@router.get('/status')
def status_view(device_id: Optional[str] = Query(None, alias='device_id')) -> JSONResponse:
    """Retrieve the current status of the server and connected devices."""
    selected_device_id = device_id or state.DEFAULT_DEVICE_ID
    uptime_seconds = int(time() - state.start_time)
    uptime = str(timedelta(seconds=uptime_seconds))

    cpu_load = _cpu_load_percent()
    current_time = utils.to_iso_datetime(datetime.now(timezone.utc))

    metrics = state.get_client_metrics(selected_device_id)
    profile = state.ensure_device_profile(selected_device_id)
    refresh_interval = state.get_refresh_interval(selected_device_id)
    battery_voltage = metrics['battery_voltage']
    battery_state = utils.get_battery_state(battery_voltage)
    wifi_signal = metrics['rssi']
    wifi_signal_strength = utils.get_wifi_signal_strength(wifi_signal)

    battery_history = models.get_battery_history(limit=30)
    client_data_db = [
        {
            'timestamp': utils.to_iso_datetime(entry.timestamp),
            'battery_voltage': entry.voltage,
            'rssi': entry.rssi
        }
        for entry in battery_history
    ]
    client_data_db.sort(key=lambda x: x['timestamp'])

    device_state = state.get_device_state(selected_device_id)
    current_entry_hash = device_state.get('last_entry_hash')
    current_preview_url = device_state.get('current_preview_url')
    current_preview_token = device_state.get('current_preview_token')
    now_showing = _screen_title_for_plugin(device_state.get('last_entry_plugin'))
    next_refresh_at = _next_refresh_at(metrics.get('last_contact'), refresh_interval)

    metrics_store = state.get_all_client_metrics()

    def _has_contact(device_id: str) -> bool:
        metrics_record = metrics_store.get(device_id) or {}
        last_contact = metrics_record.get('last_contact')
        return isinstance(last_contact, (int, float)) and last_contact > 0

    filtered_ids = []
    seen_ids = set()
    for known_id in state.known_device_ids(include_default=False):
        if _has_contact(known_id):
            filtered_ids.append(known_id)
            seen_ids.add(known_id)
    if selected_device_id and selected_device_id != state.DEFAULT_DEVICE_ID and selected_device_id not in seen_ids:
        filtered_ids.append(selected_device_id)
    devices_summary = [_serialize_device_payload(known_id) for known_id in filtered_ids]
    playlists_summary = state.list_playlist_targets()

    status_data = {
        'server': {
            'uptime': uptime,
            'cpu_load': cpu_load,
            'current_time': current_time
        },
        'client': {
            'device_id': selected_device_id,
            'friendly_name': profile.get('friendly_name') or selected_device_id,
            'battery_voltage': battery_voltage,
            'battery_voltage_max': config.BATTERY_MAX_VOLTAGE,
            'battery_voltage_min': config.BATTERY_MIN_VOLTAGE,
            'battery_state': battery_state,
            'wifi_signal': wifi_signal,
            'wifi_signal_strength': wifi_signal_strength,
            'refresh_time': refresh_interval,
            'last_contact': utils.to_iso_timestamp(metrics['last_contact']),
            'profile': {
                'refresh_interval': profile.get('refresh_interval'),
                'time_zone': profile.get('time_zone'),
                'last_seen': utils.to_iso_datetime(profile.get('last_seen')) if profile.get('last_seen') else None
            },
            'supports_grayscale': device_state.get('supports_grayscale'),
            'current_entry_hash': current_entry_hash,
            'current_plugin_id': device_state.get('last_entry_plugin'),
            'current_preview_url': current_preview_url,
            'current_preview_token': current_preview_token,
            # Dashboard extras. `now_showing` is the human title of whatever
            # frame the panel last collected; `next_refresh_at` is when it is
            # due back. Both are null until the device has actually polled —
            # the UI must not invent a countdown from nothing.
            'now_showing': now_showing,
            'next_refresh_at': next_refresh_at
        },
        'devices': devices_summary,
        'playlists': playlists_summary,
        'client_data_db': client_data_db
    }
    return JSONResponse(status_data)
