"""Image-serving routes for TRMNL local server.

Two of upstream's three routes are deliberately absent, because restoring
them verbatim would have quietly undone the two properties this fork's
image handling exists to provide:

* `GET /image/{image_name}` served the rotation under four fixed, guessable
  names (`screen.bmp`, `screen1.bmp`, `original.bmp`, `grayscale.png`). The
  `?token=` it accepts is optional — `_device_context_for_image_request()`
  falls back to `get_device_state_from_request()`, so an anonymous GET with
  no token still returns a frame under the `default` device. The firmware
  fetches `image_url` with no auth header at all, and the Pangolin edge
  config bypasses SSO for `/image/*` for exactly that reason, so on this
  deployment those URLs would have been an unauthenticated read of health
  data from the open internet. `routes/panel.py` keeps ownership of
  `/image/{name}`, where the only servable names are the
  `screen-NNN-<16 hex>.bmp` nonces it just generated and then prunes.

* `GET /preview/{device_id}` returned the device's current frame with no
  authentication whatsoever, and `{device_id}` is the panel's MAC. This
  fork's `/preview/{slug}.png` lives in `routes/panel.py` behind the
  Access-Token check. Note `{device_id}` would also have matched the literal
  string `readiness.png`, so registering it ahead of the panel router would
  have shadowed the gated route with an ungated one.

The UI needs neither: its thumbnails read `state.current_preview_url`, which
this fork points at the plugin-generated PNG under `/generated/...`, and
`entry.url_png` from the rotation snapshot, which resolves to the same place.
Those URLs are served by `serve_generated` below — an allowlist of what the
current rotation publishes, not a StaticFiles mount over the scheduler's
output directory. See that function for why.

What is left besides that is `/images/current.png` — a convenience for
looking at the frame the rotation currently holds, gated on the Access-Token
like every other frame-bearing route this fork serves.
"""

from __future__ import annotations

import re
from io import BytesIO

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from .. import config, utils
from ..services import state
from .auth import has_ui_session
from .panel import authorised

router = APIRouter()
logger = config.logger

# Path shape `utils.path_to_web_url()` can produce: slash-separated segments
# of conservative characters, ending in .png or .bmp. No segment may start
# with a dot, so `..` never matches and traversal is rejected before the
# allowlist lookup rather than relying on it.
_GENERATED_RE = re.compile(
    r'^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*\.(png|bmp)$'
)


def _binary_response(image_blob: BytesIO, media_type: str) -> Response:
    payload = image_blob.getvalue()
    if media_type == 'image/png':
        payload = utils.ensure_png_payload_under_budget(
            payload,
            levels=4,
            dither_mode=config.DITHERING_MODE,
            max_bytes=config.PNG_MAX_BYTES,
            log_context='serve_png'
        )
    headers = {'Content-Length': str(len(payload))}
    return Response(content=payload, media_type=media_type, headers=headers)


def _not_found() -> JSONResponse:
    return JSONResponse({'status': 404, 'error': 'not found'}, status_code=404)


@router.get('/generated/{path:path}')
def serve_generated(path: str, request: Request) -> Response:
    """Serve a plugin-generated frame, but only if the rotation publishes it.

    Authenticated, because `/preview/<slug>.png` is. Both routes hand back
    the same Garmin render — one drawn on demand, one drawn by the plugin
    scheduler — so an unauthenticated `/generated/...` is not a smaller hole
    than an unauthenticated `/preview/...`, it is the same hole reached by a
    sibling route. Relying on the edge alone to tell them apart is exactly
    the assumption `routes/auth.py` exists to reject: the app cannot see
    whether Authentik ran, one broadened bypass rule covers this prefix, and
    the rule that already exists (`/image/*`) is one character away from
    matching `/images/`.

    Two credentials are accepted, and both are ones the caller already has:
    a control-plane session cookie (what the UI's `<img>` tags send —
    same-site, so `SameSite=Strict` does not block them), or the panel's
    Access-Token (what `/preview` takes). When no `TRMNL_TOKEN_FILE` is
    configured `authorised()` returns True, so a LAN deployment behaves
    exactly as `/preview` does — one rule, not two.

    This replaces `app.mount("/generated", StaticFiles(...))`. The mount was
    not an internet-facing hole — `/generated/*` matches neither of the
    edge's bypass rules (`/api/*`, `/image/*`), so it sits behind Authentik,
    and it exposes neither the panel's nonce frames nor `trmnl.db`, both of
    which live in `<state_dir>` itself rather than `<state_dir>/generated`.
    What it *was* is a standing grant on a directory: whatever a future
    plugin writes there becomes HTTP-reachable with no review step, at a
    stable guessable path, for as long as the file exists — decoupled from
    whether the rotation still contains it.

    So: the app decides what is servable rather than delegating that to the
    filesystem. The URL string is byte-identical to what
    `utils.path_to_web_url()` produced before, which matters more than it
    looks — `state._rotation_entry_id()` embeds these URLs in the entry IDs
    persisted in `rotation_playlists`, and `build_rotation_snapshot()` prunes
    and re-persists any saved playlist whose IDs it cannot resolve. Changing
    the URL scheme would silently wipe the user's playlists.

    The bytes come from memory: `append_rotation_assets` /
    `set_primary_rotation_assets` read each file once at publish time into
    `master['bmp_entries']` / `['png_entries']`, and every other read path in
    this fork already serves from there. The files on disk stay — the
    scheduler's `_assets_exist()` staleness check needs them.

    Deliberately a plain `Response` and not `_binary_response()`: that helper
    runs `ensure_png_payload_under_budget(levels=4)`, which would re-quantise
    an oversized payload to four dithered grey levels. These are mode-"1"
    renders and must stay that way.
    """
    # Before the path check, so an unauthenticated caller cannot use the
    # 404-vs-401 split to enumerate which renders the rotation is publishing.
    if not (has_ui_session(request) or authorised(request)):
        return JSONResponse(
            {'status': 401, 'error': 'unauthorised'}, status_code=401
        )
    if not _GENERATED_RE.match(path):
        return _not_found()
    url = f'/generated/{path}'
    with state.STATE_LOCK:
        meta = list(state.rotation_master().get('meta') or [])
    for idx, entry in enumerate(meta):
        if entry.get('url_png') == url:
            getter, media = state.get_rotation_png_bytes, 'image/png'
        elif entry.get('url_bmp') == url:
            getter, media = state.get_rotation_bmp_bytes, 'image/bmp'
        else:
            continue
        try:
            payload = getter(idx)
        except state.RotationUnavailableError:
            # meta and the byte lists are appended under the same lock, so
            # this means the rotation was rebuilt between the two reads.
            return _not_found()
        return Response(
            content=payload,
            media_type=media,
            headers={'Cache-Control': 'no-store'},
        )
    return _not_found()


@router.get('/images/current.png')
def serve_current_png(request: Request) -> Response:
    """Convert the current BMP frame to PNG for browser viewing."""
    if not authorised(request):
        return JSONResponse(
            {'status': 401, 'error': 'bad access token'}, status_code=401
        )
    _, device_state = state.get_device_state_from_request(request)
    entry_idx = state.current_frame_entry_index(device_state)
    if entry_idx is None:
        raise HTTPException(status_code=404, detail='No current image available')
    bmp_blob = BytesIO(state.get_rotation_bmp_bytes(entry_idx))
    png_bytes = utils.convert_bmp_bytes_to_png(bmp_blob)
    response = _binary_response(png_bytes, 'image/png')
    response.headers['Cache-Control'] = 'no-store'
    return response
