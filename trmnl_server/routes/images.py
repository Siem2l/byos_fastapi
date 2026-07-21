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
this fork points at the plugin-generated PNG under `/generated/...` (behind
the same Authentik gate as the rest of the UI), and `entry.url_png` from the
rotation snapshot, which resolves to the same place.

What is left is `/images/current.png` — a convenience for looking at the
frame the rotation currently holds, gated on the Access-Token like every
other frame-bearing route this fork serves.
"""

from __future__ import annotations

from io import BytesIO

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from .. import config, utils
from ..services import state
from .panel import authorised

router = APIRouter()
logger = config.logger


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
