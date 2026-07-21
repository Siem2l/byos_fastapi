"""App-owned session auth for the browser control plane.

Why the app authenticates at all, when the Pangolin edge already puts
Authentik SSO in front of everything outside `/api/*` and `/image/*`:

* **The edge forwards no identity.** Pangolin 1.19.4 has no
  `Remote-User`-style header injection and no configuration for one; the
  authenticated user object it builds is consumed by badger, an external
  Traefik plugin, and the generated middleware exposes exactly six fields,
  none of them a header name. So there is nothing for the backend to read.
* **The backend cannot tell SSO from bypass.** One resource, one target:
  `/api/display` (bypassed) and `/status` (SSO'd) arrive on the same
  `127.0.0.1:8095` socket via the same router and service. The only
  per-resource header facility is a *router*-level static middleware, which
  runs on the bypassed prefixes too — so a shared secret injected there
  proves "came through the edge", never "passed Authentik", and nothing
  strips a client-supplied copy of it on the bypassed path.

Therefore: an app-owned, HMAC-signed, `SameSite=Strict`, HttpOnly cookie,
minted by `POST /auth/session` against a secret this app owns
(`TRMNL_UI_TOKEN_FILE`), enforced as one router-level dependency in
`routes/api.py`. Edge SSO stays as the outer gate; this is the inner one,
and it is the one that survives an edge misconfiguration — a broadened
bypass rule, `sso-enabled` flipped off, or a route accidentally registered
under `/api/`.

Deliberately *not* the panel's Access-Token. A compromise of the panel
credential must not become a control-plane write, and putting the panel
token in a browser (XSS, a copy-pasted curl, `document.referrer`) would
undo the gate `/api/display` depends on.

Stateless by construction: no DB table, no server-side session store, no
per-request SQLite write. The signing key is derived from the secret, so
rotating `TRMNL_UI_TOKEN_FILE` invalidates every outstanding session for
free — no revocation list to maintain. stdlib only (`hmac`, `hashlib`,
`secrets`, `base64`, `time`), so `propagatedBuildInputs` stays
`pillow fastapi uvicorn httpx sqlalchemy`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading
import time
from typing import Any, Dict

from fastapi import APIRouter, Body, HTTPException, Request, Response

from .. import config as config_module
from ..config import panel_config
from ..credentials import secret_equal

logger = config_module.logger

router = APIRouter()

COOKIE_NAME = "trmnl_ui"
# 30 days. The cookie is HttpOnly and SameSite=Strict, and the key rotates
# with the secret file, so a long life costs little and spares the operator
# a login every time they open the dashboard.
SESSION_TTL = 30 * 24 * 3600
_VERSION = "v1"
_KEY_CONTEXT = b"trmnl-ui-session-v1"

# Methods that cannot change state, and so do not need the origin check.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# --- POST /auth/session throttling ----------------------------------------
#
# This route is an unauthenticated oracle for the UI secret. It is nominally
# behind Authentik, but the premise of this whole module is that the app
# cannot tell an SSO'd request from a bypassed one, so it is bounded as
# though it were exposed. Only *failures* are counted, and a success clears
# the caller's counter: an operator who fat-fingers the secret once and then
# gets it right is never locked out by their own successful login, while a
# guesser gets ten tries per five minutes and no more.
_MINT_RATE_WINDOW = 300.0        # seconds
_MINT_FAIL_LIMIT = 10            # failed attempts per window per client
_MINT_GLOBAL_FAIL_LIMIT = 100    # failed attempts per window, all clients
_MINT_MAX_SOURCES = 512          # distinct clients tracked, to bound the dict
_mint_failures: dict[str, list[float]] = {}
_mint_global_failures: list[float] = []
_mint_lock = threading.Lock()


def _mint_source(request: Request) -> str:
    """Client address, or a single shared bucket when there is none.

    Behind Pangolin every request arrives from the Newt tunnel, so in
    production this is frequently one address for everyone — which is why
    the global counter exists and is not merely a backstop.
    """
    client = request.client
    return client.host if client and client.host else "unknown"


def _mint_allowed(source: str) -> bool:
    """False once this client, or the server as a whole, is over its budget."""
    now = time.monotonic()
    cutoff = now - _MINT_RATE_WINDOW
    with _mint_lock:
        hits = [t for t in _mint_failures.get(source, []) if t >= cutoff]
        if hits:
            _mint_failures[source] = hits
        else:
            _mint_failures.pop(source, None)
        if len(hits) >= _MINT_FAIL_LIMIT:
            return False
        global _mint_global_failures
        _mint_global_failures = [t for t in _mint_global_failures if t >= cutoff]
        return len(_mint_global_failures) < _MINT_GLOBAL_FAIL_LIMIT


def _mint_record_failure(source: str) -> None:
    now = time.monotonic()
    cutoff = now - _MINT_RATE_WINDOW
    with _mint_lock:
        if len(_mint_failures) > _MINT_MAX_SOURCES:
            for key in [
                k for k, v in _mint_failures.items() if not v or v[-1] < cutoff
            ]:
                del _mint_failures[key]
            if len(_mint_failures) > _MINT_MAX_SOURCES:
                _mint_failures.clear()
        hits = [t for t in _mint_failures.get(source, []) if t >= cutoff]
        hits.append(now)
        _mint_failures[source] = hits
        global _mint_global_failures
        _mint_global_failures = [t for t in _mint_global_failures if t >= cutoff]
        _mint_global_failures.append(now)


def _mint_clear(source: str) -> None:
    """A correct secret proves the caller is not the guesser being throttled."""
    with _mint_lock:
        _mint_failures.pop(source, None)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _session_key(secret: str) -> bytes:
    """Derive the cookie-signing key from the configured secret.

    Derived rather than used directly so the secret itself is never the
    thing being compared against attacker-supplied bytes, and so rotating
    the file invalidates every issued cookie.
    """
    return hmac.new(secret.encode("utf-8"), _KEY_CONTEXT, hashlib.sha256).digest()


def _sign(key: bytes, payload: str) -> str:
    return _b64(hmac.new(key, payload.encode("ascii"), hashlib.sha256).digest())


def mint_session(secret: str, *, ttl: int = SESSION_TTL) -> str:
    exp = int(time.time()) + ttl
    payload = f"{_VERSION}.{exp}.{secrets.token_hex(8)}"
    return f"{payload}.{_sign(_session_key(secret), payload)}"


def _valid_session_value(secret: str, value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    version, exp_raw, _nonce, signature = parts
    if version != _VERSION:
        return False
    payload = ".".join(parts[:3])
    expected = _sign(_session_key(secret), payload)
    # Constant-time compare before the (cheap) expiry check so a forged
    # signature and an expired-but-valid one cost the same. `secret_equal`
    # rather than `hmac.compare_digest` because the cookie is attacker-
    # supplied and header values decode as latin-1, so a non-ASCII cookie
    # would otherwise raise TypeError and 500 — see credentials.py.
    if not secret_equal(signature, expected):
        return False
    try:
        exp = int(exp_raw)
    except ValueError:
        return False
    return exp > time.time()


def has_ui_session(request: Request) -> bool:
    """True when the request carries a currently-valid session cookie."""
    secret = panel_config().ui_token()
    if not secret:
        return False
    raw = request.cookies.get(COOKIE_NAME)
    if not raw:
        return False
    return _valid_session_value(secret, raw)


def _same_origin(request: Request) -> bool:
    """CSRF layer 2: pin the origin of every state-changing request.

    `SameSite=Strict` is layer 1 and already blocks cross-site requests
    outright, including top-level navigations. This holds if a client ships
    with weak SameSite handling. Both headers are set by the browser and
    cannot be forged from page JS.
    """
    fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
    if fetch_site:
        return fetch_site in ("same-origin", "none")
    origin = (request.headers.get("origin") or "").strip().rstrip("/")
    if not origin:
        # No Origin and no Sec-Fetch-Site: not a browser (curl, the test
        # client). Browsers always send Origin on cross-origin state-changing
        # requests, so absence cannot be a cross-site forgery.
        return True
    configured = (panel_config().base_url or "").rstrip("/")
    if configured:
        # Pin to the configured origin and *only* that. `request.base_url` is
        # built from the Host header, which the client supplies: accepting it
        # meant the rule was "Origin must match a value the caller also
        # controls", which any request that can set both headers satisfies —
        # a rebound DNS name, a misconfigured upstream that forwards Host
        # verbatim, a proxy honouring X-Forwarded-Host. TRMNL_BASE_URL is set
        # by the NixOS module and is the one origin this deployment has.
        return origin == configured
    # No TRMNL_BASE_URL: a source checkout or a LAN box with no fixed name,
    # where there is nothing to pin to but the URL the request arrived on.
    # Weaker by necessity, and the reason the module logs at startup when
    # base_url is unset.
    return origin == str(request.base_url).rstrip("/")


def require_ui_session(request: Request) -> None:
    """Router-level dependency guarding the whole control plane.

    Fail-closed: with no `TRMNL_UI_TOKEN_FILE` configured there is no way to
    authenticate anyone, so the control plane is refused rather than opened.
    A silently-evaporating guard is precisely the failure mode this design
    exists to avoid.
    """
    if not panel_config().ui_token():
        logger.error(
            "control-plane request refused: TRMNL_UI_TOKEN_FILE is not "
            "configured, so no UI session can be minted or verified"
        )
        raise HTTPException(status_code=503, detail="ui token not configured")
    if not has_ui_session(request):
        raise HTTPException(status_code=401, detail="ui session required")
    if request.method.upper() not in _SAFE_METHODS and not _same_origin(request):
        raise HTTPException(status_code=403, detail="cross-origin request refused")


def _set_cookie(response: Response, value: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        value,
        max_age=SESSION_TTL,
        httponly=True,
        # Strict, not Lax: nothing links into a control-plane URL, `/` needs
        # no cookie to render, and the SPA's own XHRs are same-site.
        samesite="strict",
        # Only over TLS when the deployment is TLS. Keeping http://127.0.0.1
        # dev working matters more than a Secure flag a loopback browser
        # would then refuse to store.
        secure=(panel_config().base_url or "").startswith("https://"),
        path="/",
    )


@router.post("/auth/session")
def create_session(
    request: Request, data: Dict[str, Any] | None = Body(default=None)
) -> Response:
    """Exchange the UI secret for a session cookie.

    Accepts `X-TRMNL-UI-Token:` or a JSON body `{"token": "..."}` — JSON
    rather than a form specifically so `python-multipart` is not pulled into
    the closure.
    """
    secret = panel_config().ui_token()
    if not secret:
        return Response(status_code=503)
    source = _mint_source(request)
    if not _mint_allowed(source):
        logger.warning("session mint throttled for %s", source)
        return Response(status_code=429)
    supplied = request.headers.get("X-TRMNL-UI-Token") or ""
    if not supplied and isinstance(data, dict):
        candidate = data.get("token")
        if isinstance(candidate, str):
            supplied = candidate
    # One constant-time comparison on both branches, so a missing token and a
    # wrong one take the same path — and a non-ASCII one is a 401, not the
    # 500 `hmac.compare_digest` would raise on it.
    if not secret_equal(supplied.strip(), secret):
        _mint_record_failure(source)
        return Response(status_code=401)
    _mint_clear(source)
    response = Response(status_code=204)
    _set_cookie(response, mint_session(secret))
    return response


@router.delete("/auth/session")
def destroy_session(request: Request) -> Response:
    """Clear the session cookie.

    Origin-pinned like every other mutating route: without it, any page on
    the internet could log the operator out of their own dashboard on a
    loop. Deliberately *not* session-gated — clearing a cookie you may no
    longer hold a valid version of has to stay idempotent, or a browser
    holding an expired or rotated cookie could never get rid of it.
    """
    if not _same_origin(request):
        raise HTTPException(status_code=403, detail="cross-origin request refused")
    response = Response(status_code=204)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@router.get("/auth/session")
def session_state(request: Request) -> Dict[str, bool]:
    """Whether this browser holds a session, so the UI can show a login form.

    Leaks nothing: `configured` is derivable by anyone who can POST here and
    read the 503, and `authenticated` describes the caller's own cookie.
    """
    return {
        "configured": bool(panel_config().ui_token()),
        "authenticated": has_ui_session(request),
    }
