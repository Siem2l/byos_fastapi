"""App-owned session auth for the browser control plane.

Why the app authenticates at all, on a deployment that already puts a
reverse proxy with SSO in front of everything outside `/api/*` and `/image/*`:

* **The edge may forward no identity.** Several popular reverse proxies have
  no `Remote-User`-style header injection at all: the authenticated user
  object is consumed internally by a plugin and never becomes a header the
  backend could read. So there may be nothing to read.
* **The backend cannot tell SSO from bypass.** One host, one upstream:
  `/api/display` (bypassed, because an ESP32 cannot do SSO) and `/status`
  (SSO'd) arrive on the same loopback socket via the same route and service.
  Where a per-route static header *is* available it is usually attached at
  the router level, which runs on the bypassed prefixes too — so a shared
  secret injected there proves "came through the proxy", never "passed the
  IdP", and nothing strips a client-supplied copy of it on the bypassed
  path.

Therefore: an app-owned, HMAC-signed, `SameSite=Strict`, HttpOnly cookie,
minted by `POST /auth/session` against a secret this app owns
(`TRMNL_UI_TOKEN_FILE`), enforced as one router-level dependency in
`routes/api.py`. Edge SSO stays as the outer gate where there is one; this
is the inner one, and it is the one that survives an edge misconfiguration —
a broadened bypass rule, SSO switched off, or a route accidentally registered
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
from .. import oidc as oidc_module
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

# --- throttling for unauthenticated routes ---------------------------------
#
# `POST /auth/session` is an unauthenticated oracle for the UI secret. It is
# nominally behind an edge IdP, but the premise of this whole module is that the
# app cannot tell an SSO'd request from a bypassed one, so it is bounded as
# though it were exposed. Only *failures* are counted, and a success clears
# the caller's counter: an operator who fat-fingers the secret once and then
# gets it right is never locked out by their own successful login, while a
# guesser gets ten tries per five minutes and no more.
#
# The counter is a class rather than a set of module globals because there is
# now more than one unauthenticated route that needs one, and they must NOT
# share a budget. A cross-site flood of `/auth/oidc/callback` costs the
# operator nothing if the OIDC path has its own accounting, and locks every
# operator out of the shared-secret form if it does not.


class RateBudget:
    """A sliding-window per-source *and* global counter.

    Two counters, not one: behind a tunnelling edge every request arrives from
    the same address, so a per-source limit alone is a limit of one bucket,
    and a global limit alone lets one noisy client spend everyone's budget.

    `source` is a client address, which an attacker on a shared egress can
    forge only by moving hosts — this is a cost multiplier, not an identity.
    """

    def __init__(
        self,
        name: str,
        *,
        window: float,
        per_source_limit: int,
        global_limit: int,
        max_sources: int = 512,
    ) -> None:
        self.name = name
        self.window = window
        self.per_source_limit = per_source_limit
        self.global_limit = global_limit
        self.max_sources = max_sources
        self._per_source: dict[str, list[float]] = {}
        self._global: list[float] = []
        self._lock = threading.Lock()

    def allowed(self, source: str) -> bool:
        """False once this client, or the server as a whole, is over budget."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            hits = [t for t in self._per_source.get(source, []) if t >= cutoff]
            if hits:
                self._per_source[source] = hits
            else:
                self._per_source.pop(source, None)
            if len(hits) >= self.per_source_limit:
                return False
            self._global = [t for t in self._global if t >= cutoff]
            return len(self._global) < self.global_limit

    def record(self, source: str) -> None:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            if len(self._per_source) > self.max_sources:
                for key in [
                    k for k, v in self._per_source.items()
                    if not v or v[-1] < cutoff
                ]:
                    del self._per_source[key]
                if len(self._per_source) > self.max_sources:
                    self._per_source.clear()
            hits = [t for t in self._per_source.get(source, []) if t >= cutoff]
            hits.append(now)
            self._per_source[source] = hits
            self._global = [t for t in self._global if t >= cutoff]
            self._global.append(now)

    def clear(self, source: str) -> None:
        """A correct secret proves the caller is not the guesser being throttled."""
        with self._lock:
            self._per_source.pop(source, None)

    def reset(self) -> None:
        """Drop every counter. For the test suite, which builds ~30 apps."""
        with self._lock:
            self._per_source.clear()
            self._global.clear()

    def tracked(self, source: str) -> int:
        """How many hits are currently attributed to `source`. Diagnostics only."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            return len([t for t in self._per_source.get(source, []) if t >= cutoff])


MINT_RATE_WINDOW = 300.0        # seconds
MINT_FAIL_LIMIT = 10            # failed attempts per window per client
MINT_GLOBAL_FAIL_LIMIT = 100    # failed attempts per window, all clients

MINT_BUDGET = RateBudget(
    "session-mint",
    window=MINT_RATE_WINDOW,
    per_source_limit=MINT_FAIL_LIMIT,
    global_limit=MINT_GLOBAL_FAIL_LIMIT,
)


def client_source(request: Request) -> str:
    """Client address, or a single shared bucket when there is none.

    Behind a reverse proxy or a tunnel every request arrives from one
    address, so in production this is frequently a single bucket for everyone
    — which is why the global counter exists and is not merely a backstop.
    """
    client = request.client
    return client.host if client and client.host else "unknown"


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
    # `_sign` does `payload.encode("ascii")`, and this payload is the first
    # three fields of an attacker-supplied cookie — header values decode as
    # latin-1, so a non-ASCII byte anywhere in them raised UnicodeEncodeError
    # and 500 before any comparison happened. `secret_equal` already covers
    # the signature field; this covers the other three.
    if not value.isascii():
        return False
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
    """True when the request carries a currently-valid session cookie.

    `session_secret()`, not `ui_token()`: the cookie is the same whichever
    login path minted it, and on an OIDC-only deployment there is no
    `TRMNL_UI_TOKEN_FILE` to derive a key from. See `Config.session_secret`.
    """
    secret = panel_config().session_secret()
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
        # by the deployment and is the one origin this server has.
        return origin == configured
    # No TRMNL_BASE_URL: a source checkout or a LAN box with no fixed name,
    # where there is nothing to pin to but the URL the request arrived on.
    # Weaker by necessity, and the reason the module logs at startup when
    # base_url is unset.
    return origin == str(request.base_url).rstrip("/")


def require_ui_session(request: Request) -> None:
    """Router-level dependency guarding the whole control plane.

    Fail-closed: with *neither* login method configured there is no way to
    authenticate anyone and no key to sign a session with, so the control
    plane is refused rather than opened. A silently-evaporating guard is
    precisely the failure mode this design exists to avoid. Adding OIDC
    widened the predicate from one input to two; it did not weaken it.
    """
    if not panel_config().session_secret():
        logger.error(
            "control-plane request refused: neither TRMNL_UI_TOKEN_FILE nor "
            "TRMNL_OIDC_CLIENT_SECRET_FILE is configured, so no UI session "
            "can be minted or verified"
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
    source = client_source(request)
    if not MINT_BUDGET.allowed(source):
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
        MINT_BUDGET.record(source)
        return Response(status_code=401)
    MINT_BUDGET.clear(source)
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
def session_state(request: Request) -> Dict[str, Any]:
    """Which login methods exist and whether this browser has used one.

    Leaks nothing an unauthenticated caller cannot already establish:
    `configured` is derivable from the 503-vs-401 on `POST /auth/session`,
    `oidc` from whether `/auth/oidc/login` redirects to a provider, and
    `authenticated` describes the caller's own cookie. `oidc_provider` is a
    display name the operator chose (or the issuer's hostname), which is
    about to appear on a button on this very page.

    The four fields are what lets the UI render the *right* thing rather
    than a token form that can only ever 503 — the state a half-configured
    box was previously stuck in.
    """
    cfg = panel_config()
    oidc_available = oidc_module.enabled(cfg)
    return {
        "configured": bool(cfg.ui_token()),
        "authenticated": has_ui_session(request),
        "oidc": oidc_available,
        "oidc_provider": oidc_module.provider_name(cfg) if oidc_available else None,
    }
