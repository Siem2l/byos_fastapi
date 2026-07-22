"""The OIDC authorization-code flow, ending in the existing session mint.

Two routes plus an interstitial. Nothing here invents a session format, a
cookie or a gate: `/auth/oidc/callback` finishes by calling
`auth.mint_session()` and `auth._set_cookie()`, the same two functions
`POST /auth/session` calls, so the cookie an SSO login produces is
byte-indistinguishable from a shared-secret one and everything downstream —
`require_ui_session`, the origin pin, the TTL, rotation-invalidates-sessions
— is unchanged by construction.

    shared-secret login ─┐
                         ├─→ mint_session() → trmnl_ui cookie → require_ui_session()
    OIDC code flow ──────┘

**This router is not under `/api/`, and must never be.** The panel is an
ESP32 that follows no redirects and cannot do SSO; the edge bypasses SSO for
`/api/*` precisely so it can talk. `main.py::_assert_route_invariants()`
refuses to build the app if a control-plane route appears under that prefix.

Three non-obvious decisions, each of which looks like a mistake without the
reason:

1. **The state cookie is `SameSite=Lax`, not `Strict`.** The callback is a
   cross-site-initiated top-level navigation from the IdP. A `Strict` cookie
   is *not sent* on that request, so a Strict state cookie would break every
   real login while leaving `curl` unaffected. The session cookie stays
   `Strict`; only this short-lived, single-purpose one is relaxed, and it is
   scoped to `path=/auth/oidc` so it is never sent anywhere else.

2. **`_same_origin()` is not used on the callback**, though the design doc
   suggested it. It returns False for exactly the `Sec-Fetch-Site:
   cross-site` header a genuine IdP redirect carries, and True for a request
   with no `Sec-Fetch-Site` at all — so applying it would refuse every real
   login and admit every scripted one. The callback's CSRF defence is the
   signed, single-use, verifier-bound `state`, which is what OIDC specifies
   for this and what actually binds the response to *this* browser's login
   attempt.

3. **Success 302s to `/auth/oidc/complete`, which then navigates to `/`.**
   The freshly-minted session cookie is `SameSite=Strict`; a redirect chain
   that began cross-site does not carry it in Chromium, so a direct 302 to
   `/` produces a dashboard that reports itself logged out until the operator
   reloads — a bug that reads as flakiness. The interstitial's own navigation
   is same-site-initiated and does carry it. It also gets the authorization
   code out of the address bar and browser history.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import config as config_module
from .. import oidc as oidc_module
from ..config import panel_config
from ..credentials import secret_equal
from .auth import (
    MINT_RATE_WINDOW,
    RateBudget,
    _b64,
    _set_cookie,
    _sign,
    client_source,
    mint_session,
)

logger = config_module.logger

router = APIRouter()

# --- throttling ------------------------------------------------------------
#
# Two budgets, and neither is the shared-secret form's.
#
# `CALLBACK_BUDGET` counts failed callbacks. It used to be `auth`'s mint
# counter, which meant a hundred cross-site GETs on `/auth/oidc/callback` —
# free to send, requiring no credential and no cookie — spent the *global*
# mint budget and locked every operator out of `POST /auth/session`. An
# attacker who cannot guess the secret could still deny it to everyone. The
# two paths are different oracles over different secrets, so they get
# different accounting; a failure on one must never cost the other.
#
# `LOGIN_BUDGET` counts *every* `/auth/oidc/login`, not just failures, because
# a successful login is precisely what costs the server an outbound round trip.
# This is the first of the two bounds on that endpoint; `oidc.OUTBOUND_LIMIT`
# is the second and is the one that holds when the flood is distributed.
CALLBACK_BUDGET = RateBudget(
    "oidc-callback",
    window=MINT_RATE_WINDOW,
    per_source_limit=10,
    global_limit=100,
)
# A human clicking "Sign in with ..." generates one of these. Thirty per five
# minutes per client is a fat margin over a person retrying a failed login,
# and three hundred globally is far more SSO logins than a panel server sees.
LOGIN_BUDGET = RateBudget(
    "oidc-login",
    window=MINT_RATE_WINDOW,
    per_source_limit=30,
    global_limit=300,
)

STATE_COOKIE = "trmnl_oidc_state"
# Five minutes is long enough for a password plus a TOTP prompt and short
# enough that an abandoned tab is not a standing credential.
STATE_TTL = 300
STATE_VERSION = "o1"
# A *different* key context from the session cookie's, so a session cookie can
# never be replayed as a state token or vice versa even though both are signed
# with the same underlying secret.
_STATE_KEY_CONTEXT = b"trmnl-oidc-state-v1"

# States that have already been redeemed. The cookie is cleared on every
# callback, which alone defeats a replay from a *fresh* browser; this also
# defeats one from the same browser (the back button, a duplicated tab, a
# proxy that retries), where the cookie is still in flight.
_USED_STATE_MAX = 1024
_used_states: dict[str, float] = {}
# Sync `def` handlers run in FastAPI's threadpool, so two callbacks carrying
# the same state really can be in `_claim_state` at once. Without this lock
# the check-then-set is a race and "single use" means "usually single use".
_used_lock = threading.Lock()


def reset_state_store() -> None:
    """Drop the single-use state ledger. Called by the test suite."""
    with _used_lock:
        _used_states.clear()


def _state_key(secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), _STATE_KEY_CONTEXT, hashlib.sha256).digest()


def _pack_state(secret: str, payload: dict[str, Any]) -> str:
    """Sign a state payload into an ASCII cookie value.

    Base64url around the JSON is not decoration: `auth._sign()` does
    `payload.encode("ascii")`, so a raw JSON blob carrying a non-ASCII byte
    would raise `UnicodeEncodeError` and 500 instead of failing a comparison.
    """
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signed = f"{STATE_VERSION}.{body}"
    return f"{signed}.{_sign(_state_key(secret), signed)}"


def _unpack_state(secret: str, raw: str) -> dict[str, Any] | None:
    """Verify and decode a state cookie. Never raises on hostile input.

    The ASCII guard is load-bearing, not belt-and-braces: `auth._sign()` does
    `payload.encode("ascii")` and cookie bytes decode as latin-1, so a single
    non-ASCII byte in the cookie would otherwise be an unhandled
    UnicodeEncodeError — a 500 on a route reachable by anyone, instead of a
    refused login.
    """
    if not raw.isascii():
        return None
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    version, body, signature = parts
    if version != STATE_VERSION:
        return None
    expected = _sign(_state_key(secret), f"{version}.{body}")
    # `secret_equal`, not `hmac.compare_digest`: the cookie is attacker-
    # supplied and header values decode as latin-1, so a non-ASCII one would
    # otherwise be a 500 rather than a refused login. See credentials.py.
    if not secret_equal(signature, expected):
        return None
    try:
        # binascii.Error and UnicodeDecodeError are both ValueError, so this
        # covers a malformed base64 body, non-UTF-8 bytes and invalid JSON.
        payload = json.loads(oidc_module.b64url_decode(body))
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    try:
        if int(payload.get("exp", 0)) <= time.time():
            return None
    except (TypeError, ValueError):
        return None
    for key in ("state", "verifier", "nonce"):
        if not isinstance(payload.get(key), str) or not payload[key]:
            return None
    return payload


def _claim_state(state: str) -> bool:
    """True the first time `state` is redeemed, False every time after."""
    now = time.monotonic()
    with _used_lock:
        for key in [k for k, expiry in _used_states.items() if expiry <= now]:
            _used_states.pop(key, None)
        if state in _used_states:
            return False
        if len(_used_states) >= _USED_STATE_MAX:
            # Bounded rather than unbounded: the entries expire in STATE_TTL
            # anyway, and a flood of unredeemed states must not become a leak.
            _used_states.clear()
        _used_states[state] = now + STATE_TTL
        return True


def _set_state_cookie(response: Response, value: str) -> None:
    response.set_cookie(
        STATE_COOKIE,
        value,
        max_age=STATE_TTL,
        httponly=True,
        # Lax, and only here — see the module docstring. Strict would not be
        # sent on the IdP's cross-site-initiated return navigation.
        samesite="lax",
        # Never sent to anything but the two OIDC routes.
        path="/auth/oidc",
        secure=(panel_config().base_url or "").startswith("https://"),
    )


def _clear_state_cookie(response: Response) -> None:
    response.delete_cookie(STATE_COOKIE, path="/auth/oidc")


def _fail(code: str) -> RedirectResponse:
    """Send the browser home with a code the SPA can explain.

    A fixed vocabulary only. Nothing the identity provider said is ever
    reflected into a URL or the DOM.
    """
    if code not in oidc_module.LOGIN_ERROR_CODES:  # pragma: no cover - guard
        code = "oidc_provider"
    response = RedirectResponse(f"/?login_error={code}", status_code=302)
    _clear_state_cookie(response)
    return response


@router.get("/auth/oidc/login")
def oidc_login(request: Request) -> Response:
    """Start the code flow: mint state + PKCE, 302 to the provider.

    Takes no parameters at all — deliberately. There is no `next`, no
    `redirect_uri`, no `return_to`: the redirect URI is derived from
    `TRMNL_BASE_URL` and the post-login destination is always `/`. That is
    the entire mitigation for the open-redirect class, and it is free because
    a single-page dashboard has nowhere else to land.
    """
    cfg = panel_config()
    problem = oidc_module.configuration_problem(cfg)
    if problem:
        logger.warning("/auth/oidc/login refused: %s", problem)
        return _fail("oidc_disabled")
    secret = cfg.session_secret()
    if not secret:  # pragma: no cover - implied by configuration_problem
        return _fail("oidc_disabled")

    # Before any outbound work, and before any allocation: this endpoint is
    # unauthenticated and the panel shares the threadpool it would otherwise
    # spend. See the LOGIN_BUDGET comment.
    source = client_source(request)
    if not LOGIN_BUDGET.allowed(source):
        logger.warning("/auth/oidc/login throttled for %s", source)
        return _fail("oidc_throttled")
    LOGIN_BUDGET.record(source)

    try:
        document = oidc_module.discovery(cfg)
    except oidc_module.OidcError as exc:
        logger.error("/auth/oidc/login refused: %s", exc)
        return _fail(exc.code)

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    # 64 bytes of entropy: RFC 7636 allows 43-128 characters and there is no
    # reason to be near the floor.
    verifier = secrets.token_urlsafe(64)
    url = oidc_module.authorization_url(
        cfg,
        document,
        state=state,
        nonce=nonce,
        code_challenge=oidc_module.code_challenge_for(verifier),
        redirect_uri=cfg.oidc_callback_url(),
    )
    response = RedirectResponse(url, status_code=302)
    _set_state_cookie(response, _pack_state(secret, {
        "exp": int(time.time()) + STATE_TTL,
        "state": state,
        "nonce": nonce,
        "verifier": verifier,
    }))
    return response


@router.get("/auth/oidc/callback")
def oidc_callback(request: Request) -> Response:
    """Finish the flow and mint the ordinary session cookie.

    Throttled on `CALLBACK_BUDGET`, which is shaped like `POST /auth/session`'s
    but is emphatically *not* the same counter. Both are unauthenticated
    endpoints that answer differently depending on whether a supplied value was
    right, so both need a budget; behind a tunnelling edge every caller shares
    one source address, so both need a global counter as well as a per-source
    one. But they are oracles over *different* secrets, and sharing one budget
    meant a hundred cross-site GETs here — free to send, no credential, no
    cookie — locked every operator out of the shared-secret form.
    """
    cfg = panel_config()
    if oidc_module.configuration_problem(cfg):
        return _fail("oidc_disabled")
    secret = cfg.session_secret()
    if not secret:  # pragma: no cover - implied by configuration_problem
        return _fail("oidc_disabled")

    source = client_source(request)
    if not CALLBACK_BUDGET.allowed(source):
        logger.warning("OIDC callback throttled for %s", source)
        return _fail("oidc_throttled")

    params = request.query_params
    if params.get("error"):
        # The provider refused. Log what it said; show the operator a code.
        logger.warning(
            "identity provider refused the authorization request: %s",
            params.get("error"),
        )
        CALLBACK_BUDGET.record(source)
        return _fail("oidc_provider")

    cookie = request.cookies.get(STATE_COOKIE) or ""
    payload = _unpack_state(secret, cookie) if cookie else None
    supplied_state = params.get("state") or ""
    if payload is None or not secret_equal(supplied_state, payload["state"]):
        logger.warning(
            "OIDC callback refused: state cookie missing, expired, forged or "
            "not matching the state parameter"
        )
        CALLBACK_BUDGET.record(source)
        return _fail("oidc_state")
    if not _claim_state(payload["state"]):
        logger.warning("OIDC callback refused: state was already redeemed")
        CALLBACK_BUDGET.record(source)
        return _fail("oidc_state")

    # RFC 9207. Optional, and only a few providers send it, but when it is
    # present a mismatch means the response came from a different issuer than
    # the one the flow started with.
    supplied_issuer = params.get("iss")
    if supplied_issuer and oidc_module.normalise_issuer(
        supplied_issuer
    ) != oidc_module.normalise_issuer(cfg.oidc_issuer):
        logger.warning(
            "OIDC callback refused: the `iss` parameter does not match the "
            "configured issuer"
        )
        CALLBACK_BUDGET.record(source)
        return _fail("oidc_state")

    code = params.get("code") or ""
    if not code:
        CALLBACK_BUDGET.record(source)
        return _fail("oidc_state")

    try:
        document = oidc_module.discovery(cfg)
        tokens = oidc_module.exchange_code(
            cfg,
            document,
            code=code,
            code_verifier=payload["verifier"],
            redirect_uri=cfg.oidc_callback_url(),
        )
        id_claims: dict[str, Any] = {}
        raw_id_token = tokens.get("id_token")
        if not isinstance(raw_id_token, str) or not raw_id_token:
            raise oidc_module.OidcError(
                "oidc_provider", "token response carried no id_token"
            )
        id_claims = oidc_module.decode_jwt_claims(raw_id_token)
        # Signature: deliberately unchecked, per OIDC Core §3.1.3.7 item 6 and
        # the oidc.py module docstring. *Claims*: checked, because item 6 is
        # one item and the rest of §3.1.3.7 is the part that says this token
        # was minted for this client, by this issuer, and has not expired.
        oidc_module.validate_id_claims(cfg, document, id_claims)
        if not secret_equal(id_claims.get("nonce"), payload["nonce"]):
            raise oidc_module.OidcError(
                "oidc_nonce",
                "the id_token's nonce does not match the one this server "
                "sent, so the response does not belong to this login attempt",
            )
        userinfo = oidc_module.fetch_userinfo(document, tokens["access_token"])
        groups = oidc_module.check_groups(cfg, userinfo, id_claims)
    except oidc_module.OidcError as exc:
        logger.warning("OIDC login failed (%s): %s", exc.code, exc)
        CALLBACK_BUDGET.record(source)
        return _fail(exc.code)

    CALLBACK_BUDGET.clear(source)
    logger.info(
        "OIDC login accepted for %s (groups: %s)",
        oidc_module.subject_label(userinfo, id_claims),
        ",".join(sorted(groups)) or "<none reported>",
    )
    response = RedirectResponse("/auth/oidc/complete", status_code=302)
    _clear_state_cookie(response)
    # The single join point. Same function, same cookie, same everything as
    # the shared-secret path — see the module docstring.
    _set_cookie(response, mint_session(secret))
    return response


# A same-origin document whose only job is to navigate to `/` itself, so the
# navigation that loads the dashboard is same-site-initiated and therefore
# carries the SameSite=Strict session cookie. `replace()` keeps the callback
# out of the back-button history. The `<meta refresh>` is the no-JS fallback;
# there is no third-party anything here, and no inline script that reads
# anything from the URL.
_COMPLETE_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Signed in</title>
<meta http-equiv="refresh" content="0; url=/">
</head><body>
<p>Signed in. <a href="/">Continue to the dashboard</a>.</p>
<script>location.replace('/');</script>
</body></html>
"""


@router.get("/auth/oidc/complete")
def oidc_complete() -> Response:
    """Post-login interstitial. See decision 3 in the module docstring."""
    return HTMLResponse(_COMPLETE_PAGE)
