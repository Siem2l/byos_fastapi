"""The OIDC authorization-code flow, ending in the existing session mint.

Two routes plus an interstitial. Nothing here invents a session format, a
cookie or a gate: `/auth/oidc/callback` finishes by calling
`auth.issue_session()`, the same function `POST /auth/session` calls, so the
cookie an SSO login produces is the same shape as a shared-secret one and
everything downstream — `require_ui_session`, the origin pin,
rotation-invalidates-sessions — is unchanged by construction.

    shared-secret login ─┐
                         ├─→ issue_session() → trmnl_ui cookie → require_ui_session()
    OIDC code flow ──────┘

The one deliberate difference is *lifetime*. A shared-secret session lasts
`auth.SESSION_TTL` (30 days); an OIDC one lasts
`Config.oidc_session_lifetime()` (8 hours by default,
`TRMNL_OIDC_SESSION_TTL`), because it is a cached claim about an authorization
the identity provider granted and can withdraw — a group membership removed, an
account disabled — without this server ever being told. The shared secret has
no such external authority to fall out of step with. Nothing downstream reads
the difference: it is one number, carried identically in the signature and the
cookie's max-age.

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
from collections import OrderedDict
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
    _sign,
    client_source,
    issue_session,
)

logger = config_module.logger

router = APIRouter()

STATE_COOKIE = "trmnl_oidc_state"
# Five minutes is long enough for a password plus a TOTP prompt and short
# enough that an abandoned tab is not a standing credential.
STATE_TTL = 300
STATE_VERSION = "o1"
# A *different* key context from the session cookie's, so a session cookie can
# never be replayed as a state token or vice versa even though both are signed
# with the same underlying secret.
_STATE_KEY_CONTEXT = b"trmnl-oidc-state-v1"

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
CALLBACK_BUDGET = RateBudget(
    "oidc-callback",
    window=MINT_RATE_WINDOW,
    per_source_limit=10,
    global_limit=100,
)

# `LOGIN_BUDGET` counts *every* `/auth/oidc/login`, not just the failures.
#
# It is **not** what keeps the panel alive under a login flood, and sizing it
# as though it were is how it came to deny SSO to every operator after thirty
# anonymous GETs. What protects the device plane is `oidc.OUTBOUND_LIMIT`: a
# non-blocking semaphore that lets at most eight of anyio's forty threadpool
# workers be inside an IdP call and refuses the ninth immediately. Measured
# against a 64-thread flood with an IdP stalling one second per call:
#
#     both guards                       /api/display median  30.1 ms, worst  101.7 ms
#     this budget off, semaphore on     /api/display median  37.5 ms, worst  102.5 ms
#     neither                           /api/display median 944.4 ms, worst 1008.1 ms
#
# The semaphore is the whole effect; this budget's contribution to device
# latency is inside the noise. Meanwhile a per-source budget behind a
# tunnelling edge is one bucket for *everybody* — see `RateBudget`'s own
# docstring — so a low limit here is a lockout primitive that any anonymous
# caller can pull, for free, with no credential. A lockout an anonymous caller
# can trigger is a worse failure than the flood it was meant to stop.
#
# So the budget has exactly one job left: stop `_StateLedger` from ever being
# forced to evict a *live* state, which is the only way a redeemed state
# becomes replayable. The arithmetic that keeps that true, worst case:
#
#   1. A ledger entry exists only for a state `_unpack_state()` accepted,
#      which needs a signature made with this server's own secret — i.e. one
#      `/auth/oidc/login` minted. A throttled login mints none (`_fail()`
#      returns before the state is generated), so:
#          ledger entries created ≤ logins allowed.
#   2. Each entry needs a *distinct* state: claiming the same one twice is
#      precisely what the ledger refuses, and a refusal inserts nothing.
#   3. A state is only accepted within STATE_TTL of being minted (its signed
#      `exp`), and its ledger entry is dropped STATE_TTL after it was claimed
#      — expired entries first, before the membership test. So every entry
#      live at time T was minted somewhere in (T - 2·STATE_TTL, T].
#   4. This budget's window IS STATE_TTL, so at most LOGIN_GLOBAL_LIMIT states
#      are minted per STATE_TTL and therefore
#          live ledger entries ≤ 2 · LOGIN_GLOBAL_LIMIT = 8192,
#      against a bound of `_USED_STATE_MAX` = 16384. Twice the headroom the
#      worst case needs, and the eviction branch is unreachable.
#
# `_USED_STATE_MAX` is *derived* from LOGIN_GLOBAL_LIMIT below rather than
# asserted against it, so the two cannot drift apart in a later edit — raising
# the limit raises the ledger with it.
#
# On the other side: 4096 per five minutes is ~13.6 requests/second sustained
# before anyone is refused, against a legitimate rate of one request per human
# clicking "Sign in with ...". Nothing incidental — a crawler, a link-preview
# fetch, an uptime probe, every browser in the house retrying a dead IdP at
# once — comes within two orders of magnitude of that. Anything that does is a
# deliberate flood, and a deliberate flood is already being absorbed by
# `OUTBOUND_LIMIT` on the device plane's behalf and by the IdP's own rate
# limiting on the provider's.
LOGIN_RATE_WINDOW = float(STATE_TTL)
LOGIN_GLOBAL_LIMIT = 4096
# Half the global budget: where sources really are distinct (a LAN box, a
# directly-exposed host) one client cannot spend everybody's. Behind a tunnel
# the two collapse into a single 2048-per-five-minute bucket, which is still
# ~6.8 anonymous requests/second before an operator could notice anything.
LOGIN_PER_SOURCE_LIMIT = LOGIN_GLOBAL_LIMIT // 2
LOGIN_BUDGET = RateBudget(
    "oidc-login",
    window=LOGIN_RATE_WINDOW,
    per_source_limit=LOGIN_PER_SOURCE_LIMIT,
    global_limit=LOGIN_GLOBAL_LIMIT,
)

# Four times the login budget, i.e. twice the worst case derived above. Do not
# hard-code this: the point is that it moves with the limiter. See `_StateLedger`.
_USED_STATE_MAX = 4 * LOGIN_GLOBAL_LIMIT


class _StateLedger:
    """States that have already been redeemed, so none is redeemed twice.

    The state cookie is cleared on every callback, which alone defeats a
    replay from a *fresh* browser. This ledger defeats one from the same
    browser — the back button, a duplicated tab, a proxy that retries — where
    the cookie is still in flight.

    **There is deliberately no way to empty it.** The previous version cleared
    the whole dict on reaching its bound, which turned "single use" into "single
    use unless you first redeem a thousand states": an attacker could mint
    states from `/auth/oidc/login` at will, spend them to trip the flush, and
    then replay a state the ledger had forgotten. A flush primitive on a
    single-use ledger *is* the bypass.

    So eviction is FIFO by insertion, which is very nearly by expiry since
    every entry has the same TTL — the entry dropped is the one closest to
    ageing out anyway — and the bound is high enough that the rate limiter on
    `/auth/oidc/login` cannot fill it within one TTL. That last clause is a
    load-bearing coupling, not a remark: `_USED_STATE_MAX` is computed from
    `LOGIN_GLOBAL_LIMIT`, and the arithmetic proving 2·LOGIN_GLOBAL_LIMIT is
    the true worst case is written out above that constant. Deleting the
    limiter, or raising it without raising this bound, reopens the replay this
    ledger exists to close. The test suite gets a fresh instance rather than a
    flush; `reset_state_store()` is gone.
    """

    def __init__(self, maximum: int = _USED_STATE_MAX) -> None:
        self._maximum = maximum
        self._entries: OrderedDict[str, float] = OrderedDict()
        # Sync `def` handlers run in FastAPI's threadpool, so two callbacks
        # carrying the same state really can be in `claim()` at once. Without
        # this lock the check-then-set is a race and "single use" means
        # "usually single use".
        self._lock = threading.Lock()

    def claim(self, state: str) -> bool:
        """True the first time `state` is redeemed, False every time after."""
        now = time.monotonic()
        with self._lock:
            # Expired entries first, and *before* the membership test, so a
            # full ledger can never answer by evicting the very state being
            # asked about — which is how a bound turns into a bypass.
            while self._entries and next(iter(self._entries.values())) <= now:
                self._entries.popitem(last=False)
            if state in self._entries:
                return False
            while len(self._entries) >= self._maximum:
                self._entries.popitem(last=False)
                logger.warning(
                    "the OIDC single-use state ledger is at its %d-entry "
                    "bound and is evicting an unexpired state; either this "
                    "server is under a login flood or STATE_TTL is too long "
                    "for its traffic",
                    self._maximum,
                )
            self._entries[state] = now + STATE_TTL
            return True

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


_state_ledger = _StateLedger()


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

    # Before the state is minted, because minting is what this budget bounds:
    # every allowed login is one more entry the single-use ledger may have to
    # hold. The device plane's protection is `oidc.OUTBOUND_LIMIT`, further
    # down inside `discovery()`, not this. See the LOGIN_BUDGET comment.
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
        # `error` is a query parameter: whoever sent the browser here chose
        # it, IdP or not. Unbounded and unescaped it was a log-injection and
        # log-flooding primitive on an endpoint anyone can hit.
        logger.warning(
            "identity provider refused the authorization request: %s (%s)",
            oidc_module.redact(params.get("error")),
            oidc_module.redact(params.get("error_description"), 200),
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
    if not _state_ledger.claim(payload["state"]):
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
        # Before any claim in it is read, let alone used for authorization.
        oidc_module.bind_userinfo_subject(userinfo, id_claims)
        groups = oidc_module.check_groups(cfg, userinfo, id_claims)
    except oidc_module.OidcError as exc:
        logger.warning("OIDC login failed (%s): %s", exc.code, exc)
        CALLBACK_BUDGET.record(source)
        return _fail(exc.code)

    CALLBACK_BUDGET.clear(source)
    logger.info(
        "OIDC login accepted for %s (groups: %s)",
        # Both are provider-chosen strings; see oidc.redact().
        oidc_module.subject_label(userinfo, id_claims),
        oidc_module.redact(",".join(sorted(groups)), 200)
        if groups else "<none reported>",
    )
    response = RedirectResponse("/auth/oidc/complete", status_code=302)
    _clear_state_cookie(response)
    # The single join point. Same function, same cookie, same signing key, same
    # gate — see the module docstring. The one thing that differs is how long it
    # lasts: `oidc_session_lifetime()` rather than `auth.SESSION_TTL`, because
    # this session is a cached claim about an authorization the IdP can withdraw
    # without telling us. `issue_session` puts that number in both the signature
    # and the cookie's max-age, so the two cannot disagree.
    issue_session(response, secret, ttl=cfg.oidc_session_lifetime())
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
