"""Provider-agnostic OIDC plumbing: discovery, code exchange, userinfo.

No FastAPI in this module and no new dependencies. `httpx` is already in the
runtime closure, and discovery, the token exchange and the userinfo call are
plain HTTPS requests — so `propagatedBuildInputs` stays
`pillow fastapi uvicorn httpx sqlalchemy`.

**Why there is no local ID-token signature check.** OIDC Core §3.1.3.7 item 6
permits it: the ID token is received *directly from the token endpoint*, over
TLS, with client authentication, so the transport plus `client_secret` is
already the security boundary and a second signature check over the same
bytes proves nothing new. Identity therefore comes from the `userinfo`
endpoint, which is an authenticated call in its own right. This is the one
place a JWT/crypto dependency would otherwise be unavoidable, and avoiding it
is a hard requirement for the Nix packaging downstream. Strict local
validation slots in behind an optional extra later without changing the flow.

**What this module deliberately does not do**: talk to the database, hold a
session, or know anything about cookies. It hands `routes/oidc.py` a
validated set of claims; that module ends the flow in the *existing*
`auth.mint_session()`.

**The HTTP seam.** Everything outbound goes through `_http_client()`, and it
honours the module-level `HTTP_TRANSPORT`. That is the one hook the test
suite needs to point the whole flow at an in-process fake IdP with no
network. Requests are synchronous, matching every other route in this app
(`utils.py` already does a blocking `httpx.get`): FastAPI runs sync handlers
in a threadpool, so a blocking call here cannot stall the event loop the
plugin refresher shares.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx

from . import config as config_module
from .config import Config

logger = config_module.logger

DISCOVERY_PATH = "/.well-known/openid-configuration"
# Providers change endpoints roughly never, and a stale document costs a
# failed login at worst. An hour keeps the outbound request rate at one per
# hour per issuer.
DISCOVERY_TTL = 3600.0
# Failures are NOT cached as failures for long — the design requires a
# discovery outage to heal by itself — but they are not retried on every
# single request either, or an unreachable IdP would turn each hit on
# /auth/oidc/login into an outbound connection attempt.
DISCOVERY_RETRY_BACKOFF = 15.0
HTTP_TIMEOUT = 10.0
# The largest reply this server will read from an identity provider. A
# discovery document is a couple of kilobytes, a token response a few hundred
# bytes, a userinfo response less; 256 KiB is two orders of magnitude of
# headroom and still small enough that a hostile provider cannot use this
# process's memory as a weapon against the panel sharing it.
MAX_RESPONSE_BYTES = 256 * 1024

# --- the device plane's share of the threadpool ----------------------------
#
# Every route in this app is a sync `def`, so FastAPI runs each one in anyio's
# threadpool — which defaults to 40 workers and is *shared* with `/api/display`,
# `/api/setup` and `/api/log`. A blocking outbound call therefore does not stall
# the event loop, but it does hold a worker for up to `HTTP_TIMEOUT` seconds.
#
# `/auth/oidc/login` is unauthenticated and does outbound work, so without a
# bound an unauthenticated flood parks every worker on a slow IdP and the panel
# — which cannot retry, cannot follow a redirect and has no way to report the
# failure — simply stops updating. That is a control-plane endpoint taking the
# device plane down with it, which is the one thing this fork's route split
# exists to prevent.
#
# So: at most OUTBOUND_LIMIT threadpool workers may ever be inside an IdP call
# (or waiting on one), leaving 40 - OUTBOUND_LIMIT for everything else. Over
# the limit the login is refused immediately with `oidc_throttled` rather than
# queued, because queueing is exactly the resource the attacker is after.
OUTBOUND_LIMIT = 8
# How long a follower waits for the in-flight discovery fetch it is sharing.
# Bounded by the same timeout the fetch itself has, plus a little slack.
OUTBOUND_WAIT = HTTP_TIMEOUT + 1.0

_outbound_slots = threading.BoundedSemaphore(OUTBOUND_LIMIT)

# Test seam. Production leaves this None and httpx builds its own transport;
# tests set an in-process transport so the entire flow runs with no network.
HTTP_TRANSPORT: httpx.BaseTransport | None = None

_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_discovery_failures: dict[str, tuple[float, str]] = {}
# Single-flight: one in-flight discovery fetch per issuer, whatever the arrival
# rate. Without it N concurrent cold logins are N outbound requests, which both
# hammers the IdP and multiplies the number of workers parked on it.
_discovery_inflight: dict[str, threading.Event] = {}
_discovery_lock = threading.Lock()

# The fixed vocabulary the callback is allowed to put in `?login_error=`.
# Codes only: nothing the IdP said is ever reflected into a URL or the DOM,
# and the UI maps these to its own strings.
LOGIN_ERROR_CODES = frozenset({
    "oidc_disabled",
    "oidc_state",
    "oidc_provider",
    "oidc_nonce",
    "oidc_group",
    "oidc_group_claim_missing",
    "oidc_userinfo_jwt",
    "oidc_throttled",
    "oidc_claims",
    "oidc_subject",
})

# OIDC Core §3.1.3.7 item 10 leaves the acceptable clock skew to the client.
# Two minutes: large enough that a provider without NTP does not lock everyone
# out, small enough that an expired token is not usable for a working day.
CLOCK_SKEW = 120

# Distinguishes "the claim is not there" from "the claim is there and empty",
# which is the difference between "your IdP is not sending groups" and "your
# account is in no allowed group" — the single most useful thing this feature
# can tell a misconfigured operator.
MISSING = object()


def redact(value: object, limit: int = 120) -> str:
    """A log-safe rendering of something the identity provider chose.

    Three jobs, all of them about the *log* being an attacker-writable file:
    control characters (a newline above all) are escaped so a hostile claim
    cannot forge a second log line; the result is truncated so a megabyte of
    JSON cannot fill the journal; and the whole thing is `repr`-quoted so the
    boundaries of the untrusted span are visible.

    Never pass a credential through here — a truncated secret is still a
    leaked prefix. Tokens, authorization codes and the client secret are not
    logged at all, at any length.
    """
    text = value if isinstance(value, str) else repr(value)
    if len(text) > limit:
        text = text[:limit] + f"...(+{len(text) - limit} more)"
    return repr(text)


class OidcError(RuntimeError):
    """A login failure with a stable code for the UI and detail for the log.

    `code` is one of `LOGIN_ERROR_CODES` and is safe to put in a URL.
    `str(exc)` is for the server log only and may quote the provider.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def reset_caches() -> None:
    """Drop every module-global cache.

    Called by the test suite between apps. The suite builds ~30 apps in one
    process, and a leaked discovery document would let a test pass for the
    wrong reason.
    """
    with _discovery_lock:
        _discovery_cache.clear()
        _discovery_failures.clear()
        for event in _discovery_inflight.values():
            event.set()
        _discovery_inflight.clear()


class IdpResponse:
    """The parts of a bounded IdP response this module is willing to look at.

    Not an `httpx.Response`: the point is that the body has already been read
    under a cap and cannot be re-read unbounded by accident.
    """

    __slots__ = ("status_code", "content_type", "content")

    def __init__(self, status_code: int, content_type: str, content: bytes) -> None:
        self.status_code = status_code
        self.content_type = content_type
        self.content = content

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", "replace")

    def json(self) -> Any:
        """Raises `ValueError` on a non-JSON body, like `httpx.Response.json`."""
        return json.loads(self.content)


def _read_capped(client: httpx.Client, request: httpx.Request, what: str) -> IdpResponse:
    """Send `request` and read at most `MAX_RESPONSE_BYTES` of the answer.

    The identity provider is a remote party this server talks to on the say-so
    of an unauthenticated caller. Nothing bounded the reply, so a hostile or
    broken IdP could answer `/auth/oidc/login` with a gigabyte and have this
    process buffer all of it — one request, unbounded memory, and the panel
    lives in the same process.

    `Content-Length` is checked first (cheap, and honest providers set it) and
    the stream is then capped anyway, because that header is a claim, not a
    fact.
    """
    response = client.send(request, stream=True)
    try:
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                if int(declared) > MAX_RESPONSE_BYTES:
                    raise OidcError(
                        "oidc_provider",
                        f"the {what} response declares {int(declared)} bytes, "
                        f"over this server's {MAX_RESPONSE_BYTES}-byte cap",
                    )
            except ValueError:
                pass  # An unparseable Content-Length; the stream cap covers it.
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise OidcError(
                    "oidc_provider",
                    f"the {what} response exceeded this server's "
                    f"{MAX_RESPONSE_BYTES}-byte cap",
                )
            chunks.append(chunk)
        content_type = (
            (response.headers.get("content-type") or "").split(";")[0].strip().lower()
        )
        return IdpResponse(response.status_code, content_type, b"".join(chunks))
    finally:
        response.close()


def _http_client() -> httpx.Client:
    return httpx.Client(
        timeout=HTTP_TIMEOUT,
        # Never chase a redirect: a token endpoint that 302s is either
        # misconfigured or is trying to move a client_secret somewhere it was
        # not sent.
        follow_redirects=False,
        transport=HTTP_TRANSPORT,
    )


@contextmanager
def outbound_slot(what: str) -> Iterator[None]:
    """Hold one of the OUTBOUND_LIMIT permits, or refuse the login outright.

    Non-blocking on purpose. See the OUTBOUND_LIMIT comment: an unauthenticated
    caller must never be able to make a threadpool worker wait, because the
    worker is the thing `/api/display` also needs.
    """
    if not _outbound_slots.acquire(blocking=False):
        raise OidcError(
            "oidc_throttled",
            f"refusing to start an outbound {what} call: all {OUTBOUND_LIMIT} "
            "OIDC slots are busy. The device plane shares this server's "
            "threadpool and keeps its share.",
        )
    try:
        yield
    finally:
        _outbound_slots.release()


# --- configuration ---------------------------------------------------------


def normalise_issuer(value: str) -> str:
    """Trailing-slash-insensitive issuer.

    authentik's per-application issuer ends in `/`; the other four providers
    surveyed do not. Naive concatenation produces
    `.../trmnl//.well-known/openid-configuration`.
    """
    return (value or "").strip().rstrip("/")


def _is_absolute_http_url(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _is_loopback(host: str) -> bool:
    """True for 127.0.0.0/8, ::1 and the `localhost` names RFC 6761 reserves."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def is_secure_url(value: object) -> bool:
    """https anywhere, or http only to loopback.

    The reason this exists at all is that the whole zero-dependency design
    rests on OIDC Core §3.1.3.7 item 6, which permits skipping the ID token
    signature check *only* because the token arrived "directly from the Token
    Endpoint ... over a TLS-protected channel". Take the TLS away and the
    premise is gone: an unsigned-in-practice assertion over plaintext is
    whatever the network says it is, and so is the `client_secret` sent to
    fetch it. Accepting an `http://` issuer therefore did not weaken one
    check, it invalidated the argument for not having one.

    Loopback is the exception, and only loopback: `http://127.0.0.1:8105` has
    no network to be on, and a developer running the server and the IdP on one
    machine is the case this feature has to stay usable for. It is documented
    in the README as the only plaintext arrangement that works.
    """
    if not _is_absolute_http_url(value):
        return False
    parts = urlsplit(str(value))
    if parts.scheme == "https":
        return True
    return _is_loopback(parts.hostname or "")


def is_configured(cfg: Config) -> bool:
    """The operator asked for OIDC, whether or not it actually works."""
    return bool(cfg.oidc_issuer)


def configuration_problem(cfg: Config) -> str | None:
    """None when the OIDC login path can be offered; else why it cannot.

    Config shape only — nothing here touches the network, because a
    discovery outage must never disable a login method at startup (or lock
    out the shared-secret path, which is the failure this ordering exists to
    prevent).
    """
    if not cfg.oidc_issuer:
        return "TRMNL_OIDC_ISSUER is not set"
    if not _is_absolute_http_url(cfg.oidc_issuer):
        return (
            f"TRMNL_OIDC_ISSUER {cfg.oidc_issuer!r} is not an absolute "
            "http(s) URL"
        )
    if not is_secure_url(cfg.oidc_issuer):
        return (
            f"TRMNL_OIDC_ISSUER {cfg.oidc_issuer!r} is plaintext http to a "
            "non-loopback host. This server does not verify the ID token "
            "signature, which OIDC Core 3.1.3.7 item 6 only permits over a "
            "TLS-protected channel — so without https there is nothing left "
            "authenticating the provider. Use https, or point the issuer at "
            "loopback for local development."
        )
    if not cfg.oidc_client_id:
        return "TRMNL_OIDC_CLIENT_ID is not set"
    if not cfg.oidc_client_secret_file:
        return "TRMNL_OIDC_CLIENT_SECRET_FILE is not set"
    if cfg.oidc_client_secret() is None:
        return (
            f"TRMNL_OIDC_CLIENT_SECRET_FILE {cfg.oidc_client_secret_file!r} "
            "is empty or could not be read"
        )
    if not cfg.base_url:
        # Without a fixed origin there is nothing to build the redirect URI
        # from and nothing to allowlist it against, and the CSRF origin pin
        # in routes/auth.py has already degraded to "whatever Host you sent".
        # Refusing to enable OIDC is the honest answer.
        return (
            "TRMNL_BASE_URL is not set; OIDC needs a fixed public origin to "
            "derive its redirect URI from and to allowlist it against"
        )
    redirect = cfg.oidc_callback_url()
    if not is_secure_url(redirect):
        return (
            f"the OIDC redirect URI {redirect!r} is plaintext http to a "
            "non-loopback host. The authorization code comes back on it, so "
            "it must be https unless this is a loopback development setup. "
            "Set TRMNL_BASE_URL (or TRMNL_OIDC_REDIRECT_URL) to an https URL."
        )
    if not redirect.startswith(cfg.base_url.rstrip("/") + "/"):
        return (
            f"TRMNL_OIDC_REDIRECT_URL {redirect!r} is not under TRMNL_BASE_URL "
            f"{cfg.base_url!r} — refusing to hand an IdP a redirect target "
            "outside this server's own origin"
        )
    return None


def enabled(cfg: Config) -> bool:
    """True when `/auth/oidc/login` will actually work."""
    return configuration_problem(cfg) is None


def provider_name(cfg: Config) -> str:
    """What the "Sign in with ..." button says."""
    if cfg.oidc_provider_name:
        return cfg.oidc_provider_name
    host = urlsplit(cfg.oidc_issuer).hostname
    return host or "OIDC"


def startup_report(cfg: Config) -> tuple[str, str]:
    """`(level, message)` describing the OIDC decision, for `create_app()`.

    Deliberately a pure function returning a decision rather than logging
    directly, so a test can assert on the decision without capturing logs.
    """
    if not is_configured(cfg):
        return ("info", "OIDC login is not configured (TRMNL_OIDC_ISSUER unset)")
    problem = configuration_problem(cfg)
    if problem:
        return (
            "error",
            f"OIDC login is DISABLED: {problem}. The shared-secret login path "
            "(TRMNL_UI_TOKEN_FILE) is unaffected.",
        )
    return (
        "info",
        "OIDC login enabled: issuer=%s client_id=%s redirect_uri=%s "
        "scopes=%r groups_claim=%r allowed_groups=%s"
        % (
            normalise_issuer(cfg.oidc_issuer),
            cfg.oidc_client_id,
            cfg.oidc_callback_url(),
            cfg.oidc_scopes,
            cfg.oidc_groups_claim,
            ",".join(cfg.oidc_allowed_groups) or "<any authenticated user>",
        ),
    )


# --- discovery -------------------------------------------------------------


def _discovery_problem(doc: object, issuer: str) -> str | None:
    if not isinstance(doc, dict):
        return "discovery document is not a JSON object"
    for key in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint"):
        if not _is_absolute_http_url(doc.get(key)):
            return f"discovery document has no usable {key!r}"
        if not is_secure_url(doc.get(key)):
            # Discovery is fetched from the issuer, so this is the issuer
            # moving the flow to plaintext — by misconfiguration or because
            # someone rewrote the document in transit. Either way the token
            # endpoint is where the client_secret goes and the ID token comes
            # back, and neither belongs on a cleartext hop.
            return (
                f"discovery document points {key!r} at plaintext http on a "
                f"non-loopback host ({redact(doc.get(key))})"
            )
    # RFC 8414 §2 / RFC 7636. This server always sends `code_challenge` with
    # `code_challenge_method=S256`, but a provider that ignores PKCE entirely
    # simply drops both and issues the code anyway — and the downgrade is
    # invisible from here, because a successful login looks identical. So the
    # advertisement is what gets checked, and its absence is a refusal rather
    # than a shrug: every provider this feature targets (authentik, Keycloak,
    # Authelia, Pocket ID, Google) publishes it, so a document without it is a
    # provider that cannot be shown to be doing PKCE at all.
    #
    # `plain` is never selected even when offered. authentik advertises both,
    # and `plain` puts the verifier in the authorization request, which is the
    # exact leak PKCE exists to close.
    methods = doc.get("code_challenge_methods_supported")
    if not isinstance(methods, list) or not methods:
        return (
            "discovery document does not advertise "
            "`code_challenge_methods_supported`, so PKCE support cannot be "
            "confirmed and a silent downgrade to no PKCE would be undetectable"
        )
    if "S256" not in methods:
        return (
            "the provider does not advertise the PKCE `S256` challenge method "
            f"(advertised: {redact(methods)}). This server will not fall back "
            "to `plain`, which puts the verifier in the authorization request"
        )

    advertised = normalise_issuer(str(doc.get("issuer") or ""))
    if advertised and advertised != issuer:
        # A warning, not a failure. authentik in *global* issuer mode
        # advertises its root URL as `iss` while only serving the discovery
        # document under `/application/o/<slug>/` — a valid setup in which
        # these two legitimately differ, and rejecting it would break a
        # provider this feature exists to support.
        logger.warning(
            "OIDC discovery at %s advertises issuer %s, which differs from "
            "the configured TRMNL_OIDC_ISSUER %r. Continuing — authentik in "
            "global issuer mode does exactly this — but check the value if "
            "logins fail.",
            issuer + DISCOVERY_PATH, redact(advertised), issuer,
        )
    return None


def discovery(cfg: Config) -> dict[str, Any]:
    """The provider's `.well-known/openid-configuration`, cached.

    Raises `OidcError` on any failure, and the caller turns that into a
    refused *OIDC* login. It never touches the shared-secret path: nothing on
    `POST /auth/session` or `require_ui_session` calls into this module.
    """
    issuer = normalise_issuer(cfg.oidc_issuer)
    cached = _cached_discovery(issuer)
    if cached is not None:
        return cached

    # Nothing cached, so this call may have to go out. Take a slot *before*
    # deciding whether to lead or follow, so the number of workers tied up in
    # discovery — fetching or waiting — is bounded by OUTBOUND_LIMIT either way.
    with outbound_slot("discovery"):
        while True:
            cached = _cached_discovery(issuer)
            if cached is not None:
                return cached
            with _discovery_lock:
                inflight = _discovery_inflight.get(issuer)
                if inflight is None:
                    inflight = threading.Event()
                    _discovery_inflight[issuer] = inflight
                    leader = True
                else:
                    leader = False
            if leader:
                try:
                    return _fetch_discovery(issuer)
                finally:
                    with _discovery_lock:
                        _discovery_inflight.pop(issuer, None)
                    inflight.set()
            # Follower: the leader's result — document or cached failure —
            # lands in the cache, so wait for it rather than making a second
            # identical request. Bounded by the fetch's own timeout.
            if not inflight.wait(OUTBOUND_WAIT):
                raise OidcError(
                    "oidc_provider",
                    "timed out waiting for an in-flight discovery fetch to "
                    f"{issuer + DISCOVERY_PATH}",
                )
            # Loop: re-read the cache the leader just populated. If the leader
            # raced with a `reset_caches()` there is nothing there, and this
            # thread becomes the next leader rather than spinning.


def _cached_discovery(issuer: str) -> dict[str, Any] | None:
    """The cached document, or None. Raises when a *failure* is still cached."""
    now = time.monotonic()
    with _discovery_lock:
        cached = _discovery_cache.get(issuer)
        if cached and cached[0] > now:
            return cached[1]
        failed = _discovery_failures.get(issuer)
        if failed and failed[0] > now:
            raise OidcError("oidc_provider", failed[1])
    return None


def _fetch_discovery(issuer: str) -> dict[str, Any]:
    """One actual outbound discovery request. Callers hold an outbound slot."""
    now = time.monotonic()
    url = issuer + DISCOVERY_PATH
    try:
        with _http_client() as client:
            response = _read_capped(
                client,
                client.build_request(
                    "GET", url, headers={"Accept": "application/json"}
                ),
                "discovery",
            )
        if response.status_code != 200:
            raise OidcError(
                "oidc_provider", f"HTTP {response.status_code}"
            )
        doc = response.json()
        problem = _discovery_problem(doc, issuer)
    except (httpx.HTTPError, ValueError, OidcError) as exc:
        problem = redact(f"{type(exc).__name__}: {exc}", 300)
        doc = None

    if problem is not None:
        message = f"OIDC discovery at {url} failed: {problem}"
        with _discovery_lock:
            _discovery_failures[issuer] = (now + DISCOVERY_RETRY_BACKOFF, message)
        logger.error(
            "%s — OIDC logins will be refused until it recovers; the "
            "shared-secret login path is unaffected", message,
        )
        raise OidcError("oidc_provider", message)

    assert isinstance(doc, dict)  # narrowed by _discovery_problem
    with _discovery_lock:
        _discovery_cache[issuer] = (now + DISCOVERY_TTL, doc)
        _discovery_failures.pop(issuer, None)
    logger.info("OIDC discovery loaded from %s", url)
    return doc


# --- the code flow ---------------------------------------------------------


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def authorization_url(
    cfg: Config,
    doc: dict[str, Any],
    *,
    state: str,
    nonce: str,
    code_challenge: str,
    redirect_uri: str,
) -> str:
    """The URL the browser is 302'd to.

    `redirect_uri` is passed in rather than read here so the caller proves it
    came from `cfg.oidc_callback_url()` and not from the request.
    """
    endpoint = str(doc["authorization_endpoint"])
    params = {
        "response_type": "code",
        "client_id": cfg.oidc_client_id,
        "redirect_uri": redirect_uri,
        "scope": cfg.oidc_scopes,
        "state": state,
        "nonce": nonce,
        # PKCE on a confidential client too. It costs one hash and it is the
        # only thing that helps if an authorization code leaks through a
        # referrer, a proxy log or a shared browser.
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    separator = "&" if urlsplit(endpoint).query else "?"
    return endpoint + separator + urlencode(params)


def code_challenge_for(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def _token_auth(
    doc: dict[str, Any], client_id: str, client_secret: str
) -> tuple[dict[str, str], dict[str, str]]:
    """`(extra_headers, extra_form_fields)` for authenticating to the token endpoint.

    Read from discovery rather than hardcoded: Authelia defaults to
    `client_secret_basic` and *enforces* the registered method, so a hardcoded
    `client_secret_post` fails there. The OIDC spec's default when the
    provider advertises nothing is `client_secret_basic`.
    """
    methods = doc.get("token_endpoint_auth_methods_supported")
    if isinstance(methods, list) and methods:
        if "client_secret_basic" in methods:
            chosen = "client_secret_basic"
        elif "client_secret_post" in methods:
            chosen = "client_secret_post"
        else:
            raise OidcError(
                "oidc_provider",
                "the provider supports none of the client authentication "
                f"methods this server implements (advertised: "
                f"{redact(methods, 200)}; supported: client_secret_basic, "
                "client_secret_post)",
            )
    else:
        chosen = "client_secret_basic"

    if chosen == "client_secret_post":
        return {}, {"client_id": client_id, "client_secret": client_secret}
    # RFC 6749 §2.3.1: both halves are form-urlencoded *before* base64.
    pair = f"{quote(client_id, safe='')}:{quote(client_secret, safe='')}"
    encoded = base64.b64encode(pair.encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}, {"client_id": client_id}


def exchange_code(
    cfg: Config,
    doc: dict[str, Any],
    *,
    code: str,
    code_verifier: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Swap the authorization code for tokens, server-side."""
    secret = cfg.oidc_client_secret()
    if not secret:
        raise OidcError("oidc_disabled", "the OIDC client secret is unavailable")
    headers, extra = _token_auth(doc, cfg.oidc_client_id, secret)
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        **extra,
    }
    headers = {"Accept": "application/json", **headers}
    try:
        with outbound_slot("token"), _http_client() as client:
            response = _read_capped(
                client,
                client.build_request(
                    "POST", str(doc["token_endpoint"]), data=form, headers=headers
                ),
                "token",
            )
    except httpx.HTTPError as exc:
        raise OidcError(
            "oidc_provider", f"token endpoint unreachable: {exc}"
        ) from exc
    if response.status_code != 200:
        raise OidcError(
            "oidc_provider",
            f"token endpoint returned HTTP {response.status_code}: "
            f"{redact(response.text, 200)}",
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise OidcError(
            "oidc_provider", "token endpoint returned a non-JSON body"
        ) from exc
    if not isinstance(payload, dict) or not payload.get("access_token"):
        raise OidcError(
            "oidc_provider", "token response carried no access_token"
        )
    return payload


def decode_jwt_claims(token: str) -> dict[str, Any]:
    """The claim set of a JWT, *without* verifying its signature.

    Legitimate only for a token received directly from the token endpoint
    over TLS with client authentication — see the module docstring and OIDC
    Core §3.1.3.7 item 6. Never call this on anything a browser handed us.
    """
    parts = token.split(".")
    if len(parts) < 2:
        raise OidcError("oidc_provider", "id_token is not a JWT")
    try:
        claims = json.loads(b64url_decode(parts[1]))
    except (ValueError, binascii.Error) as exc:
        raise OidcError(
            "oidc_provider",
            f"id_token payload is not decodable JSON: {redact(str(exc))}",
        ) from exc
    if not isinstance(claims, dict):
        raise OidcError("oidc_provider", "id_token payload is not a JSON object")
    return claims


def _expected_issuers(cfg: Config, doc: dict[str, Any]) -> list[str]:
    """The issuer values an ID token is allowed to claim.

    Normally one: the configured issuer, which per OIDC Discovery §4.3 must
    equal the document's own `issuer`. This fork tolerates them differing
    because authentik in *global* issuer mode advertises its root URL while
    serving discovery under `/application/o/<slug>/` — see
    `_discovery_problem`. So the accepted set is those two values and nothing
    else: both are operator- or discovery-derived, neither is attacker-chosen.
    """
    expected = [normalise_issuer(cfg.oidc_issuer)]
    advertised = normalise_issuer(str(doc.get("issuer") or ""))
    if advertised and advertised not in expected:
        expected.append(advertised)
    return expected


def validate_id_claims(
    cfg: Config, doc: dict[str, Any], claims: dict[str, Any]
) -> None:
    """Check the ID token's `iss`, `aud`, `azp`, `exp` and `sub`.

    **Not** signature verification — see the module docstring. §3.1.3.7 item 6
    licenses skipping *item 6*, the signature, when the token came straight
    back from the token endpoint over TLS with client authentication. It says
    nothing about items 1-5 and 8-13, which are the claim checks below, and
    those are exactly what stop a token minted for another client or another
    issuer, or one that expired last week, from being accepted here.

    Raises `OidcError("oidc_claims", ...)` and never returns a verdict, so a
    caller cannot forget to look at the result.
    """
    client_id = cfg.oidc_client_id

    # §3.1.3.7 item 2: the issuer must be the one this flow was started with.
    expected_issuers = _expected_issuers(cfg, doc)
    issuer = normalise_issuer(str(claims.get("iss") or ""))
    if not issuer:
        raise OidcError("oidc_claims", "the id_token carries no `iss` claim")
    if issuer not in expected_issuers:
        raise OidcError(
            "oidc_claims",
            f"the id_token's `iss` ({redact(issuer)}) is not this server's "
            f"configured issuer ({expected_issuers!r})",
        )

    # §3.1.3.7 item 3: `aud` must contain this client.
    audience = claims.get("aud")
    if isinstance(audience, str):
        audiences = [audience]
    elif isinstance(audience, (list, tuple)):
        audiences = [a for a in audience if isinstance(a, str)]
    else:
        audiences = []
    if not audiences:
        raise OidcError("oidc_claims", "the id_token carries no usable `aud` claim")
    if client_id not in audiences:
        raise OidcError(
            "oidc_claims",
            f"the id_token's `aud` ({redact(audiences)}) does not contain this "
            f"server's client_id ({client_id!r}) — it was minted for a "
            "different client",
        )

    # §3.1.3.7 items 4 and 5: with more than one audience `azp` is required,
    # and whenever it is present it must be this client.
    azp = claims.get("azp")
    if azp is not None and azp != client_id:
        raise OidcError(
            "oidc_claims",
            f"the id_token's `azp` ({redact(azp)}) is not this server's "
            f"client_id ({client_id!r})",
        )
    if len(audiences) > 1 and azp is None:
        raise OidcError(
            "oidc_claims",
            "the id_token has multiple audiences but no `azp` claim, so there "
            "is nothing to say it was authorized for this client",
        )

    # §3.1.3.7 item 9: not expired, with a small skew allowance.
    now = time.time()
    try:
        expires_at = int(claims["exp"])
    except (KeyError, TypeError, ValueError):
        raise OidcError(
            "oidc_claims", "the id_token carries no usable `exp` claim"
        ) from None
    if expires_at + CLOCK_SKEW <= now:
        raise OidcError(
            "oidc_claims",
            f"the id_token expired {int(now - expires_at)}s ago",
        )
    # §3.1.3.7 item 10: an `iat` far in the future is a broken or hostile clock.
    issued_at = claims.get("iat")
    if isinstance(issued_at, (int, float)) and issued_at - CLOCK_SKEW > now:
        raise OidcError(
            "oidc_claims",
            f"the id_token was issued {int(issued_at - now)}s in the future",
        )

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise OidcError("oidc_claims", "the id_token carries no `sub` claim")


def fetch_userinfo(doc: dict[str, Any], access_token: str) -> dict[str, Any]:
    """The authenticated identity call. JSON only, on purpose.

    Keycloak (`user.info.response.signature.alg`) and Authelia
    (`userinfo_signed_response_alg`) can both return `application/jwt`
    instead. Accepting that would mean parsing a *signed* assertion and
    ignoring the signature — which is not what §3.1.3.7 item 6 licenses,
    because this response did not come back from the token endpoint. So it is
    refused with a code the UI can explain, and the README tells operators to
    leave the signing algorithm at `none`.
    """
    try:
        with outbound_slot("userinfo"), _http_client() as client:
            response = _read_capped(
                client,
                client.build_request(
                    "GET",
                    str(doc["userinfo_endpoint"]),
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Accept": "application/json",
                    },
                ),
                "userinfo",
            )
    except httpx.HTTPError as exc:
        raise OidcError(
            "oidc_provider", f"userinfo endpoint unreachable: {exc}"
        ) from exc
    if response.status_code != 200:
        raise OidcError(
            "oidc_provider",
            f"userinfo endpoint returned HTTP {response.status_code}",
        )
    if response.content_type == "application/jwt":
        raise OidcError(
            "oidc_userinfo_jwt",
            "userinfo returned application/jwt. This server has no JWT "
            "signature verification (and no crypto dependency), so it will "
            "not consume a signed assertion it cannot check. Set the "
            "provider's userinfo response signing algorithm to 'none'.",
        )
    try:
        claims = response.json()
    except ValueError as exc:
        raise OidcError(
            "oidc_provider", "userinfo returned a non-JSON body"
        ) from exc
    if not isinstance(claims, dict):
        raise OidcError("oidc_provider", "userinfo did not return a JSON object")
    return claims


def bind_userinfo_subject(
    userinfo: dict[str, Any], id_claims: dict[str, Any]
) -> None:
    """OIDC Core §5.3.2: the userinfo `sub` MUST match the ID token's.

    This is not a formality here, it is the load-bearing check of the whole
    design. Identity comes from `userinfo` (see the module docstring), and the
    ID token is what binds the response to *this* login attempt via `nonce`.
    Without this check the two are unrelated: a userinfo response naming a
    different subject — or an empty one naming nobody at all — still minted a
    session, and every group decision downstream was made about whoever the
    userinfo endpoint felt like naming.

    §5.3.2's wording is exact: "the sub Claim in the UserInfo Response MUST be
    verified to exactly match the sub Claim in the ID Token; if they do not
    match, the UserInfo Response values MUST NOT be used."
    """
    id_subject = id_claims.get("sub")
    subject = userinfo.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise OidcError(
            "oidc_subject",
            "the userinfo response carries no `sub` claim, so there is nothing "
            "to tie it to the id_token this flow received. OIDC Core 5.3.2 "
            "requires the two to match.",
        )
    if not isinstance(id_subject, str) or subject != id_subject:
        raise OidcError(
            "oidc_subject",
            f"the userinfo `sub` ({redact(subject)}) does not match the "
            f"id_token `sub` ({redact(id_subject)}); OIDC Core 5.3.2 says the "
            "userinfo response must not be used",
        )


# A username, an email address or an opaque `sub`. Long enough for any real
# one, short enough that a provider cannot use the log as a write primitive.
SUBJECT_LABEL_LIMIT = 96


def subject_label(userinfo: dict[str, Any], id_claims: dict[str, Any]) -> str:
    """A short human handle for the log line. Never a credential.

    Redacted, because every candidate claim is a string the identity provider
    chose: unbounded and free to contain a newline, which in a log file is a
    forged second line.
    """
    for source in (userinfo, id_claims):
        for key in ("preferred_username", "email", "name", "sub"):
            value = source.get(key)
            if isinstance(value, str) and value.strip():
                return redact(value.strip(), SUBJECT_LABEL_LIMIT)
    return "<unknown>"


# --- authorization ---------------------------------------------------------


def claim_lookup(claims: dict[str, Any], path: str) -> Any:
    """Resolve `path` in `claims`, flat key first, dotted path second.

    Flat-first matters: an IdP that legitimately emits a claim whose *name*
    contains a dot must not be broken by dotted-path support. Only if the
    literal key is absent is the value split and traversed, which is what
    makes `resource_access.trmnl.roles` reachable for hand-rolled mappers.

    Returns `MISSING` when the claim is not present at all — distinct from a
    present-but-empty list, and the difference the error surface depends on.
    """
    if path in claims:
        return claims[path]
    if "." not in path:
        return MISSING
    node: Any = claims
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return MISSING
        node = node[part]
    return node


def groups_from(claims: dict[str, Any], path: str) -> list[str] | None:
    """The group names at `path`, or None when the claim is absent/unusable."""
    value = claim_lookup(claims, path)
    if value is MISSING or value is None:
        return None
    if isinstance(value, str):
        # A few providers emit a single group as a bare string. Deliberately
        # not split on commas or spaces: group names may contain both, and a
        # split would invent memberships nobody granted.
        return [value.strip()] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return None


def check_groups(
    cfg: Config, userinfo: dict[str, Any], id_claims: dict[str, Any]
) -> list[str]:
    """Enforce `TRMNL_OIDC_ALLOWED_GROUPS`. Returns the groups that were seen.

    Reads userinfo first and falls back to the ID token. Userinfo is the
    authoritative, freshest source and the one Authelia explicitly steers
    clients toward; the ID token covers Keycloak's `microprofile-jwt` and
    Authelia claims policies, which land groups there and nowhere else. First
    *non-absent* source wins and they are never merged — a deliberately
    narrowed userinfo response must not be widened by a staler ID token.

    Fails closed when a restriction is configured: an absent claim denies.
    When no restriction is configured an absent claim is fine, because
    otherwise Google — which has no group or role claim of any kind — could
    never be used at all.
    """
    claim = cfg.oidc_groups_claim
    groups = groups_from(userinfo, claim)
    source = "userinfo"
    if groups is None:
        groups = groups_from(id_claims, claim)
        source = "id_token"
    allowed = [g for g in cfg.oidc_allowed_groups if g]
    if not allowed:
        return groups or []
    if groups is None:
        raise OidcError(
            "oidc_group_claim_missing",
            f"the identity provider returned no {claim!r} claim in either the "
            "userinfo response or the ID token, and TRMNL_OIDC_ALLOWED_GROUPS "
            "is set. Check that the scope granting group membership is "
            "requested and that the claim is included in the userinfo "
            "response.",
        )
    matched = sorted(set(groups) & set(allowed))
    if not matched:
        raise OidcError(
            "oidc_group",
            f"none of the account's {claim!r} values from {source} "
            f"({redact(sorted(groups), 200)}) is in TRMNL_OIDC_ALLOWED_GROUPS "
            f"({sorted(allowed)!r})",
        )
    return groups
