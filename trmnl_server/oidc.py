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
import json
import threading
import time
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

# Test seam. Production leaves this None and httpx builds its own transport;
# tests set an in-process transport so the entire flow runs with no network.
HTTP_TRANSPORT: httpx.BaseTransport | None = None

_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_discovery_failures: dict[str, tuple[float, str]] = {}
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
})

# Distinguishes "the claim is not there" from "the claim is there and empty",
# which is the difference between "your IdP is not sending groups" and "your
# account is in no allowed group" — the single most useful thing this feature
# can tell a misconfigured operator.
MISSING = object()


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


def _http_client() -> httpx.Client:
    return httpx.Client(
        timeout=HTTP_TIMEOUT,
        # Never chase a redirect: a token endpoint that 302s is either
        # misconfigured or is trying to move a client_secret somewhere it was
        # not sent.
        follow_redirects=False,
        transport=HTTP_TRANSPORT,
    )


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
    advertised = normalise_issuer(str(doc.get("issuer") or ""))
    if advertised and advertised != issuer:
        # A warning, not a failure. authentik in *global* issuer mode
        # advertises its root URL as `iss` while only serving the discovery
        # document under `/application/o/<slug>/` — a valid setup in which
        # these two legitimately differ, and rejecting it would break a
        # provider this feature exists to support.
        logger.warning(
            "OIDC discovery at %s advertises issuer %r, which differs from "
            "the configured TRMNL_OIDC_ISSUER %r. Continuing — authentik in "
            "global issuer mode does exactly this — but check the value if "
            "logins fail.",
            issuer + DISCOVERY_PATH, advertised, issuer,
        )
    return None


def discovery(cfg: Config) -> dict[str, Any]:
    """The provider's `.well-known/openid-configuration`, cached.

    Raises `OidcError` on any failure, and the caller turns that into a
    refused *OIDC* login. It never touches the shared-secret path: nothing on
    `POST /auth/session` or `require_ui_session` calls into this module.
    """
    issuer = normalise_issuer(cfg.oidc_issuer)
    now = time.monotonic()
    with _discovery_lock:
        cached = _discovery_cache.get(issuer)
        if cached and cached[0] > now:
            return cached[1]
        failed = _discovery_failures.get(issuer)
        if failed and failed[0] > now:
            raise OidcError("oidc_provider", failed[1])

    url = issuer + DISCOVERY_PATH
    try:
        with _http_client() as client:
            response = client.get(url, headers={"Accept": "application/json"})
        response.raise_for_status()
        doc = response.json()
        problem = _discovery_problem(doc, issuer)
    except (httpx.HTTPError, ValueError) as exc:
        problem = f"{type(exc).__name__}: {exc}"
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
