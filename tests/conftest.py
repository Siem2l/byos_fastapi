"""Shared fixtures, and the in-process fake IdP the OIDC tests run against.

Lifted out of `test_panel.py` (unchanged in behaviour) so `test_oidc.py` can
build the same app the panel contract tests do, rather than a second,
subtly-different one.

**No network.** `trmnl_server.oidc` routes every outbound request through
`oidc.HTTP_TRANSPORT`; the `idp` fixture points that at an `httpx.MockTransport`
that hands the request to a `TestClient` wrapping a FastAPI app. So discovery,
the token exchange and the userinfo call are real HTTP round-trips against a
real ASGI app, served entirely inside the test process.

The authorization endpoint is deliberately *not* part of that app. The server
never calls `/authorize` — the browser does — so `FakeIdp.authorize()` is a
plain method standing in for the browser plus the human at the consent screen.
Modelling it as an HTTP call the server makes would be a fiction that hid the
one thing the callback's security actually rests on: that everything between
the 302 out and the 302 back is under the *browser's* control, not ours.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit

import httpx
import pytest
from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response
from fastapi.testclient import TestClient

from trmnl_server import config as config_module
from trmnl_server import models
from trmnl_server import oidc as oidc_module
from trmnl_server.config import Config
from trmnl_server.main import create_app

MAC = "E0:72:A1:FA:42:F0"
TOKEN = "test-token"
UI_TOKEN = "test-ui-token"

OIDC_ISSUER = "https://idp.example"
OIDC_CLIENT_ID = "trmnl"
OIDC_CLIENT_SECRET = "s3cr3t-client-secret"
OIDC_REDIRECT_URI = "https://trmnl.example/auth/oidc/callback"


def _reset_process_state() -> None:
    """Clear the module-global rotation/plugin caches between apps.

    `services.state` is process-global and the plugin scheduler caches
    `PluginOutput` paths in it. Production runs one app per process, but the
    suite builds several, and pytest keeps the last few tmp_path trees alive
    — so a stale cache entry whose files still exist on disk passes the
    scheduler's `_assets_exist()` staleness check, the plugin never re-runs
    under the new generated root, and `path_to_web_url()` returns None for
    every rotation entry. Cheaper to reset than to make the cache
    root-aware.
    """
    from trmnl_server.services import state as state_module

    with state_module.STATE_LOCK:
        state_module.global_state['plugins'] = {}
        state_module.global_state['rotation_master'] = {
            'bmp_entries': [],
            'png_entries': [],
            'hashes': [],
            'meta': [],
            'selected_ids': [],
            'version': 0,
            'has_persistent_playlist': False,
        }
        state_module.global_state['devices'] = {}
        state_module.global_state['device_playlists'] = {}
        state_module.global_state['named_playlists'] = {}
        state_module.global_state['device_playlist_bindings'] = {}
        # Profiles are cached in front of SQLite, and each test gets a fresh
        # database — so without this a refresh_interval written by one test
        # is still in memory for the next one, whose DB has never seen it.
        state_module.global_state['device_profiles'] = {}

    # The rate limiters are module-global sliding windows, so without this
    # the suite's own traffic accumulates across the ~30 apps it builds and
    # a later test gets a 429 for something an earlier test did.
    from trmnl_server.routes import auth as auth_module
    from trmnl_server.routes import panel as panel_module

    panel_module._log_buckets.clear()
    panel_module._log_global_hits.clear()
    auth_module._mint_failures.clear()
    auth_module._mint_global_failures.clear()

    # Same argument for the discovery cache: a document fetched by one test's
    # fake IdP would otherwise still be cached for the next test's, which
    # would pass while proving nothing.
    oidc_module.reset_caches()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # pin_database_path, not a plain assignment: create_app() calls
    # pin_generated_assets_dir(), which refreshes every path constant and
    # would otherwise recompute DATABASE_PATH back to $PWD/var/db.
    config_module.pin_database_path(str(tmp_path / "trmnl.db"))
    models.init_db()
    _reset_process_state()

    token_file = tmp_path / "token"
    token_file.write_text(TOKEN)
    ui_token_file = tmp_path / "ui-token"
    ui_token_file.write_text(UI_TOKEN)
    cfg = Config()
    cfg.state_dir = str(tmp_path / "frames")
    cfg.allowed_devices = ["e072a1fa42f0"]
    cfg.token_file = str(token_file)
    cfg.ui_token_file = str(ui_token_file)
    cfg.base_url = "https://trmnl.example"
    cfg.synthetic = True
    # Same origin as cfg.base_url, and https: the session cookie carries
    # Secure whenever the deployment is TLS, so an http test client would
    # silently drop it and every control-plane test would pass for the wrong
    # reason.
    with TestClient(create_app(cfg), base_url="https://trmnl.example") as c:
        yield c


@pytest.fixture()
def ui_client(client):
    """A client holding a valid control-plane session cookie."""
    resp = client.post("/auth/session", json={"token": UI_TOKEN})
    assert resp.status_code == 204
    return client


# --- the fake identity provider -------------------------------------------


class FakeIdp:
    """A configurable OIDC provider, good enough to exercise the real flow.

    Every knob below exists because a real provider in the matrix behaves
    that way: Authelia puts groups only in userinfo, Keycloak's
    `microprofile-jwt` puts them only in the ID token, authentik advertises an
    issuer that differs from its discovery base in global mode, Authelia
    defaults to `client_secret_basic` while Google advertises both, and both
    Keycloak and Authelia can be made to answer userinfo with
    `application/jwt`.
    """

    def __init__(
        self,
        *,
        issuer: str = OIDC_ISSUER,
        advertised_issuer: str | None = None,
        groups: list[str] | None = None,
        groups_in_userinfo: bool = True,
        groups_in_id_token: bool = False,
        groups_claim: str = "groups",
        auth_methods: list[str] | None = None,
        userinfo_content_type: str = "application/json",
        discovery_status: int = 200,
        discovery_document: dict[str, Any] | None = None,
        userinfo_claims: dict[str, Any] | None = None,
    ) -> None:
        self.issuer = issuer
        self.advertised_issuer = advertised_issuer
        self.groups = ["trmnl-admins", "everyone"] if groups is None else groups
        self.groups_in_userinfo = groups_in_userinfo
        self.groups_in_id_token = groups_in_id_token
        self.groups_claim = groups_claim
        self.auth_methods = auth_methods
        self.userinfo_content_type = userinfo_content_type
        self.discovery_status = discovery_status
        self.discovery_document = discovery_document
        self.userinfo_claims = userinfo_claims
        self.client_secret = OIDC_CLIENT_SECRET

        # Observability for assertions.
        self.discovery_hits = 0
        self.authorize_params: dict[str, str] = {}
        self.token_requests: list[dict[str, Any]] = []
        self.userinfo_hits = 0

        self._codes: dict[str, dict[str, Any]] = {}
        self._access_tokens: dict[str, dict[str, Any]] = {}
        self.app = self._build_app()

    # -- the browser's half of the flow, not the server's ------------------

    def authorize(self, authorization_url: str, *, sub: str = "alice") -> str:
        """Stand in for the browser + user. Returns the callback URL.

        Enforces what a real authorization endpoint enforces and this
        server's tests care about: PKCE parameters must be present and well
        formed, and the code is bound to the challenge so a token exchange
        with the wrong verifier fails.
        """
        query = parse_qs(urlsplit(authorization_url).query)
        params = {k: v[0] for k, v in query.items()}
        self.authorize_params = params
        assert params.get("response_type") == "code"
        assert params.get("client_id") == OIDC_CLIENT_ID
        challenge = params.get("code_challenge")
        assert challenge, "the authorization request carried no PKCE challenge"
        assert params.get("code_challenge_method") == "S256"
        code = "code-" + secrets.token_hex(8)
        self._codes[code] = {
            "challenge": challenge,
            "nonce": params.get("nonce"),
            "redirect_uri": params.get("redirect_uri"),
            "sub": sub,
        }
        back = {"code": code, "state": params.get("state", ""), "iss": self.issuer}
        return f"{params['redirect_uri']}?{urlencode(back)}"

    def issue_code_with_nonce(self, nonce: str | None) -> str:
        """Mint a code whose ID token will carry `nonce`, for the mismatch test."""
        code = "code-" + secrets.token_hex(8)
        self._codes[code] = {
            "challenge": None,
            "nonce": nonce,
            "redirect_uri": OIDC_REDIRECT_URI,
            "sub": "alice",
        }
        return code

    # -- the server's half, over real HTTP --------------------------------

    def _claims(self, sub: str, *, nonce: str | None) -> dict[str, Any]:
        return {
            "iss": self.issuer,
            "sub": sub,
            "aud": OIDC_CLIENT_ID,
            "exp": int(time.time()) + 300,
            "iat": int(time.time()),
            "nonce": nonce,
        }

    def _jwt(self, claims: dict[str, Any]) -> str:
        def seg(obj: dict[str, Any]) -> str:
            raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

        # The signature is not checked (see oidc.py's module docstring on
        # OIDC Core 3.1.3.7 item 6), so a fixed placeholder is honest here:
        # a real one would prove nothing this code path looks at.
        return f"{seg({'alg': 'RS256', 'typ': 'JWT'})}.{seg(claims)}.not-verified"

    def _build_app(self) -> FastAPI:
        app = FastAPI()
        idp = self

        @app.get("/.well-known/openid-configuration")
        def discovery() -> Response:
            idp.discovery_hits += 1
            if idp.discovery_status != 200:
                return Response(status_code=idp.discovery_status)
            if idp.discovery_document is not None:
                return JSONResponse(idp.discovery_document)
            doc: dict[str, Any] = {
                "issuer": idp.advertised_issuer or idp.issuer,
                "authorization_endpoint": f"{idp.issuer}/authorize",
                "token_endpoint": f"{idp.issuer}/token",
                "userinfo_endpoint": f"{idp.issuer}/userinfo",
                "jwks_uri": f"{idp.issuer}/jwks.json",
                "scopes_supported": ["openid", "profile", "email", "groups"],
                "code_challenge_methods_supported": ["S256"],
            }
            if idp.auth_methods is not None:
                doc["token_endpoint_auth_methods_supported"] = idp.auth_methods
            return JSONResponse(doc)

        @app.post("/token")
        async def token(
            request: Request,
            authorization: str | None = Header(default=None),
        ) -> Response:
            # The form body is parsed by hand rather than with `Form(...)`,
            # which would drag `python-multipart` into the test environment.
            # Keeping the test closure equal to the runtime closure is the
            # whole reason this feature has no new dependencies.
            body = (await request.body()).decode("utf-8")
            fields = dict(parse_qsl(body, keep_blank_values=True))
            grant_type = fields.get("grant_type", "")
            code = fields.get("code", "")
            redirect_uri = fields.get("redirect_uri", "")
            code_verifier = fields.get("code_verifier")
            client_id = fields.get("client_id")
            client_secret = fields.get("client_secret")
            idp.token_requests.append({
                "grant_type": grant_type,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
                "client_id": client_id,
                "has_basic": bool(authorization),
            })
            # Client authentication, either shape.
            if authorization:
                scheme, _, blob = authorization.partition(" ")
                if scheme.lower() != "basic":
                    return JSONResponse(
                        {"error": "invalid_client"}, status_code=401)
                decoded = base64.b64decode(blob).decode("utf-8")
                user, _, password = decoded.partition(":")
                if (user, password) != (OIDC_CLIENT_ID, idp.client_secret):
                    return JSONResponse(
                        {"error": "invalid_client"}, status_code=401)
            elif client_secret != idp.client_secret:
                return JSONResponse({"error": "invalid_client"}, status_code=401)

            record = idp._codes.pop(code, None)
            if record is None:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if record["redirect_uri"] != redirect_uri:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            if record["challenge"] is not None:
                if not code_verifier:
                    return JSONResponse(
                        {"error": "invalid_request",
                         "error_description": "code_verifier required"},
                        status_code=400,
                    )
                digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
                expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
                if expected != record["challenge"]:
                    return JSONResponse(
                        {"error": "invalid_grant",
                         "error_description": "PKCE verification failed"},
                        status_code=400,
                    )

            claims = idp._claims(record["sub"], nonce=record["nonce"])
            if idp.groups_in_id_token:
                claims[idp.groups_claim] = list(idp.groups)
            access_token = "at-" + secrets.token_hex(8)
            idp._access_tokens[access_token] = {"sub": record["sub"]}
            return JSONResponse({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": idp._jwt(claims),
            })

        @app.get("/userinfo")
        def userinfo(authorization: str | None = Header(default=None)) -> Response:
            idp.userinfo_hits += 1
            token_value = (authorization or "").removeprefix("Bearer ").strip()
            record = idp._access_tokens.get(token_value)
            if record is None:
                return Response(status_code=401)
            claims: dict[str, Any] = {
                "sub": record["sub"],
                "preferred_username": record["sub"],
                "email": f"{record['sub']}@example.com",
            }
            if idp.groups_in_userinfo:
                claims[idp.groups_claim] = list(idp.groups)
            if idp.userinfo_claims is not None:
                claims = dict(idp.userinfo_claims)
            if idp.userinfo_content_type == "application/jwt":
                return Response(
                    content=idp._jwt(claims),
                    media_type="application/jwt",
                )
            return JSONResponse(claims)

        return app


def _mock_transport(idp: FakeIdp) -> httpx.MockTransport:
    """Bridge the server's *sync* httpx calls into the fake IdP's ASGI app.

    `httpx.ASGITransport` is async-only, and every route in this codebase is
    a sync `def` (see routes/*.py), so the transport the server uses has to be
    a sync one. `MockTransport` is sync-capable; the handler forwards into a
    `TestClient`, which is what actually runs the ASGI app.
    """
    inner = TestClient(idp.app, base_url=idp.issuer)

    def handler(request: httpx.Request) -> httpx.Response:
        forwarded = {
            key: value
            for key, value in request.headers.items()
            if key.lower() in ("authorization", "content-type", "accept")
        }
        upstream = inner.request(
            request.method,
            str(request.url),
            content=request.content,
            headers=forwarded,
        )
        # Rebuild rather than copy the headers: content-length and any
        # transfer encoding belong to the inner response's framing, not this
        # one's, and httpx recomputes them.
        headers = {}
        for key in ("content-type", "location", "www-authenticate"):
            if key in upstream.headers:
                headers[key] = upstream.headers[key]
        return httpx.Response(
            upstream.status_code, headers=headers, content=upstream.content
        )

    return httpx.MockTransport(handler)


@pytest.fixture()
def idp():
    """A fake IdP wired into `trmnl_server.oidc`'s outbound HTTP seam."""
    fake = FakeIdp()
    previous = oidc_module.HTTP_TRANSPORT
    oidc_module.HTTP_TRANSPORT = _mock_transport(fake)
    oidc_module.reset_caches()
    try:
        yield fake
    finally:
        oidc_module.HTTP_TRANSPORT = previous
        oidc_module.reset_caches()


def install_idp(fake: FakeIdp) -> None:
    """Point the outbound seam at a differently-configured `FakeIdp`."""
    oidc_module.HTTP_TRANSPORT = _mock_transport(fake)
    oidc_module.reset_caches()


def configure_oidc(tmp_path, **overrides) -> Config:
    """Turn OIDC on for the *live* panel config, the way the suite mutates it.

    `Config` reads the environment only in its `default_factory`, at
    construction time, so `monkeypatch.setenv` would do nothing to an app
    that is already built. Every other config test in this suite mutates the
    live object and restores in a `finally`; this does the same.
    """
    cfg = config_module.panel_config()
    secret_file = tmp_path / "oidc-client-secret"
    if not secret_file.exists():
        secret_file.write_text(OIDC_CLIENT_SECRET)
    cfg.oidc_issuer = OIDC_ISSUER
    cfg.oidc_client_id = OIDC_CLIENT_ID
    cfg.oidc_client_secret_file = str(secret_file)
    cfg.oidc_scopes = "openid profile email groups"
    cfg.oidc_groups_claim = "groups"
    cfg.oidc_allowed_groups = []
    cfg.oidc_redirect_url = ""
    cfg.oidc_provider_name = ""
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


@pytest.fixture()
def oidc_client(client, idp, tmp_path):
    """`client`, with OIDC configured against the fake IdP and then restored."""
    cfg = config_module.panel_config()
    snapshot = {
        key: getattr(cfg, key)
        for key in (
            "oidc_issuer", "oidc_client_id", "oidc_client_secret_file",
            "oidc_scopes", "oidc_groups_claim", "oidc_allowed_groups",
            "oidc_redirect_url", "oidc_provider_name",
        )
    }
    configure_oidc(tmp_path)
    try:
        yield client
    finally:
        for key, value in snapshot.items():
            setattr(cfg, key, value)
