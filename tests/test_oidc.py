"""OIDC: configuration surface, discovery, and the code flow.

Phase 1 of `docs/oidc-design.md`. Everything here runs against the
in-process fake IdP in `conftest.py` — no network, and the flow under test is
the real one: real `httpx` calls, real ASGI app on the other end.
"""

from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

import pytest

from conftest import (
    MAC,
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_ISSUER,
    TOKEN,
    UI_TOKEN,
    FakeIdp,
    install_idp,
)
from test_panel import CONTROL_PLANE_READS
from trmnl_server import oidc
from trmnl_server.config import panel_config
from trmnl_server.routes import oidc as oidc_routes


# --- the feature is off unless asked for ----------------------------------


def test_oidc_is_off_by_default(client):
    cfg = panel_config()
    assert cfg.oidc_issuer == ""
    assert oidc.is_configured(cfg) is False
    assert oidc.enabled(cfg) is False
    assert oidc.configuration_problem(cfg) == "TRMNL_OIDC_ISSUER is not set"
    level, message = oidc.startup_report(cfg)
    assert level == "info"
    assert "not configured" in message


def test_configuring_the_issuer_enables_it(oidc_client):
    cfg = panel_config()
    assert oidc.is_configured(cfg) is True
    assert oidc.configuration_problem(cfg) is None
    assert oidc.enabled(cfg) is True
    level, message = oidc.startup_report(cfg)
    assert level == "info"
    assert "OIDC login enabled" in message
    assert OIDC_ISSUER in message
    # The default with no group restriction has to be legible, because it is
    # the state a Google deployment is permanently in.
    assert "<any authenticated user>" in message


# --- discovery -------------------------------------------------------------


def test_discovery_is_fetched_parsed_and_cached(oidc_client, idp):
    cfg = panel_config()
    doc = oidc.discovery(cfg)
    assert doc["authorization_endpoint"] == f"{OIDC_ISSUER}/authorize"
    assert doc["token_endpoint"] == f"{OIDC_ISSUER}/token"
    assert doc["userinfo_endpoint"] == f"{OIDC_ISSUER}/userinfo"
    assert idp.discovery_hits == 1
    for _ in range(5):
        assert oidc.discovery(cfg) is doc
    assert idp.discovery_hits == 1, "the discovery document was not cached"


def test_issuer_trailing_slash_is_normalised(oidc_client, idp):
    """authentik's per-application issuer ends in `/`; nobody else's does."""
    cfg = panel_config()
    cfg.oidc_issuer = OIDC_ISSUER + "/"
    oidc.reset_caches()
    doc = oidc.discovery(cfg)
    assert doc["token_endpoint"] == f"{OIDC_ISSUER}/token"
    assert idp.discovery_hits == 1
    assert oidc.normalise_issuer(OIDC_ISSUER + "///") == OIDC_ISSUER


def test_an_advertised_issuer_mismatch_is_a_warning_not_a_failure(
    oidc_client, tmp_path
):
    """authentik in global issuer mode advertises a different `iss`.

    Rejecting that would break a provider this feature exists to support, so
    it logs and continues.
    """
    install_idp(FakeIdp(advertised_issuer="https://authentik.example/"))
    doc = oidc.discovery(panel_config())
    assert doc["token_endpoint"] == f"{OIDC_ISSUER}/token"


@pytest.mark.parametrize(
    "document",
    [
        {"issuer": OIDC_ISSUER},
        {"issuer": OIDC_ISSUER, "authorization_endpoint": f"{OIDC_ISSUER}/a",
         "token_endpoint": f"{OIDC_ISSUER}/t"},
        {"issuer": OIDC_ISSUER, "authorization_endpoint": "/relative",
         "token_endpoint": f"{OIDC_ISSUER}/t",
         "userinfo_endpoint": f"{OIDC_ISSUER}/u"},
    ],
    ids=["no-endpoints", "no-userinfo", "relative-endpoint"],
)
def test_an_unusable_discovery_document_is_refused(oidc_client, document):
    install_idp(FakeIdp(discovery_document=document))
    with pytest.raises(oidc.OidcError) as excinfo:
        oidc.discovery(panel_config())
    assert excinfo.value.code == "oidc_provider"


def test_a_discovery_outage_does_not_lock_out_the_shared_secret_login(
    oidc_client, tmp_path
):
    """The whole point of the ordering: one login path failing is not both."""
    install_idp(FakeIdp(discovery_status=503))
    with pytest.raises(oidc.OidcError) as excinfo:
        oidc.discovery(panel_config())
    assert excinfo.value.code == "oidc_provider"

    # ...and the secret path is entirely unaffected.
    assert oidc_client.post(
        "/auth/session", json={"token": UI_TOKEN}
    ).status_code == 204
    assert oidc_client.get("/rotation").status_code == 200


def test_a_discovery_failure_is_not_retried_within_the_backoff_window(
    oidc_client,
):
    """An unreachable IdP must not become one outbound connection per hit."""
    broken = FakeIdp(discovery_status=503)
    install_idp(broken)
    cfg = panel_config()
    for _ in range(5):
        with pytest.raises(oidc.OidcError):
            oidc.discovery(cfg)
    assert broken.discovery_hits == 1


def test_a_discovery_failure_is_retried_once_the_backoff_elapses(
    oidc_client, monkeypatch
):
    """A failure is a backoff, never a permanent cache. The outage heals."""
    monkeypatch.setattr(oidc, "DISCOVERY_RETRY_BACKOFF", 0.0)
    broken = FakeIdp(discovery_status=503)
    install_idp(broken)
    cfg = panel_config()

    with pytest.raises(oidc.OidcError):
        oidc.discovery(cfg)
    with pytest.raises(oidc.OidcError):
        oidc.discovery(cfg)
    assert broken.discovery_hits == 2, "the failure was cached, not retried"

    # And once the provider comes back, so does the login path — same
    # process, same cache, no restart and no manual flush.
    broken.discovery_status = 200
    assert oidc.discovery(cfg)["token_endpoint"] == f"{OIDC_ISSUER}/token"
    assert broken.discovery_hits == 3


# --- configuration validation ---------------------------------------------


@pytest.mark.parametrize(
    "field,value,fragment",
    [
        ("oidc_issuer", "not-a-url", "absolute http(s) URL"),
        ("oidc_client_id", "", "TRMNL_OIDC_CLIENT_ID"),
        ("oidc_client_secret_file", "", "TRMNL_OIDC_CLIENT_SECRET_FILE"),
        ("base_url", "", "TRMNL_BASE_URL"),
        ("oidc_redirect_url", "https://evil.example/auth/oidc/callback",
         "not under TRMNL_BASE_URL"),
    ],
)
def test_a_broken_config_disables_oidc_and_says_why(
    oidc_client, field, value, fragment
):
    cfg = panel_config()
    original = getattr(cfg, field)
    setattr(cfg, field, value)
    try:
        problem = oidc.configuration_problem(cfg)
        assert problem is not None
        assert fragment in problem, problem
        assert oidc.enabled(cfg) is False
        level, message = oidc.startup_report(cfg)
        assert level == "error"
        assert "OIDC login is DISABLED" in message
        assert "shared-secret login path (TRMNL_UI_TOKEN_FILE) is unaffected" in message
    finally:
        setattr(cfg, field, original)


def test_the_redirect_uri_is_derived_from_base_url(oidc_client):
    cfg = panel_config()
    assert cfg.oidc_callback_url() == "https://trmnl.example/auth/oidc/callback"


def test_a_redirect_url_on_the_same_origin_is_accepted(oidc_client):
    cfg = panel_config()
    cfg.oidc_redirect_url = "https://trmnl.example/auth/oidc/callback"
    assert oidc.configuration_problem(cfg) is None
    # A near-miss that shares a prefix but not an origin must still fail.
    cfg.oidc_redirect_url = "https://trmnl.example.evil.test/auth/oidc/callback"
    assert "not under TRMNL_BASE_URL" in (oidc.configuration_problem(cfg) or "")


def test_an_unreadable_client_secret_file_disables_oidc(oidc_client, tmp_path):
    """"Configured but unreadable" is a fault, and a fault fails closed."""
    cfg = panel_config()
    secret_path = Path(cfg.oidc_client_secret_file)
    assert oidc.enabled(cfg) is True

    secret_path.chmod(0o000)
    try:
        if os.access(secret_path, os.R_OK):  # pragma: no cover - running as root
            pytest.skip("cannot make a file unreadable as this user")
        assert cfg.oidc_client_secret() is None
        assert oidc.enabled(cfg) is False
        assert "could not be read" in (oidc.configuration_problem(cfg) or "")
    finally:
        secret_path.chmod(0o600)

    assert oidc.enabled(cfg) is True


def test_an_empty_client_secret_file_disables_oidc(oidc_client):
    cfg = panel_config()
    secret_path = Path(cfg.oidc_client_secret_file)
    secret_path.write_text("   \n")
    try:
        assert cfg.oidc_client_secret() is None
        assert oidc.enabled(cfg) is False
    finally:
        secret_path.write_text(OIDC_CLIENT_SECRET)
    assert oidc.enabled(cfg) is True


def test_provider_name_falls_back_to_the_issuer_host(oidc_client):
    cfg = panel_config()
    assert oidc.provider_name(cfg) == "idp.example"
    cfg.oidc_provider_name = "Authentik"
    assert oidc.provider_name(cfg) == "Authentik"


# --- the session secret now has two possible sources ----------------------


def test_session_secret_prefers_the_ui_token(oidc_client):
    cfg = panel_config()
    assert cfg.session_secret() == UI_TOKEN


def test_session_secret_falls_back_to_the_oidc_client_secret(oidc_client):
    """An OIDC-only deployment still has a key to sign sessions with."""
    cfg = panel_config()
    original = cfg.ui_token_file
    cfg.ui_token_file = ""
    try:
        assert cfg.ui_token() is None
        assert cfg.session_secret() == OIDC_CLIENT_SECRET
    finally:
        cfg.ui_token_file = original


def test_with_neither_login_method_there_is_no_session_secret(client):
    """Invariant 7: fail closed, never fail open."""
    cfg = panel_config()
    original = cfg.ui_token_file
    cfg.ui_token_file = ""
    try:
        assert cfg.oidc_client_secret_file == ""
        assert cfg.session_secret() is None
    finally:
        cfg.ui_token_file = original


def test_the_default_scopes_and_claim_match_the_provider_matrix(client):
    """Defaults are load-bearing: three of five providers need no override."""
    cfg = panel_config()
    assert cfg.oidc_scopes == "openid profile email groups"
    assert cfg.oidc_groups_claim == "groups"
    assert cfg.oidc_allowed_groups == []


def test_client_id_is_carried_through_configuration(oidc_client):
    assert panel_config().oidc_client_id == OIDC_CLIENT_ID


# --- phase 2: the authorization code flow ---------------------------------


def _state_cookie(response) -> str:
    """The raw `trmnl_oidc_state` value from a Set-Cookie header."""
    for header in response.headers.get_list("set-cookie"):
        if header.startswith(f"{oidc_routes.STATE_COOKIE}="):
            return header.split(";")[0].split("=", 1)[1]
    raise AssertionError(f"no state cookie in {response.headers!r}")


def begin_login(client) -> str:
    """Follow `/auth/oidc/login` and return the authorization URL."""
    response = client.get("/auth/oidc/login", follow_redirects=False)
    assert response.status_code == 302, response.text
    return response.headers["location"]


def run_flow(client, idp, *, sub: str = "alice"):
    """The whole browser round trip: login -> IdP -> callback."""
    callback_url = idp.authorize(begin_login(client), sub=sub)
    return client.get(callback_url, follow_redirects=False)


def test_login_redirects_to_the_provider_with_pkce_state_and_nonce(
    oidc_client, idp
):
    url = begin_login(oidc_client)
    assert url.startswith(f"{OIDC_ISSUER}/authorize?")
    params = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
    assert params["response_type"] == "code"
    assert params["client_id"] == OIDC_CLIENT_ID
    assert params["redirect_uri"] == "https://trmnl.example/auth/oidc/callback"
    assert params["scope"] == "openid profile email groups"
    assert params["code_challenge_method"] == "S256"
    assert len(params["code_challenge"]) >= 43
    assert params["state"] and params["nonce"]
    # The challenge is a hash, so it must not be the verifier itself.
    assert params["code_challenge"] != params["state"]


def test_the_state_cookie_is_lax_scoped_and_short_lived(oidc_client, idp):
    response = oidc_client.get("/auth/oidc/login", follow_redirects=False)
    header = next(
        h for h in response.headers.get_list("set-cookie")
        if h.startswith(f"{oidc_routes.STATE_COOKIE}=")
    ).lower()
    assert "httponly" in header
    # Lax, NOT Strict: the callback is a cross-site-initiated top-level
    # navigation, and a Strict cookie is simply not sent on it. Getting this
    # wrong breaks every real login while leaving curl unaffected.
    assert "samesite=lax" in header
    assert "path=/auth/oidc" in header
    assert "secure" in header  # base_url is https:// in the fixture
    assert f"max-age={oidc_routes.STATE_TTL}" in header


def test_the_session_cookie_stays_strict(oidc_client, idp):
    """Only the state cookie is relaxed. The session cookie is untouched."""
    response = run_flow(oidc_client, idp)
    header = next(
        h for h in response.headers.get_list("set-cookie")
        if h.startswith("trmnl_ui=")
    ).lower()
    assert "httponly" in header
    assert "samesite=strict" in header
    assert "secure" in header


def test_the_happy_path_mints_the_ordinary_session(oidc_client, idp):
    response = run_flow(oidc_client, idp)
    assert response.status_code == 302
    assert response.headers["location"] == "/auth/oidc/complete"
    # The IdP really was asked for a PKCE-verified exchange and for userinfo.
    assert idp.token_requests[0]["code_verifier"]
    assert idp.token_requests[0]["grant_type"] == "authorization_code"
    assert idp.userinfo_hits == 1
    # And the code is not left in the address bar.
    assert "code=" not in response.headers["location"]


@pytest.mark.parametrize("path", CONTROL_PLANE_READS)
def test_an_oidc_session_opens_the_whole_control_plane(oidc_client, idp, path):
    """The proof that OIDC really is "just another mint": same matrix.

    These are the exact paths `test_panel.py` runs against a shared-secret
    session. Nothing downstream distinguishes the two.
    """
    assert oidc_client.get(path).status_code == 401
    assert run_flow(oidc_client, idp).status_code == 302
    assert oidc_client.get(path).status_code == 200


def test_the_completion_page_navigates_home_itself(oidc_client, idp):
    """Not dead indirection — see decision 3 in routes/oidc.py."""
    run_flow(oidc_client, idp)
    page = oidc_client.get("/auth/oidc/complete")
    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    assert "location.replace('/')" in page.text


# --- state: forged, tampered, replayed, missing, crossed ------------------


def test_a_missing_state_cookie_is_refused(oidc_client, idp):
    callback_url = idp.authorize(begin_login(oidc_client))
    oidc_client.cookies.clear()
    response = oidc_client.get(callback_url, follow_redirects=False)
    assert response.headers["location"] == "/?login_error=oidc_state"
    assert oidc_client.get("/rotation").status_code == 401


def test_a_tampered_state_parameter_is_refused(oidc_client, idp):
    callback_url = idp.authorize(begin_login(oidc_client))
    tampered = callback_url.replace("state=", "state=x")
    response = oidc_client.get(tampered, follow_redirects=False)
    assert response.headers["location"] == "/?login_error=oidc_state"
    assert oidc_client.get("/rotation").status_code == 401


def test_a_forged_state_cookie_is_refused(oidc_client, idp):
    """The cookie is HMAC-signed, so an attacker-chosen one does not verify."""
    callback_url = idp.authorize(begin_login(oidc_client))
    payload = {
        "exp": int(time.time()) + 300,
        "state": parse_qs(urlsplit(callback_url).query)["state"][0],
        "nonce": "n",
        "verifier": "v" * 43,
    }
    forged = f"{oidc_routes.STATE_VERSION}." + base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).decode().rstrip("=") + ".not-a-real-signature"
    oidc_client.cookies.set(
        oidc_routes.STATE_COOKIE, forged, domain="trmnl.example", path="/auth/oidc"
    )
    response = oidc_client.get(callback_url, follow_redirects=False)
    assert response.headers["location"] == "/?login_error=oidc_state"


def test_an_expired_state_cookie_is_refused(oidc_client, idp):
    callback_url = idp.authorize(begin_login(oidc_client))
    state = parse_qs(urlsplit(callback_url).query)["state"][0]
    stale = oidc_routes._pack_state(UI_TOKEN, {
        "exp": int(time.time()) - 1,
        "state": state,
        "nonce": "n",
        "verifier": "v" * 43,
    })
    oidc_client.cookies.set(
        oidc_routes.STATE_COOKIE, stale, domain="trmnl.example", path="/auth/oidc"
    )
    response = oidc_client.get(callback_url, follow_redirects=False)
    assert response.headers["location"] == "/?login_error=oidc_state"


def test_a_replayed_state_is_refused(oidc_client, idp):
    """Single-use: the same callback URL cannot be redeemed twice."""
    login = oidc_client.get("/auth/oidc/login", follow_redirects=False)
    cookie = _state_cookie(login)
    callback_url = idp.authorize(login.headers["location"])

    first = oidc_client.get(callback_url, follow_redirects=False)
    assert first.headers["location"] == "/auth/oidc/complete"

    # Put the (still unexpired) cookie back, exactly as a back-button
    # navigation or a retrying proxy would, and try the same code again.
    oidc_client.cookies.clear()
    oidc_client.cookies.set(
        oidc_routes.STATE_COOKIE, cookie, domain="trmnl.example", path="/auth/oidc"
    )
    second = oidc_client.get(callback_url, follow_redirects=False)
    assert second.headers["location"] == "/?login_error=oidc_state"


def test_a_state_cookie_from_another_login_attempt_is_refused(oidc_client, idp):
    """The cookie must match *this* attempt, not merely be a valid cookie."""
    other = oidc_client.get("/auth/oidc/login", follow_redirects=False)
    other_cookie = _state_cookie(other)
    callback_url = idp.authorize(begin_login(oidc_client))
    oidc_client.cookies.clear()
    oidc_client.cookies.set(
        oidc_routes.STATE_COOKIE, other_cookie,
        domain="trmnl.example", path="/auth/oidc",
    )
    response = oidc_client.get(callback_url, follow_redirects=False)
    assert response.headers["location"] == "/?login_error=oidc_state"


def test_a_non_ascii_state_cookie_is_a_refusal_not_a_500(oidc_client, idp):
    callback_url = idp.authorize(begin_login(oidc_client))
    response = oidc_client.get(
        callback_url,
        headers={"Cookie": f"{oidc_routes.STATE_COOKIE}=o1.caf\xc3\xa9.sig".encode("latin-1")},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/?login_error=oidc_state"


def test_an_issuer_mismatch_in_the_callback_is_refused(oidc_client, idp):
    """RFC 9207: when `iss` is present it must be the issuer we started with."""
    callback_url = idp.authorize(begin_login(oidc_client))
    swapped = callback_url.replace(
        f"iss={quote(OIDC_ISSUER, safe='')}", "iss=https%3A%2F%2Fevil.example"
    )
    assert swapped != callback_url
    response = oidc_client.get(swapped, follow_redirects=False)
    assert response.headers["location"] == "/?login_error=oidc_state"


# --- PKCE and nonce -------------------------------------------------------


def test_a_wrong_pkce_verifier_fails_the_exchange(oidc_client, idp):
    """The code is bound to the challenge, so a substituted verifier fails."""
    login = oidc_client.get("/auth/oidc/login", follow_redirects=False)
    callback_url = idp.authorize(login.headers["location"])
    genuine = oidc_routes._unpack_state(UI_TOKEN, _state_cookie(login))
    assert genuine is not None
    swapped = oidc_routes._pack_state(UI_TOKEN, {
        **genuine, "verifier": "a-completely-different-verifier-" + "x" * 20,
    })
    oidc_client.cookies.clear()
    oidc_client.cookies.set(
        oidc_routes.STATE_COOKIE, swapped, domain="trmnl.example", path="/auth/oidc"
    )
    response = oidc_client.get(callback_url, follow_redirects=False)
    assert response.headers["location"] == "/?login_error=oidc_provider"
    assert oidc_client.get("/rotation").status_code == 401


def test_a_mismatched_nonce_is_refused(oidc_client):
    """The id_token must belong to *this* login attempt."""
    idp = FakeIdp(nonce_override="somebody-elses-nonce")
    install_idp(idp)
    response = run_flow(oidc_client, idp)
    assert response.headers["location"] == "/?login_error=oidc_nonce"
    assert oidc_client.get("/rotation").status_code == 401


def test_a_token_response_without_an_id_token_is_refused(oidc_client):
    idp = FakeIdp(omit_id_token=True)
    install_idp(idp)
    response = run_flow(oidc_client, idp)
    assert response.headers["location"] == "/?login_error=oidc_provider"


def test_a_signed_userinfo_response_is_refused_rather_than_trusted(oidc_client):
    """No crypto dependency means no consuming a signature we cannot check."""
    idp = FakeIdp(userinfo_content_type="application/jwt")
    install_idp(idp)
    response = run_flow(oidc_client, idp)
    assert response.headers["location"] == "/?login_error=oidc_userinfo_jwt"


# --- open redirect --------------------------------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "?next=https://evil.example",
        "?redirect_uri=https://evil.example/steal",
        "?return_to=//evil.example",
        "?next=/auth/oidc/callback%3Fcode%3Dx",
    ],
)
def test_login_ignores_every_caller_supplied_destination(oidc_client, idp, query):
    """The route takes no parameters at all, which is the whole mitigation."""
    response = oidc_client.get(
        f"/auth/oidc/login{query}", follow_redirects=False
    )
    assert response.status_code == 302
    params = {
        k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).query).items()
    }
    assert params["redirect_uri"] == "https://trmnl.example/auth/oidc/callback"
    assert "evil.example" not in response.headers["location"]

    # ...and the flow still lands on this server's own origin.
    callback_url = idp.authorize(response.headers["location"])
    done = oidc_client.get(callback_url, follow_redirects=False)
    assert done.headers["location"] == "/auth/oidc/complete"


def test_a_redirect_uri_outside_base_url_disables_the_feature(oidc_client, idp):
    """Config cannot open the redirect either — the feature turns off first."""
    cfg = panel_config()
    cfg.oidc_redirect_url = "https://evil.example/auth/oidc/callback"
    try:
        response = oidc_client.get("/auth/oidc/login", follow_redirects=False)
        assert response.headers["location"] == "/?login_error=oidc_disabled"
    finally:
        cfg.oidc_redirect_url = ""


# --- the two credentials stay separate ------------------------------------


def test_an_oidc_session_is_not_a_panel_credential_and_vice_versa(
    oidc_client, idp
):
    assert run_flow(oidc_client, idp).status_code == 302
    # A control-plane session is not an Access-Token...
    cookie = oidc_client.cookies.get("trmnl_ui")
    assert cookie
    assert oidc_client.get(
        "/api/display", headers={"ID": MAC, "Access-Token": cookie}
    ).status_code == 401
    # ...and an Access-Token does not satisfy the OIDC callback.
    oidc_client.cookies.clear()
    response = oidc_client.get(
        "/auth/oidc/callback?code=x&state=y",
        headers={"Access-Token": TOKEN},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/?login_error=oidc_state"


# --- invariant 1: the device surface is untouched -------------------------


def test_oidc_never_touches_the_device_api(oidc_client, idp):
    """The panel is an ESP32. It follows no redirects and does no SSO.

    With OIDC fully enabled, every device path must still work on a MAC
    allowlist plus an Access-Token header, with no cookie, no session and no
    302 anywhere near it.
    """
    oidc_client.cookies.clear()
    setup = oidc_client.get("/api/setup", headers={"ID": MAC}, follow_redirects=False)
    assert setup.status_code == 200
    assert setup.json()["api_key"] == TOKEN
    assert oidc_client.get(
        "/api/setup/", headers={"ID": MAC}, follow_redirects=False
    ).status_code == 200

    display = oidc_client.get(
        "/api/display",
        headers={"ID": MAC, "Access-Token": TOKEN},
        follow_redirects=False,
    )
    assert display.status_code == 200
    image_url = display.json()["image_url"]
    assert "/image/" in image_url

    # The frame itself: no auth header at all, the unguessable path is the
    # capability, and no redirect.
    frame = oidc_client.get(
        image_url.replace("https://trmnl.example", ""), follow_redirects=False
    )
    assert frame.status_code == 200
    assert frame.headers["content-type"] == "image/bmp"

    assert oidc_client.post(
        "/api/log", content=b"hello", headers={"ID": MAC}
    ).status_code == 204
    # Not one Set-Cookie on any of it.
    assert "set-cookie" not in frame.headers


def test_no_oidc_route_lives_under_api(oidc_client):
    from trmnl_server.main import _DEVICE_API_PATHS, _under_api, route_paths

    paths = route_paths(oidc_client.app)
    assert {"/auth/oidc/login", "/auth/oidc/callback"} <= paths
    assert {p for p in paths if _under_api(p)} <= _DEVICE_API_PATHS


# --- disabled, broken and throttled ---------------------------------------


def test_login_when_oidc_is_off_says_so_instead_of_500ing(client):
    response = client.get("/auth/oidc/login", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "/?login_error=oidc_disabled"


def test_a_discovery_outage_leaves_the_secret_form_working(oidc_client):
    install_idp(FakeIdp(discovery_status=503))
    response = oidc_client.get("/auth/oidc/login", follow_redirects=False)
    assert response.headers["location"] == "/?login_error=oidc_provider"
    # The other login path is completely unaffected.
    assert oidc_client.post(
        "/auth/session", json={"token": UI_TOKEN}
    ).status_code == 204
    assert oidc_client.get("/rotation").status_code == 200


def test_the_callback_is_throttled_like_the_secret_mint(oidc_client, idp):
    from trmnl_server.routes import auth as auth_module

    auth_module._mint_failures.clear()
    auth_module._mint_global_failures.clear()
    codes = []
    for _ in range(auth_module._MINT_FAIL_LIMIT + 3):
        response = oidc_client.get(
            "/auth/oidc/callback?code=x&state=guess", follow_redirects=False
        )
        codes.append(response.headers["location"])
    assert codes[: auth_module._MINT_FAIL_LIMIT] == [
        "/?login_error=oidc_state"
    ] * auth_module._MINT_FAIL_LIMIT
    assert set(codes[auth_module._MINT_FAIL_LIMIT:]) == {
        "/?login_error=oidc_throttled"
    }
    auth_module._mint_failures.clear()
    auth_module._mint_global_failures.clear()


def test_a_successful_oidc_login_clears_the_failure_counter(oidc_client, idp):
    from trmnl_server.routes import auth as auth_module

    auth_module._mint_failures.clear()
    auth_module._mint_global_failures.clear()
    for _ in range(auth_module._MINT_FAIL_LIMIT - 1):
        oidc_client.get("/auth/oidc/callback?code=x&state=y", follow_redirects=False)
    assert run_flow(oidc_client, idp).headers["location"] == "/auth/oidc/complete"
    assert not auth_module._mint_failures
    auth_module._mint_global_failures.clear()


# --- provider variation ---------------------------------------------------


@pytest.mark.parametrize(
    "methods,expect_basic",
    [
        (None, True),                        # spec default when unadvertised
        (["client_secret_basic"], True),     # Authelia's default, enforced
        (["client_secret_post"], False),     # post-only providers
        (["client_secret_post", "client_secret_basic"], True),  # Google
    ],
)
def test_token_endpoint_auth_follows_discovery(oidc_client, methods, expect_basic):
    """Hardcoding `client_secret_post` breaks Authelia. So it is read, not assumed."""
    idp = FakeIdp(auth_methods=methods)
    install_idp(idp)
    assert run_flow(oidc_client, idp).headers["location"] == "/auth/oidc/complete"
    assert idp.token_requests[0]["has_basic"] is expect_basic


def test_a_provider_supporting_neither_method_is_refused(oidc_client):
    idp = FakeIdp(auth_methods=["private_key_jwt"])
    install_idp(idp)
    response = run_flow(oidc_client, idp)
    assert response.headers["location"] == "/?login_error=oidc_provider"


def test_an_authorization_endpoint_with_a_query_string_is_appended_to(
    oidc_client,
):
    """Some deployments put a tenant id in the authorize URL's query."""
    document = {
        "issuer": OIDC_ISSUER,
        "authorization_endpoint": f"{OIDC_ISSUER}/authorize?tenant=home",
        "token_endpoint": f"{OIDC_ISSUER}/token",
        "userinfo_endpoint": f"{OIDC_ISSUER}/userinfo",
    }
    install_idp(FakeIdp(discovery_document=document))
    url = begin_login(oidc_client)
    params = parse_qs(urlsplit(url).query)
    assert params["tenant"] == ["home"]
    assert params["code_challenge_method"] == ["S256"]


# --- an OIDC-only deployment ----------------------------------------------


def test_an_oidc_only_deployment_can_log_in(oidc_client, idp):
    """No TRMNL_UI_TOKEN_FILE at all: the design's "neither is mandatory"."""
    cfg = panel_config()
    original = cfg.ui_token_file
    cfg.ui_token_file = ""
    oidc_client.cookies.clear()
    try:
        assert cfg.session_secret() == OIDC_CLIENT_SECRET
        # The secret form is gone...
        assert oidc_client.post(
            "/auth/session", json={"token": UI_TOKEN}
        ).status_code == 503
        # ...but the control plane is reachable through SSO.
        assert oidc_client.get("/rotation").status_code == 401
        assert run_flow(oidc_client, idp).headers["location"] == "/auth/oidc/complete"
        assert oidc_client.get("/rotation").status_code == 200
    finally:
        cfg.ui_token_file = original


def test_with_neither_method_the_control_plane_is_503(client):
    """Invariant 7 end to end: fail closed, never fail open."""
    cfg = panel_config()
    original = cfg.ui_token_file
    cfg.ui_token_file = ""
    try:
        assert client.get("/rotation").status_code == 503
        assert client.post("/auth/session", json={"token": UI_TOKEN}).status_code == 503
        assert client.get(
            "/auth/oidc/login", follow_redirects=False
        ).headers["location"] == "/?login_error=oidc_disabled"
    finally:
        cfg.ui_token_file = original


# --- what the UI is told --------------------------------------------------


def test_session_state_reports_both_login_methods(oidc_client, idp):
    body = oidc_client.get("/auth/session").json()
    assert body == {
        "configured": True,
        "authenticated": False,
        "oidc": True,
        "oidc_provider": "idp.example",
    }
    run_flow(oidc_client, idp)
    assert oidc_client.get("/auth/session").json()["authenticated"] is True


def test_session_state_hides_a_broken_provider(oidc_client):
    cfg = panel_config()
    cfg.oidc_client_id = ""
    try:
        body = oidc_client.get("/auth/session").json()
        assert body["oidc"] is False
        assert body["oidc_provider"] is None
        assert body["configured"] is True
    finally:
        cfg.oidc_client_id = OIDC_CLIENT_ID


def test_session_state_without_oidc_is_unchanged(client):
    body = client.get("/auth/session").json()
    assert body == {
        "configured": True,
        "authenticated": False,
        "oidc": False,
        "oidc_provider": None,
    }
