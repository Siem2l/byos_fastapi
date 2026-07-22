"""OIDC: configuration surface, discovery, and the code flow.

Phase 1 of `docs/oidc-design.md`. Everything here runs against the
in-process fake IdP in `conftest.py` — no network, and the flow under test is
the real one: real `httpx` calls, real ASGI app on the other end.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import (
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_ISSUER,
    UI_TOKEN,
    FakeIdp,
    install_idp,
)
from trmnl_server import oidc
from trmnl_server.config import panel_config


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
