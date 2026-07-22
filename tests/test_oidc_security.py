"""Adversarial regression suite for the OIDC login path.

Every test here started life as a *passing exploit* in an adversarial review
of `feat/oidc`. Each one has been inverted in place: where the proof-of-concept
asserted that the attack worked, the test now asserts the safe behaviour. So a
failure in this file is not "a test broke" — it is "an exploit came back", and
the docstring above each test names the class.

Keep it. Do not fold it into `test_oidc.py`: that file documents what the
feature does, this one documents what it refuses to do, and the two rot in
different directions.

The findings, in the order the review ranked them:

1. HIGH   — an unauthenticated flood of `/auth/oidc/login` starved the shared
            threadpool and stalled the *device* plane. The panel is an ESP32
            that cannot retry and cannot report; a control-plane endpoint must
            never be able to take it down.
2. HIGH   — cross-site GETs on `/auth/oidc/callback` spent the shared-secret
            login's global failure budget and locked every operator out.
3. MED-HI — the ID token's `iss`, `aud`, `azp` and `exp` were never checked.
4. MED    — userinfo's `sub` was never bound to the ID token's (OIDC 5.3.2).
5. MED    — no transport-scheme enforcement: an `http://` issuer was accepted,
            which voids the §3.1.3.7-item-6 premise this design rests on.
6. LOW-MD — unbounded IdP response bodies.
7. LOW    — PKCE support was never negotiated; a downgrade was undetectable.
8. LOW    — the single-use state ledger had a flush primitive.
9. LOW    — IdP-controlled strings reached the log unbounded and unscrubbed.
"""

from __future__ import annotations

import threading
import time
from statistics import median
from urllib.parse import urlsplit

import pytest

from trmnl_server import oidc as oidc_module
from trmnl_server.routes import auth as auth_module
from trmnl_server.routes import oidc as oidc_routes

from conftest import (
    MAC,
    OIDC_ISSUER,
    TOKEN,
    UI_TOKEN,
    FakeIdp,
    configure_oidc,
    install_idp,
)


def run_flow(client, idp, *, sub="alice"):
    """One complete browser round trip. Returns the callback's response."""
    login = client.get("/auth/oidc/login", follow_redirects=False)
    assert login.status_code == 302, login.status_code
    callback = idp.authorize(login.headers["location"], sub=sub)
    split = urlsplit(callback)
    return client.get(f"{split.path}?{split.query}", follow_redirects=False)


# --- 1: the device plane must not be collateral damage ---------------------


class SlowIdp(FakeIdp):
    """A provider that answers discovery slowly, the way a sick one does.

    Tracks concurrent in-flight discovery requests, because "how many
    threadpool workers can an unauthenticated caller tie up" is the entire
    question this finding is about.
    """

    def __init__(self, delay: float = 0.5, **kwargs) -> None:
        super().__init__(**kwargs)
        self.delay = delay
        self.concurrent = 0
        self.peak_concurrent = 0
        self._gauge = threading.Lock()
        inner = self.app

        @inner.middleware("http")
        async def _measure(request, call_next):
            with self._gauge:
                self.concurrent += 1
                self.peak_concurrent = max(self.peak_concurrent, self.concurrent)
            try:
                time.sleep(self.delay)
                return await call_next(request)
            finally:
                with self._gauge:
                    self.concurrent -= 1


def test_outbound_idp_calls_are_bounded(oidc_client, tmp_path):
    """Finding 1. A slow IdP must not be able to hold every worker.

    The PoC held one threadpool worker per concurrent login for as long as the
    provider cared to stall. `oidc.OUTBOUND_LIMIT` is now the ceiling, and it
    is enforced by refusing rather than queueing — queueing *is* the resource
    the attacker is after.
    """
    slow = SlowIdp(delay=0.4)
    install_idp(slow)
    oidc_routes.LOGIN_BUDGET.reset()

    workers = oidc_module.OUTBOUND_LIMIT * 4
    barrier = threading.Barrier(workers)

    def hit():
        barrier.wait()
        try:
            oidc_module.discovery(oidc_module.config_module.panel_config())
        except oidc_module.OidcError:
            pass

    threads = [threading.Thread(target=hit) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert slow.peak_concurrent <= oidc_module.OUTBOUND_LIMIT, (
        f"{slow.peak_concurrent} concurrent outbound calls, ceiling is "
        f"{oidc_module.OUTBOUND_LIMIT}"
    )


def test_concurrent_cold_logins_make_exactly_one_discovery_fetch(
    oidc_client, tmp_path
):
    """Finding 1 (thundering herd). N concurrent logins were N fetches.

    The inverted PoC F: the assertion used to be `discovery_hits >= 1`, which
    is true of any number. Single-flight makes it exactly one.
    """
    fake = SlowIdp(delay=0.2)
    install_idp(fake)
    oidc_routes.LOGIN_BUDGET.reset()
    barrier = threading.Barrier(8)

    def hit():
        barrier.wait()
        oidc_client.get("/auth/oidc/login", follow_redirects=False)

    threads = [threading.Thread(target=hit) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert fake.discovery_hits == 1, (
        f"8 concurrent cold logins made {fake.discovery_hits} outbound "
        "discovery requests"
    )


def test_a_login_flood_does_not_stall_the_device_plane(oidc_client, tmp_path):
    """Finding 1, the invariant that matters: `/api/display` keeps working.

    An unauthenticated flood of `/auth/oidc/login` against a stalling IdP,
    while the panel's own endpoint is polled throughout. Every device request
    must succeed, and none may wait anywhere near the IdP's stall time.
    """
    slow = SlowIdp(delay=1.0)
    install_idp(slow)
    oidc_routes.LOGIN_BUDGET.reset()

    stop = threading.Event()
    flood_hits = [0]
    flood_lock = threading.Lock()

    def flood():
        while not stop.is_set():
            try:
                oidc_client.get("/auth/oidc/login", follow_redirects=False)
            except Exception:  # pragma: no cover - the flood is best-effort
                pass
            with flood_lock:
                flood_hits[0] += 1

    floods = [threading.Thread(target=flood, daemon=True) for _ in range(24)]
    for t in floods:
        t.start()
    try:
        latencies = []
        statuses = []
        for _ in range(20):
            started = time.monotonic()
            resp = oidc_client.get(
                "/api/display", headers={"ID": MAC, "Access-Token": TOKEN}
            )
            latencies.append(time.monotonic() - started)
            statuses.append(resp.status_code)
    finally:
        stop.set()
        for t in floods:
            t.join(timeout=15)

    worst = max(latencies)
    print(
        f"device plane under a {flood_hits[0]}-request login flood: "
        f"median {median(latencies) * 1000:.1f} ms, worst "
        f"{worst * 1000:.1f} ms, statuses {set(statuses)}"
    )
    assert set(statuses) == {200}, "the panel was refused while the flood ran"
    # The IdP stalls for a full second per call. If the flood could reach the
    # threadpool, device latency would be a multiple of that.
    assert worst < 1.0, f"worst device latency {worst:.3f}s under flood"


def test_the_login_endpoint_is_rate_limited(oidc_client, idp):
    """Finding 1. `/auth/oidc/login` counted nothing at all before."""
    oidc_routes.LOGIN_BUDGET.reset()
    limit = oidc_routes.LOGIN_BUDGET.per_source_limit
    codes = [
        oidc_client.get("/auth/oidc/login", follow_redirects=False)
        for _ in range(limit + 5)
    ]
    assert all(r.status_code == 302 for r in codes)
    assert all(
        "/?login_error=" not in r.headers["location"] for r in codes[:limit]
    )
    assert {r.headers["location"] for r in codes[limit:]} == {
        "/?login_error=oidc_throttled"
    }


def test_a_login_flood_does_not_lock_out_the_secret_login(oidc_client, idp):
    """Finding 1 + 2. Throttling the SSO path must cost the other path nothing."""
    oidc_routes.LOGIN_BUDGET.reset()
    auth_module.MINT_BUDGET.reset()
    for _ in range(oidc_routes.LOGIN_BUDGET.per_source_limit + 20):
        oidc_client.get("/auth/oidc/login", follow_redirects=False)
    assert oidc_client.post(
        "/auth/session", json={"token": UI_TOKEN}
    ).status_code == 204


# --- 2: a callback flood must not spend the shared-secret budget -----------


def test_a_callback_flood_does_not_lock_out_the_secret_login(client, tmp_path):
    """Finding 2, inverted PoC E.

    100 cross-site GETs — no credential, no cookie, free to send — used to
    exhaust `auth`'s *global* mint budget, so the correct UI secret then got
    a 429. The two paths now keep separate accounting.
    """
    configure_oidc(tmp_path)
    auth_module.MINT_BUDGET.reset()
    oidc_routes.CALLBACK_BUDGET.reset()
    for i in range(100):
        response = client.get(
            f"/auth/oidc/callback?state=x{i}&code=y", follow_redirects=False
        )
        assert response.status_code == 302
    response = client.post("/auth/session", json={"token": UI_TOKEN})
    print("POST /auth/session with the correct secret ->", response.status_code)
    assert response.status_code == 204


def test_a_secret_login_flood_does_not_lock_out_the_callback(
    oidc_client, idp, tmp_path
):
    """Finding 2, the other direction. Separate means separate both ways."""
    auth_module.MINT_BUDGET.reset()
    oidc_routes.CALLBACK_BUDGET.reset()
    for i in range(auth_module.MINT_FAIL_LIMIT + 5):
        client_status = oidc_client.post(
            "/auth/session", json={"token": f"guess-{i}"}
        ).status_code
        assert client_status in (401, 429)
    assert oidc_client.post(
        "/auth/session", json={"token": UI_TOKEN}
    ).status_code == 429
    # ...and SSO is entirely unaffected.
    assert run_flow(oidc_client, idp).headers["location"] == "/auth/oidc/complete"
    auth_module.MINT_BUDGET.reset()


# --- 3: the ID token's claims are checked, even though its signature is not -


class ForgedClaimsIdp(FakeIdp):
    """A provider that mints a token for someone else, and expired at that."""

    def __init__(self, **overrides) -> None:
        self.claim_overrides = overrides.pop("claim_overrides", {})
        super().__init__(**overrides)

    def _claims(self, sub: str, *, nonce: str | None) -> dict:
        claims = super()._claims(sub, nonce=nonce)
        claims.update(self.claim_overrides)
        return claims


@pytest.mark.parametrize(
    "overrides,why",
    [
        (
            {
                "iss": "https://totally-other-issuer.example",
                "aud": "some-other-client",
                "azp": "some-other-client",
                "exp": int(time.time()) - 86400,
                "iat": int(time.time()) - 172800,
            },
            "the original PoC B: wrong issuer, wrong audience, expired",
        ),
        ({"iss": "https://totally-other-issuer.example"}, "wrong issuer"),
        ({"iss": ""}, "no issuer"),
        ({"aud": "some-other-client"}, "wrong audience"),
        ({"aud": []}, "empty audience"),
        ({"aud": None}, "no audience"),
        ({"azp": "some-other-client"}, "wrong authorized party"),
        ({"aud": ["trmnl", "another-client"]}, "multiple audiences, no azp"),
        ({"exp": int(time.time()) - 86400}, "expired a day ago"),
        ({"exp": int(time.time()) - 600}, "expired well past the skew window"),
        ({"exp": "soon"}, "unparseable exp"),
        ({"exp": None}, "no exp"),
        ({"iat": int(time.time()) + 86400}, "issued a day in the future"),
        ({"sub": ""}, "no subject"),
    ],
)
def test_a_forged_id_token_is_refused(client, tmp_path, overrides, why):
    """Finding 3, inverted PoC B.

    Skipping the *signature* is what §3.1.3.7 item 6 permits when the token
    came straight back from the token endpoint over TLS. Skipping the *claims*
    was never covered by that, and without them any provider — or anyone who
    can make this server talk to one — can mint an admin session.
    """
    configure_oidc(tmp_path)
    forged = ForgedClaimsIdp(claim_overrides=overrides)
    install_idp(forged)
    response = run_flow(client, forged)
    assert response.headers["location"] == "/?login_error=oidc_claims", why
    assert "trmnl_ui" not in response.headers.get("set-cookie", "")
    assert client.get("/status").status_code == 401


def test_a_token_within_the_clock_skew_window_still_works(client, tmp_path):
    """The skew allowance is real, or a provider without NTP locks everyone out."""
    configure_oidc(tmp_path)
    fresh = ForgedClaimsIdp(claim_overrides={"exp": int(time.time()) - 30})
    install_idp(fresh)
    assert run_flow(client, fresh).headers["location"] == "/auth/oidc/complete"


def test_the_advertised_issuer_is_accepted_as_well_as_the_configured_one(
    client, tmp_path
):
    """authentik in global issuer mode advertises an `iss` of its own.

    Rejecting it would break a provider this feature exists to support, so the
    accepted set is exactly those two values — and nothing else.
    """
    configure_oidc(tmp_path)
    authentik = ForgedClaimsIdp(
        advertised_issuer="https://authentik.example",
        claim_overrides={"iss": "https://authentik.example"},
    )
    install_idp(authentik)
    assert run_flow(client, authentik).headers["location"] == "/auth/oidc/complete"


# --- 4: userinfo is bound to the ID token (OIDC Core 5.3.2) ----------------


@pytest.mark.parametrize(
    "userinfo_claims,why",
    [
        (
            {
                "sub": "mallory",
                "preferred_username": "mallory",
                "groups": ["trmnl-admins"],
            },
            "the original PoC A: userinfo names a different subject entirely",
        ),
        ({}, "PoC A2: a completely empty userinfo response"),
        ({"preferred_username": "alice", "groups": ["trmnl-admins"]},
         "claims but no sub at all"),
        ({"sub": "", "groups": ["trmnl-admins"]}, "an empty sub"),
        ({"sub": None, "groups": ["trmnl-admins"]}, "a null sub"),
        ({"sub": ["alice"], "groups": ["trmnl-admins"]}, "a non-string sub"),
    ],
)
def test_userinfo_must_match_the_id_token_subject(
    oidc_client, idp, userinfo_claims, why
):
    """Finding 4, inverted PoCs A and A2.

    Identity in this design comes from `userinfo`; the ID token is what binds
    the response to this login attempt. Unbound, the two are unrelated and the
    group decision is made about whoever `userinfo` names.
    """
    idp.userinfo_claims = userinfo_claims
    response = run_flow(oidc_client, idp, sub="alice")
    assert response.headers["location"] == "/?login_error=oidc_subject", why
    assert "trmnl_ui" not in response.headers.get("set-cookie", "")
    assert oidc_client.get("/status").status_code == 401


def test_a_matching_userinfo_subject_still_logs_in(oidc_client, idp):
    """The binding must not break the ordinary case it exists to protect."""
    idp.userinfo_claims = {
        "sub": "alice", "preferred_username": "alice", "groups": ["trmnl-admins"]
    }
    assert run_flow(oidc_client, idp, sub="alice").headers[
        "location"
    ] == "/auth/oidc/complete"
    assert oidc_client.get("/status").status_code == 200


# --- 5: no plaintext transport, because the design rests on TLS ------------


@pytest.mark.parametrize(
    "issuer",
    [
        "http://idp.lan",
        "http://idp.example",
        "http://192.168.1.10:9000",
        "http://[2001:db8::1]/idp",
    ],
)
def test_a_plaintext_issuer_disables_oidc(client, tmp_path, issuer):
    """Finding 5, inverted PoC C.

    Not a nice-to-have. The zero-dependency design skips the ID token
    signature under OIDC Core 3.1.3.7 item 6, which permits it only because
    the token arrives "over a TLS-protected channel". Over http there is no
    such channel, so the exemption does not apply and the whole argument for
    not carrying a JWT library collapses.
    """
    cfg = configure_oidc(tmp_path, oidc_issuer=issuer)
    problem = oidc_module.configuration_problem(cfg)
    print("configuration_problem ->", problem)
    assert problem is not None
    assert "3.1.3.7" in problem
    assert oidc_module.enabled(cfg) is False


@pytest.mark.parametrize(
    "issuer",
    [
        "http://127.0.0.1:9000",
        "http://127.0.0.2:9000",
        "http://localhost:9000",
        "http://[::1]:9000",
        "http://idp.localhost:9000",
    ],
)
def test_loopback_http_is_still_permitted(client, tmp_path, issuer):
    """...and local development keeps working, which is why loopback is carved out."""
    cfg = configure_oidc(
        tmp_path, oidc_issuer=issuer, base_url="http://127.0.0.1:8105"
    )
    try:
        assert oidc_module.configuration_problem(cfg) is None
        assert oidc_module.enabled(cfg) is True
    finally:
        cfg.base_url = "https://trmnl.example"


def test_a_plaintext_redirect_uri_disables_oidc(client, tmp_path):
    """The authorization code comes back on it. It is not a lesser hop."""
    cfg = configure_oidc(tmp_path, base_url="http://trmnl.example")
    try:
        problem = oidc_module.configuration_problem(cfg)
        assert problem is not None and "redirect URI" in problem
    finally:
        cfg.base_url = "https://trmnl.example"


def test_discovery_may_not_move_an_endpoint_to_plaintext(client, tmp_path):
    """Finding 5, inverted PoC C2.

    A correct https issuer is not enough if the document it serves can then
    move the token endpoint — where the client_secret goes and the ID token
    comes back — onto a cleartext hop.
    """
    configure_oidc(tmp_path)
    for endpoint in (
        "authorization_endpoint", "token_endpoint", "userinfo_endpoint"
    ):
        document = {
            "issuer": OIDC_ISSUER,
            "authorization_endpoint": f"{OIDC_ISSUER}/authorize",
            "token_endpoint": f"{OIDC_ISSUER}/token",
            "userinfo_endpoint": f"{OIDC_ISSUER}/userinfo",
            "code_challenge_methods_supported": ["S256"],
        }
        document[endpoint] = "http://evil.example/x"
        install_idp(FakeIdp(discovery_document=document))
        login = client.get("/auth/oidc/login", follow_redirects=False)
        assert login.status_code == 302
        assert login.headers["location"] == "/?login_error=oidc_provider", endpoint


# --- 6: IdP response bodies are bounded ------------------------------------


def test_an_oversized_discovery_document_is_refused(client, tmp_path):
    """Finding 6. The IdP is a remote party an unauthenticated caller invokes."""
    configure_oidc(tmp_path)
    install_idp(FakeIdp(discovery_document={
        "issuer": OIDC_ISSUER,
        "authorization_endpoint": f"{OIDC_ISSUER}/authorize",
        "token_endpoint": f"{OIDC_ISSUER}/token",
        "userinfo_endpoint": f"{OIDC_ISSUER}/userinfo",
        "code_challenge_methods_supported": ["S256"],
        "padding": "x" * (oidc_module.MAX_RESPONSE_BYTES + 1),
    }))
    login = client.get("/auth/oidc/login", follow_redirects=False)
    assert login.headers["location"] == "/?login_error=oidc_provider"


def test_an_oversized_userinfo_response_is_refused(oidc_client, idp):
    """Finding 6, on the one endpoint whose body is attacker-influenced."""
    idp.userinfo_claims = {
        "sub": "alice",
        "groups": ["trmnl-admins"],
        "padding": "x" * (oidc_module.MAX_RESPONSE_BYTES + 1),
    }
    response = run_flow(oidc_client, idp)
    assert response.headers["location"] == "/?login_error=oidc_provider"
    assert oidc_client.get("/status").status_code == 401


@pytest.mark.parametrize("declare_length", [True, False])
def test_the_body_cap_holds_whatever_content_length_claims(declare_length):
    """Finding 6. `Content-Length` is a claim, not a fact, so the stream is capped too."""
    import httpx

    oversized = b"y" * (oidc_module.MAX_RESPONSE_BYTES + 4096)

    def handler(request):
        headers = {"content-type": "application/json"}
        if not declare_length:
            # Chunked: no Content-Length for the early check to catch.
            return httpx.Response(
                200, headers=headers, content=iter([oversized])
            )
        return httpx.Response(200, headers=headers, content=oversized)

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport) as http:
        request = http.build_request("GET", "https://idp.example/userinfo")
        with pytest.raises(oidc_module.OidcError) as excinfo:
            oidc_module._read_capped(http, request, "userinfo")
    assert "cap" in str(excinfo.value)


def test_a_normal_sized_body_is_unaffected(oidc_client, idp):
    """The cap has two orders of magnitude of headroom over a real provider."""
    assert run_flow(oidc_client, idp).headers["location"] == "/auth/oidc/complete"


# --- 7: PKCE support is negotiated, never assumed --------------------------


class NoPkceIdp(FakeIdp):
    """A provider that issues the code without checking the challenge.

    Exactly what an IdP with PKCE switched off does, and — this is the finding
    — completely indistinguishable from a compliant one at the callback, since
    a successful login looks the same either way.
    """

    def authorize(self, authorization_url: str, *, sub: str = "alice") -> str:
        from urllib.parse import parse_qs

        params = {
            k: v[0]
            for k, v in parse_qs(urlsplit(authorization_url).query).items()
        }
        code = "code-nopkce"
        self._codes[code] = {
            "challenge": None,
            "nonce": params.get("nonce"),
            "redirect_uri": params.get("redirect_uri"),
            "sub": sub,
        }
        return f"{params['redirect_uri']}?code={code}&state={params.get('state', '')}"


@pytest.mark.parametrize(
    "methods,why",
    [
        (["plain"], "the original PoC D: plain only, S256 never offered"),
        ([], "an empty list"),
        (None, "the key absent altogether"),
        (["S512"], "a method this server does not implement"),
    ],
)
def test_a_provider_that_cannot_prove_pkce_is_refused(
    client, tmp_path, methods, why
):
    """Finding 7, inverted PoC D. The downgrade is silent, so negotiate."""
    configure_oidc(tmp_path)
    document = {
        "issuer": OIDC_ISSUER,
        "authorization_endpoint": f"{OIDC_ISSUER}/authorize",
        "token_endpoint": f"{OIDC_ISSUER}/token",
        "userinfo_endpoint": f"{OIDC_ISSUER}/userinfo",
    }
    if methods is not None:
        document["code_challenge_methods_supported"] = methods
    install_idp(NoPkceIdp(discovery_document=document))
    login = client.get("/auth/oidc/login", follow_redirects=False)
    assert login.headers["location"] == "/?login_error=oidc_provider", why


def test_s256_is_selected_even_when_plain_is_also_offered(client, tmp_path):
    """authentik advertises both. `plain` puts the verifier in the request."""
    from urllib.parse import parse_qs

    configure_oidc(tmp_path)
    both = FakeIdp(discovery_document={
        "issuer": OIDC_ISSUER,
        "authorization_endpoint": f"{OIDC_ISSUER}/authorize",
        "token_endpoint": f"{OIDC_ISSUER}/token",
        "userinfo_endpoint": f"{OIDC_ISSUER}/userinfo",
        "code_challenge_methods_supported": ["plain", "S256"],
    })
    install_idp(both)
    login = client.get("/auth/oidc/login", follow_redirects=False)
    params = parse_qs(urlsplit(login.headers["location"]).query)
    assert params["code_challenge_method"] == ["S256"]
    # And the verifier itself is nowhere in the authorization request.
    assert "code_verifier" not in params
    assert run_flow(client, both).headers["location"] == "/auth/oidc/complete"
