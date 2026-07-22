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

# pytest's conventions collide with five pylint defaults, none of which is
# reporting a defect here:
#   unused-argument / redefined-outer-name — a fixture is requested by naming
#     it as a parameter, and a test that only needs the fixture's side effect
#     (an app built, OIDC configured) never references the name.
#   protected-access / import-outside-toplevel — these are white-box tests of
#     module-global state, and several modules must be imported *after* the
#     app is built to observe what building it did.
#   missing-function-docstring — the test names are the documentation; the
#     ones with something extra to say have a docstring already.
# pylint: disable=unused-argument,redefined-outer-name,protected-access
# pylint: disable=import-outside-toplevel,missing-function-docstring

import threading
import time
from contextlib import contextmanager
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


# anyio's default threadpool is 40 workers and every route in this app is a
# sync `def`, so a flood larger than that is what turns "slow" into "the panel
# stopped updating". 64 is comfortably over the line.
FLOOD_THREADS = 64


def _device_plane_under_flood(client, label):
    """Poll `/api/display` while `FLOOD_THREADS` threads hammer the login route.

    The discovery caches are neutralised for the duration. That is not
    stacking the deck, it is removing the thing that would otherwise be
    measured instead of the guard: with the document cached, the second and
    every later login does no outbound work at all and the flood costs
    nothing. The case that has to hold is the one where the cache is not
    helping — a cold start, an hourly TTL expiry, or (the realistic one) an
    IdP that is down, whose failure backoff has elapsed, with every browser on
    the network retrying at once.
    """
    stop = threading.Event()
    hits = [0]
    counter_lock = threading.Lock()

    def flood():
        while not stop.is_set():
            try:
                client.get("/auth/oidc/login", follow_redirects=False)
            except Exception:  # pragma: no cover - the flood is best-effort
                pass
            with counter_lock:
                hits[0] += 1

    threads = [threading.Thread(target=flood, daemon=True) for _ in range(FLOOD_THREADS)]
    for thread in threads:
        thread.start()
    try:
        # Let the flood fill the threadpool before the first measurement, or
        # the numbers describe a server that is not under load yet.
        time.sleep(0.5)
        latencies = []
        statuses = []
        for _ in range(20):
            started = time.monotonic()
            response = client.get(
                "/api/display", headers={"ID": MAC, "Access-Token": TOKEN}
            )
            latencies.append(time.monotonic() - started)
            statuses.append(response.status_code)
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=30)

    print(
        f"{label}: {hits[0]} login requests, /api/display median "
        f"{median(latencies) * 1000:.1f} ms, worst {max(latencies) * 1000:.1f} ms, "
        f"statuses {sorted(set(statuses))}"
    )
    return statuses, latencies


def test_a_login_flood_does_not_stall_the_device_plane(
    oidc_client, tmp_path, monkeypatch
):
    """Finding 1, the invariant that matters: `/api/display` keeps working.

    An unauthenticated flood of `/auth/oidc/login` against an IdP that stalls
    a full second per call, while the panel's own endpoint is polled
    throughout. Every device request must succeed, and none may wait anywhere
    near the IdP's stall time.
    """
    monkeypatch.setattr(oidc_module, "DISCOVERY_TTL", 0.0)
    monkeypatch.setattr(oidc_module, "DISCOVERY_RETRY_BACKOFF", 0.0)
    install_idp(SlowIdp(delay=1.0))
    oidc_routes.LOGIN_BUDGET.reset()
    statuses, latencies = _device_plane_under_flood(oidc_client, "rate-limited flood")
    assert set(statuses) == {200}, "the panel was refused while the flood ran"
    assert max(latencies) < 1.0, f"worst device latency {max(latencies):.3f}s"


def test_a_distributed_login_flood_does_not_stall_the_device_plane(
    oidc_client, tmp_path, monkeypatch
):
    """Finding 1, with the per-source rate limiter taken out of the picture.

    A botnet does not share a source address, so the rate limiter sees one
    request per client and lets every one of them through. What has to hold
    then is `oidc.OUTBOUND_LIMIT`: however many callers arrive, at most eight
    threadpool workers are ever inside an IdP call, and the other thirty-two
    are the panel's.
    """
    monkeypatch.setattr(oidc_module, "DISCOVERY_TTL", 0.0)
    monkeypatch.setattr(oidc_module, "DISCOVERY_RETRY_BACKOFF", 0.0)
    install_idp(SlowIdp(delay=1.0))
    budget = oidc_routes.LOGIN_BUDGET
    original = (budget.per_source_limit, budget.global_limit)
    budget.reset()
    budget.per_source_limit = 10 ** 9
    budget.global_limit = 10 ** 9
    try:
        statuses, latencies = _device_plane_under_flood(
            oidc_client, "unthrottled distributed flood"
        )
    finally:
        budget.per_source_limit, budget.global_limit = original
        budget.reset()
    assert set(statuses) == {200}, "the panel was refused while the flood ran"
    assert max(latencies) < 1.0, f"worst device latency {max(latencies):.3f}s"


@contextmanager
def _with_login_limits(per_source, global_limit):
    """Temporarily shrink LOGIN_BUDGET so its *mechanism* can be exercised.

    The production limits are four figures on purpose (below), which is far too
    many requests to push through a TestClient just to watch a counter trip.
    Shrinking them tests the counter; the two tests after this one test the
    numbers.
    """
    budget = oidc_routes.LOGIN_BUDGET
    original = (budget.per_source_limit, budget.global_limit)
    budget.reset()
    budget.per_source_limit = per_source
    budget.global_limit = global_limit
    try:
        yield budget
    finally:
        budget.per_source_limit, budget.global_limit = original
        budget.reset()


def test_the_login_endpoint_is_still_rate_limited(oidc_client, idp):
    """Finding 1. `/auth/oidc/login` counted nothing at all before.

    The budget did not go away when it was resized — deleting it is the trap
    (see `test_the_login_budget_cannot_fill_the_state_ledger`). It still
    refuses, it still refuses by redirecting rather than queueing, and it still
    refuses before a state is minted.
    """
    with _with_login_limits(8, 1000):
        codes = [
            oidc_client.get("/auth/oidc/login", follow_redirects=False)
            for _ in range(13)
        ]
    assert all(r.status_code == 302 for r in codes)
    assert all("/?login_error=" not in r.headers["location"] for r in codes[:8])
    assert {r.headers["location"] for r in codes[8:]} == {
        "/?login_error=oidc_throttled"
    }
    # A throttled login mints no state, which is what makes "ledger entries <=
    # logins allowed" true. If it minted one anyway, the budget would bound
    # nothing. `_fail()` still *clears* the cookie, so the check is that no
    # value was handed out, not that the header is absent.
    for refused in codes[8:]:
        header = next(
            (h for h in refused.headers.get_list("set-cookie")
             if h.startswith(f"{oidc_routes.STATE_COOKIE}=")),
            f"{oidc_routes.STATE_COOKIE}=",
        )
        value = header.split(";")[0].split("=", 1)[1].strip('"')
        assert value == "", f"a throttled login still minted a state: {header}"


# How much anonymous traffic `/auth/oidc/login` might plausibly see from
# something that is not an attack: a crawler that found the link, a link-
# preview fetcher, an uptime probe, every browser in the house retrying at once
# after the IdP came back. A thousand hits in one window is already an absurd
# over-estimate of all of those put together — and it is 33x the limit this
# endpoint used to have.
PLAUSIBLE_ANONYMOUS_FLOOD = 1000


def test_a_plausible_anonymous_flood_does_not_deny_a_real_login(oidc_client, idp):
    """Finding N1. The lockout, which was the cure being worse than the disease.

    `LOGIN_BUDGET` was 30 per source per five minutes. Behind a tunnelling edge
    — Pangolin/Newt, and `RateBudget`'s own docstring says exactly this — every
    request arrives from one address, so "per source" is one bucket for
    everybody and thirty anonymous GETs denied SSO to every operator for five
    minutes. No credential needed, no cookie, nothing to guess.

    Note that the flood and the legitimate login here share a source address,
    because that *is* the deployment topology. The whole flood plus a complete
    round trip has to fit inside the budget with room to spare.
    """
    oidc_routes.LOGIN_BUDGET.reset()
    auth_module.MINT_BUDGET.reset()
    for _ in range(PLAUSIBLE_ANONYMOUS_FLOOD):
        response = oidc_client.get("/auth/oidc/login", follow_redirects=False)
        assert response.status_code == 302
    oidc_client.cookies.clear()

    # ...and an operator arriving behind all of that still reaches the IdP,
    # rather than being bounced to `/?login_error=oidc_throttled`.
    started = oidc_client.get("/auth/oidc/login", follow_redirects=False)
    assert started.headers["location"].startswith(OIDC_ISSUER), (
        f"{PLAUSIBLE_ANONYMOUS_FLOOD} anonymous GETs locked a real operator "
        f"out of SSO: {started.headers['location']} (tracked: "
        f"{oidc_routes.LOGIN_BUDGET.tracked('testclient')} of "
        f"{oidc_routes.LOGIN_BUDGET.per_source_limit})"
    )
    # ...and completes the round trip and holds a session at the end of it.
    assert run_flow(oidc_client, idp).headers["location"] == "/auth/oidc/complete"
    assert oidc_client.get("/status").status_code == 200
    # With margin left, rather than landing exactly on the line.
    assert PLAUSIBLE_ANONYMOUS_FLOOD * 2 < oidc_routes.LOGIN_PER_SOURCE_LIMIT


def test_the_login_budget_cannot_fill_the_state_ledger(oidc_client, idp, caplog):
    """Finding N1, the other half — why the budget could not simply be deleted.

    `_StateLedger` bounds itself at `_USED_STATE_MAX` entries and evicts FIFO,
    and its docstring rests the safety of that on the login limiter: fill the
    ledger inside one STATE_TTL and it starts dropping *live* states, which is
    exactly the replay the ledger exists to refuse. So the two are interlocked,
    and raising one limit without the other reopens the hole.

    The arithmetic, asserted rather than asserted-to:

      * a ledger entry needs a distinct state that `_unpack_state()` accepted,
        so it needs a signature only `/auth/oidc/login` makes;
      * a state is accepted only within STATE_TTL of being minted, and its
        entry is dropped STATE_TTL after being claimed, so every live entry was
        minted within the last 2 * STATE_TTL;
      * the budget's window IS STATE_TTL, so at most LOGIN_GLOBAL_LIMIT states
        exist per STATE_TTL and at most 2 * LOGIN_GLOBAL_LIMIT entries can be
        live at once.
    """
    budget = oidc_routes.LOGIN_BUDGET
    assert budget.window <= oidc_routes.STATE_TTL, (
        "a window longer than STATE_TTL breaks the one-to-one step in the "
        "derivation: more states could be minted per TTL than the limit says"
    )
    worst_case = 2 * budget.global_limit
    assert worst_case < oidc_routes._USED_STATE_MAX, (
        f"{worst_case} live states are reachable against a ledger bound of "
        f"{oidc_routes._USED_STATE_MAX}"
    )
    # Derived, not coincidental: raising the limiter raises the ledger with it.
    assert oidc_routes._USED_STATE_MAX == 4 * budget.global_limit

    # Now drive a real ledger to that worst case and check the claim holds: no
    # eviction, and the very first state is still remembered as spent.
    ledger = oidc_routes._StateLedger()
    caplog.clear()
    with caplog.at_level("WARNING"):
        for i in range(worst_case):
            assert ledger.claim(f"state-{i}") is True
    assert len(ledger) == worst_case
    assert not [r for r in caplog.records if "evicting an unexpired state" in r.message]
    assert ledger.claim("state-0") is False, "a live state was evicted and is replayable"
    assert ledger.claim(f"state-{worst_case - 1}") is False

    # And the bound is real rather than decorative: one entry past it *does*
    # evict, which is the thing the arithmetic above keeps out of reach.
    small = oidc_routes._StateLedger(maximum=4)
    for i in range(5):
        assert small.claim(f"s{i}") is True
    assert small.claim("s0") is True, "the FIFO bound is not evicting at all"


def test_a_login_flood_does_not_lock_out_the_secret_login(oidc_client, idp):
    """Finding 1 + 2. Throttling the SSO path must cost the other path nothing.

    Even with the OIDC budget fully spent — forced here, since the real limit
    is too high to reach by hand — the shared-secret form is untouched.
    """
    auth_module.MINT_BUDGET.reset()
    with _with_login_limits(5, 5):
        for _ in range(25):
            oidc_client.get("/auth/oidc/login", follow_redirects=False)
        assert oidc_client.get(
            "/auth/oidc/login", follow_redirects=False
        ).headers["location"] == "/?login_error=oidc_throttled"
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


# --- 8: the single-use state ledger has no flush primitive -----------------


def test_the_state_ledger_cannot_be_flushed_by_filling_it(oidc_client, idp):
    """Finding 8. A flush primitive on a single-use ledger *is* the bypass.

    The old ledger cleared itself wholesale on reaching its bound, so "single
    use" held only until an attacker had redeemed enough states to trip the
    flush — at which point the state they were holding was forgotten and
    replayable. Eviction is now FIFO, so the state that just went in is the
    last one to leave, not the first.
    """
    ledger = oidc_routes._StateLedger(maximum=64)
    states = [f"state-{i}" for i in range(100)]
    for state in states:
        assert ledger.claim(state) is True

    # Overflowing the bound by 36 must cost 36 entries, not all 64. Under the
    # old wholesale clear it cost every entry the moment the bound was hit, so
    # a state redeemed one request earlier was replayable.
    still_remembered = [s for s in states[-63:] if ledger.claim(s) is False]
    assert len(still_remembered) == 63, (
        f"only {len(still_remembered)} of the 63 most recent states survived; "
        "the ledger flushed rather than evicted"
    )
    assert len(ledger) <= 64


def test_production_exposes_no_way_to_empty_the_ledger(oidc_client):
    """Finding 8. The flush the test suite used to call is gone entirely."""
    assert not hasattr(oidc_routes, "reset_state_store")
    assert not hasattr(oidc_routes, "_used_states")
    ledger = oidc_routes._state_ledger
    assert not [
        name
        for name in dir(ledger)
        if not name.startswith("_") and name in ("clear", "reset", "flush", "drop")
    ]


def test_a_state_is_still_single_use_end_to_end(oidc_client, idp):
    """The property the ledger exists for, through the real routes."""
    login = oidc_client.get("/auth/oidc/login", follow_redirects=False)
    callback = idp.authorize(login.headers["location"])
    split = urlsplit(callback)
    first = oidc_client.get(f"{split.path}?{split.query}", follow_redirects=False)
    assert first.headers["location"] == "/auth/oidc/complete"
    second = oidc_client.get(f"{split.path}?{split.query}", follow_redirects=False)
    assert second.headers["location"] == "/?login_error=oidc_state"


# --- 9: nothing the provider says reaches the log unbounded or unescaped ---


def test_redact_escapes_control_characters_and_truncates():
    """Finding 9. A log file an unauthenticated caller can write lines into."""
    injected = "alice\nJan 01 00:00:00 trmnl: ERROR forged line"
    rendered = oidc_module.redact(injected)
    assert "\n" not in rendered, "a newline survived into the log line"
    assert "\r" not in rendered
    assert "\\n" in rendered

    huge = "x" * 10_000
    rendered = oidc_module.redact(huge)
    assert len(rendered) < 300
    assert "+9880 more" in rendered


def test_the_callback_error_parameter_is_bounded_and_escaped(
    oidc_client, caplog
):
    """`?error=` is chosen by whoever sent the browser here, IdP or not."""
    import logging

    payload = "denied\n" + "A" * 20_000
    with caplog.at_level(logging.WARNING):
        oidc_client.get(
            "/auth/oidc/callback",
            params={"error": payload, "error_description": "B" * 20_000},
            follow_redirects=False,
        )
    records = [r for r in caplog.records if "refused the authorization" in r.message]
    assert records, "the refusal was not logged at all"
    rendered = records[0].getMessage()
    assert len(rendered) < 1000, f"{len(rendered)} characters of provider text"
    assert "\n" not in rendered


def test_a_hostile_subject_label_is_bounded_and_escaped(oidc_client, idp, caplog):
    """Finding 9. The success line quotes a name the provider chose."""
    import logging

    idp.userinfo_claims = {
        "sub": "alice",
        "preferred_username": "alice\nforged: " + "Z" * 5_000,
        "groups": ["trmnl-admins"],
    }
    with caplog.at_level(logging.INFO):
        assert run_flow(oidc_client, idp).headers[
            "location"
        ] == "/auth/oidc/complete"
    records = [r for r in caplog.records if "OIDC login accepted" in r.message]
    assert records
    rendered = records[0].getMessage()
    assert "\n" not in rendered
    assert len(rendered) < 400


def test_a_hostile_group_list_is_bounded(oidc_client, idp, caplog):
    """A provider can send a thousand groups; the log line must not grow with it."""
    import logging

    idp.groups = [f"group-{i}" for i in range(2000)]
    with caplog.at_level(logging.INFO):
        run_flow(oidc_client, idp)
    records = [r for r in caplog.records if "OIDC login accepted" in r.message]
    assert records
    assert len(records[0].getMessage()) < 600


def test_no_credential_ever_reaches_the_log(oidc_client, idp, caplog):
    """Finding 9's other half: tokens, codes and secrets are not logged at all."""
    import logging

    from conftest import OIDC_CLIENT_SECRET

    with caplog.at_level(logging.DEBUG):
        login = oidc_client.get("/auth/oidc/login", follow_redirects=False)
        callback = idp.authorize(login.headers["location"])
        split = urlsplit(callback)
        oidc_client.get(f"{split.path}?{split.query}", follow_redirects=False)

    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert OIDC_CLIENT_SECRET not in logged
    for code in idp._codes:
        assert code not in logged
    for access_token in idp._access_tokens:
        assert access_token not in logged
    # The state and PKCE verifier are credentials for this flow too.
    assert "code_verifier" not in logged
