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
