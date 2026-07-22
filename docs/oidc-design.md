# Design: native OIDC login for BYOS

**Status:** implemented (phases 1-5); phase 6 (upstream PR) pending ·
**Target:** `usetrmnl/byos_fastapi` · **Written** 2026-07-22 ·
**Updated** 2026-07-22

## Why

Every BYOS implementation in the [feature matrix][matrix] ships a dashboard,
and none of them ship authentication. The assumption is a trusted LAN. That
assumption breaks the moment anyone exposes their server — and people do,
because a panel that only works at home is half a product.

Today this fork gates its control plane on a shared secret pasted into a
login overlay. That works, but it is one secret for everyone, it cannot say
*who* changed a playlist, and it means a second login for operators who
already run an identity provider.

Native OIDC fixes all three, and it is the feature that lets a BYOS server be
exposed to the internet without a reverse-proxy auth layer bolted in front.

## The core idea: OIDC is just another way to mint the existing session

`routes/auth.py` already owns everything hard about sessions: an HMAC-signed
cookie (`mint_session` / `_valid_session_value`), `HttpOnly` + `SameSite=Strict`,
a `Secure` flag derived from the base URL, TTL, origin-pinned CSRF checks,
mint rate-limiting, and the property that rotating the signing secret
invalidates every session.

**OIDC does not replace any of that.** It adds one more path that ends in
`mint_session(...)`. Everything downstream is unchanged, which is what keeps
this small and reviewable.

```
shared-secret login ─┐
                     ├─→ mint_session() → trmnl_ui cookie → require_ui_session()
OIDC code flow ──────┘
```

Both paths stay available. An operator with no IdP keeps the overlay; an
operator with Authentik/Keycloak/Authelia/Pocket ID gets real SSO. Neither is
mandatory: with neither configured, `require_ui_session` stays fail-closed.

> **Implementation note.** "Neither is mandatory" did not hold as written.
> The cookie's HMAC key was derived from `TRMNL_UI_TOKEN_FILE`, so an
> OIDC-only deployment had nothing to sign a session with and answered 503 to
> every control-plane request *after a flawless code flow*.
> `Config.session_secret()` now returns the UI secret when there is one and
> the OIDC client secret otherwise. `require_ui_session` stays fail-closed —
> the predicate simply took a second input. Rotating either file invalidates
> outstanding sessions, and on an OIDC-only box the IdP also holds the key
> material; it can already mint an identity for anyone, so this is not an
> escalation, but it is why the UI secret stays preferred when both exist.

## Zero new dependencies

`httpx` is already a runtime dependency. Discovery, the token exchange and
the userinfo call are all plain HTTPS requests.

The one thing that would normally drag in a JWT/crypto library is verifying
the ID token signature. We can legitimately skip it: **OIDC Core §3.1.3.7
item 6** states that when the ID token is received directly from the token
endpoint over a TLS-protected channel, using client authentication, the
signature MAY go unverified — server-to-server TLS plus `client_secret` is
already the security boundary. Identity is then read from the `userinfo`
endpoint, which is an authenticated call in its own right.

This keeps the dependency set at **pillow, fastapi, uvicorn, httpx,
sqlalchemy** — a hard requirement for the Nix packaging downstream, and a
much easier ask upstream than "add authlib".

If a future maintainer wants strict local ID-token validation, it slots in
behind an optional extra without changing the flow.

## The split gate must generalise

This fork already separates *device* paths from *human* paths because an
ESP32 cannot complete an SSO redirect:

| Paths | Gate |
| --- | --- |
| `/api/setup`, `/api/display`, `/api/log`, `/image/*` | MAC allowlist + `Access-Token`, never a session |
| everything else | session cookie |

**OIDC changes nothing here.** Any implementation that puts an IdP in front
of `/api/*` bricks the panel — the firmware follows no redirects, and the
failure is silent: enrolment 404s or 302s and the display simply never
updates. The existing `tests/test_panel.py` route-boundary invariant already
fails the build if a control-plane route is registered under `/api/`; that
test becomes load-bearing documentation for this feature and should be
called out in the PR.

## Configuration surface

Provider-agnostic, discovery-driven, all optional:

| Variable | Meaning |
| --- | --- |
| `TRMNL_OIDC_ISSUER` | Issuer URL. `.well-known/openid-configuration` is fetched from it; presence of this var enables the feature |
| `TRMNL_OIDC_CLIENT_ID` | Client ID |
| `TRMNL_OIDC_CLIENT_SECRET_FILE` | File holding the secret. A file, not a value, so it never lands in a unit file, `/proc`, or `docker inspect` |
| `TRMNL_OIDC_SCOPES` | Default `openid profile email groups` |
| `TRMNL_OIDC_ALLOWED_GROUPS` | Optional. Comma-separated; when set, a claim must match or login is refused |
| `TRMNL_OIDC_GROUPS_CLAIM` | Default `groups`. Keycloak and Authelia differ here |
| `TRMNL_OIDC_REDIRECT_URL` | Defaults to `<TRMNL_BASE_URL>/auth/oidc/callback` |

Discovery rather than seven endpoint variables is what makes this work
across providers without per-IdP code.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /auth/oidc/login` | Builds the authorization URL, sets a short-lived signed state+PKCE cookie, 302s to the IdP |
| `GET /auth/oidc/callback` | Validates state, exchanges the code (PKCE `S256`), calls `userinfo`, checks group claims, mints the session, 302s to `/` |
| `GET /auth/session` | Extended to report which login methods are configured, so the UI renders the right thing |

The UI shows a "Sign in with <provider>" button when the issuer is
configured, the secret overlay when it is not, and both when both are.

## Security requirements (non-negotiable in review)

- **PKCE S256** on every flow, even though this is a confidential client.
- **`state` is signed and single-use**, bound to the PKCE verifier, TTL ≈ 5 min.
- **Redirect URI allowlisted** against `TRMNL_BASE_URL`; never reflect a
  caller-supplied `redirect_uri` or `next` without validating it against the
  configured origin — open-redirect is the classic bug here.
- **`nonce`** sent and checked against the ID token claim.
- **Group check fails closed** — a missing or unreadable claim denies *when
  a restriction is configured*. With `TRMNL_OIDC_ALLOWED_GROUPS` unset a
  missing claim must not deny, or Google — which has no group or role claim
  of any kind — could never be used.
- **Discovery is cached but re-fetched on failure**, and a discovery outage
  must not lock out the shared-secret path.
- **The IdP is never consulted for `/api/*`.** Assert it in tests.
- ~~Reuse `_same_origin` for CSRF on the callback.~~ **Wrong — see below.**

Eight more were added by an adversarial review of the finished branch, and
each is now an executable test in `tests/test_oidc_security.py`:

- **The ID token's claims are checked** — `iss`, `aud`, `azp`, `exp`, `iat`,
  `sub`, with two minutes of clock skew. §3.1.3.7 item 6 licenses skipping
  the *signature*; it says nothing about the rest of §3.1.3.7, and without
  those checks a token minted for another client by another issuer, expired a
  day earlier, was accepted.
- **`userinfo.sub` is bound to the ID token's `sub`** (OIDC Core §5.3.2,
  a MUST). Unbound, a mismatched or entirely empty userinfo response still
  minted a session.
- **https is required** for the issuer, the redirect URI and every discovered
  endpoint, with http permitted only to loopback. This is not a hardening
  extra: §3.1.3.7 item 6 permits skipping the signature *because* the token
  arrives over TLS, so a plaintext issuer voids the premise the zero-dependency
  design rests on.
- **PKCE is negotiated, not assumed.** `code_challenge_methods_supported` must
  advertise `S256`; a provider that ignores PKCE is otherwise indistinguishable
  from one that honours it. `plain` is never selected even when offered.
- **The device plane cannot be starved by the control plane.** Every route is
  a sync `def` sharing one 40-worker threadpool with `/api/display`, so
  `/auth/oidc/login` — unauthenticated, and doing outbound work — is rate
  limited, its outbound calls are capped at eight concurrent, and discovery is
  single-flight.
- **The OIDC paths do not share the shared-secret login's failure budget.**
  A hundred free cross-site GETs on the callback used to exhaust it and lock
  every operator out of `POST /auth/session`.
- **Every IdP response body is capped** at 256 KiB.
- **The single-use state ledger has no flush primitive.** It evicts FIFO; a
  ledger that can be emptied is a ledger that can be bypassed.
- **Nothing the provider chose reaches the log unbounded or unescaped**, and
  no token, code or secret reaches it at all.

## Decisions taken during implementation

Five things in the sketch above turned out to be wrong or underspecified.
Each is a comment in the code as well, because each looks like a mistake
without the reason.

1. **`_same_origin()` must NOT guard the callback.** The callback is a
   cross-site-initiated top-level navigation, so a real browser sends
   `Sec-Fetch-Site: cross-site` — which `_same_origin` returns `False` for —
   while `curl` sends neither `Sec-Fetch-Site` nor `Origin`, which it returns
   `True` for. Applying it would refuse every genuine login and admit every
   scripted one. The callback's CSRF defence is the signed, single-use,
   verifier-bound `state` cookie, which is what actually binds the response
   to *this* browser's attempt. `require_ui_session` is unaffected: `GET` is
   in `_SAFE_METHODS`.

2. **The state cookie is `SameSite=Lax`, not `Strict`.** A `Strict` cookie is
   not sent on the IdP's return navigation at all, so a Strict state cookie
   breaks every real login while leaving scripted requests untouched. It is
   scoped to `path=/auth/oidc` with a 300 s max-age, and it is the *only*
   relaxed cookie — the session cookie stays `Strict`, asserted in tests.

3. **The callback 302s to a same-origin interstitial, not to `/`.** The
   freshly-minted `SameSite=Strict` session cookie is not carried on a
   redirect chain that began cross-site, so a direct 302 to `/` renders a
   dashboard that reports itself logged out until the operator reloads — a
   bug indistinguishable from flakiness. `/auth/oidc/complete` navigates to
   `/` itself, and that hop is same-site-initiated. It also keeps the
   authorization code out of the address bar and history.

4. **`/auth/oidc/login` takes no parameters at all.** No `next`, no
   `redirect_uri`, no `return_to`. The redirect URI is derived from
   `TRMNL_BASE_URL`; the destination is always `/`. That is the whole
   open-redirect mitigation, and it is free because a single-page dashboard
   has nowhere else to land. A `TRMNL_OIDC_REDIRECT_URL` outside `base_url`
   disables the feature rather than being honoured, and OIDC refuses to
   enable at all without a `base_url` — with no fixed origin there is nothing
   to build a redirect from and nothing to allowlist it against.

5. **Groups are read from `userinfo` first and the ID token second.**
   Userinfo is the authoritative source and the one Authelia explicitly
   steers clients toward; the ID token covers Keycloak's `microprofile-jwt`
   and Authelia claims policies, which land groups there and nowhere else.
   First non-absent source wins and the two are never merged, so a
   deliberately narrowed userinfo response is not widened by a staler ID
   token. Relatedly, "no claim at all" and "no matching group" are distinct
   errors: the same symptom with completely different fixes, and collapsing
   them is what makes a misconfigured Keycloak take an afternoon.

Two smaller ones:

* **Token-endpoint authentication is read from discovery**, preferring
  `client_secret_basic` and falling back to `client_secret_post`, because
  Authelia enforces the registered method and a hardcoded
  `client_secret_post` simply fails there.
* **A userinfo response with `Content-Type: application/jwt` is refused.**
  Consuming it would mean parsing a signed assertion and ignoring the
  signature, which is *not* what §3.1.3.7 item 6 licenses — that covers the
  token endpoint, not this one. Keycloak and Authelia can both be configured
  to do it; the README says not to.

## Phases

1. ✅ **Discovery + config** — parse `.well-known`, validate config at
   startup, log clearly when OIDC is off. Tests with a stubbed discovery
   document.
2. ✅ **Code flow** — login/callback, PKCE, state, nonce, session mint. Tests
   against a fake IdP served by FastAPI's own test client; no network.
3. ✅ **Authorization** — group claim matching, fail-closed. Tests for missing
   claim, wrong group, multiple groups.
4. ✅ **UI** — provider button, method reporting, error surfaces that say what
   went wrong ("your account is not in an allowed group") rather than "login
   failed".
5. ✅ **Docs** — `README` section plus a copy-paste config block per provider:
   Authentik, Keycloak, Authelia, Pocket ID, Google.
6. **Upstream PR** — one feature, one branch, docs and tests included.

Phases 1–3 are independently mergeable and each leaves the tree working.

## Risks

- **Provider drift.** Claim names vary (`groups` vs `roles` vs
  `resource_access`). Mitigated by making the claim name configurable and
  documenting the known ones.
- **Skipping ID-token signature verification** is spec-permitted but will be
  questioned in review. The PR should quote §3.1.3.7 and note the optional
  strict mode.
- **Lockout.** An operator who configures OIDC badly and disables the shared
  secret cannot reach the UI. Keep both paths independently usable and say so
  in the docs.
- **Scope creep.** Multi-user roles, per-user audit and device ownership are
  natural follow-ups and should stay out of the first PR.

[matrix]: https://docs.trmnl.com/go/diy/byos
