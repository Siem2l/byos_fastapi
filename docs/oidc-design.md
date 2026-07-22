# Design: native OIDC login for BYOS

**Status:** proposal · **Target:** `usetrmnl/byos_fastapi` (developed in
`Siem2l/byos_fastapi`) · **Written** 2026-07-22

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
- **Group check fails closed** — a missing or unreadable claim denies.
- **Discovery is cached but re-fetched on failure**, and a discovery outage
  must not lock out the shared-secret path.
- **The IdP is never consulted for `/api/*`.** Assert it in tests.
- Reuse `_same_origin` for CSRF on the callback.

## Phases

1. **Discovery + config** — parse `.well-known`, validate config at startup,
   log clearly when OIDC is off. Tests with a stubbed discovery document.
2. **Code flow** — login/callback, PKCE, state, nonce, session mint. Tests
   against a fake IdP served by FastAPI's own test client; no network.
3. **Authorization** — group claim matching, fail-closed. Tests for missing
   claim, wrong group, multiple groups.
4. **UI** — provider button, method reporting, error surfaces that say what
   went wrong ("your account is not in an allowed group") rather than "login
   failed".
5. **Docs** — `README` section plus a copy-paste config block per provider:
   Authentik, Keycloak, Authelia, Pocket ID, Google.
6. **Upstream PR** — one feature, one branch, docs and tests included.

Phases 1–3 are independently mergeable and each leaves the tree working.

## Downstream: the NixOS module

Once merged, `services.apis-mellifera.trmnl` gains `oidc.{enable, issuer,
clientId, clientSecretFile, allowedGroups}`. The repo's `expose` framework
already has `auth = "native-oidc"` with three services using it
(`romm`, `miniflux`, `hivemind`), so the Authentik application and client
secret are generated by the existing blueprint machinery rather than by hand.

At that point `pangolinSsoAtEdge` can go **false** for this service: the app
authenticates users itself, so the edge no longer needs to, and the double
login disappears. The device bypass rules stay exactly as they are.

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
