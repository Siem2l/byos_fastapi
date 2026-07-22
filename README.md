# BYOS TRMNL Server in FastAPI

This is a self-hosted FastAPI backend that emulates the [TRMNL](https://usetrmnl.com/) cloud so e-paper devices can fetch fresh images and metadata from your local network.

![Main Screen](docs/main.png)
![Device Details](docs/devices.png)
![Server Logs](docs/logs.png)
![Playlist Management](docs/playlist.png)

It is loosely based on [a Flask implementation by @ohAnd](https://github.com/ohAnd/trmnlServer), rewritten (nearly) from scratch to use FastAPI, async I/O, and a plugin-driven architecture for rendering various charts and images, prioritizing greyscale output suitable for later firmware versions but allowing you to force 1-bit BMP for legacy devices on a per-item basis

The server maintains device/playlists in SQLite, renders plugin-driven charts/photos into BMP/PNG assets, and exposes `/api/display` plus legacy-compatible endpoints expected by the firmware.

It also tries too hard to do image color grading and dithering to improve the appearance of photos and complex graphics on e-ink panels, which is a rabbit hole I fell into.

## Non-Goals

- **Full feature parity with the official TRMNL cloud** – this is a lightweight server for personal use, not a 1:1 clone of the official backend.
- **Multi-user support** – the dashboard authenticates *operators* (see **Authentication**: a shared secret, OIDC, or both), but there is one control plane and one set of permissions. Per-user roles, audit trails and device ownership are out of scope.
- **Extensive plugin library** – only a few example plugins are provided; users are encouraged to write their own.
- **Web dashboard for management** – a minimal static UI is included for previewing plugin outputs and doing basic playlist management, but no full-featured admin panel.
- **Browser-based rendering** – all image generation is done server-side using Python libraries to minimize system requirements.

## Highlights

- **FastAPI core** – `trmnl_server/main.py` hosts the HTTP API, static assets under `/web`, and middleware-level request logging.
- **Plugin rendering pipeline** – classes in `plugins/` generate images (always 1-bit and 2-bit) using Pillow, httpx, pandas, etc. Just output an image and the server handles (configurable) dithering, grading, and persistence.
- **Device + playlist persistence** – SQLAlchemy models in `models.py` keep per-device rotation state, playlists, logs, and battery samples in `var/db/trmnl.db`.
- **Autodiscovered plugin scheduler** – background workers keep assets fresh; see **Plugins & registry** for discovery rules and toggles.
- **Firmware compatibility** – `/api/display` always returns a single `image_url` plus a changing `filename` token so ESP32-based firmware knows when to refresh.
- **Batteries-included tooling** – `Makefile` wraps `make serve` (launch FastAPI via `python -m trmnl_server`) and `make test` (pytest). Plugins can be previewed via helper scripts under the repo root.
- **Color grading + dithering** – "color" grading and multiple dithering algorithms are available to improve image quality on e-ink panels, and you can force specific playlist entries to use 1-bit BMP output if needed.

## Deployment

I am deploying this with `kata`, a Docker-based service manager I wrote, but any method that can run a FastAPI app will work.

## Running Locally

```bash
git clone https://github.com/rcarmo/python-fastapi-trmnl-server.git
cd trmnlServer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
make serve
```

The server logs which port it binds to (default `SERVER_PORT=4567`). Point your TRMNL device at `http://<server_ip>:<port>`.

Useful commands:

- `make serve` – start FastAPI using the current working directory as the runtime root.
- `SERVER_PORT=8081 make serve` – override port for quick tests.
- `make serve ARGS=/path/to/workdir` – run the server against a different working directory (`var/` contents plus SSL/generated assets) without touching your source tree.
- `python -m trmnl_server --list-plugins` – print the plugin registry (names + defaults) and exit.
- `python -m trmnl_server --run-plugin WeatherPlugin --plugin-output /tmp --plugin-arg image_root=/path` – run a single plugin once for debugging with optional keyword arguments.
- `make test` – run `pytest` (`tests/test_rotation.py`, `tests/test_plugins.py`, `tests/test_weather.py`).

## Configuration

All settings come from environment variables:

- `SERVER_PORT`, `ENABLE_SSL` – networking defaults (4567/False out of the box, set `ENABLE_SSL=true` when you need TLS).
- `IMAGE_PATH`, `REFRESH_TIME`, `DITHERING_MODE` – rendering and dithering behaviour.
- `PHOTO_GRADING_ENABLED` – enable/disable photographic grading for image-heavy plugins (default: true).
- `EINK_TONE_POINTS`, `EINK_TONE_GAMMA` – optional grayscale response compensation points/gamma for panel-space quantization.
- `BATTERY_MAX_VOLTAGE`, `BATTERY_MIN_VOLTAGE`, `TIME_ZONE` – telemetry scaling.
- `SETUP_API_KEY`, `SETUP_FRIENDLY_ID`, `SETUP_MESSAGE` – `/api/setup` payload fields.
- `ASSETS_ROOT`, `STATIC_ROOT`, `GENERATED_ROOT` – relative directories (inside the working dir) for dashboard assets and generated BMP/PNG output (defaults: `web`, `web`, and `var/generated`).
- `CALIBRATION_PLUGIN_ENABLED` – set to `false` to remove calibration plugins from the registry and skip generating calibration assets.

Whenever a setting is changed via the `/settings/*` endpoints, the new value is written to SQLite (table `config_entries`). On startup, `config.py` loads environment variables first (highest precedence) and then applies any persisted entries that are not overridden by the environment, so API-driven tweaks survive restarts without fighting `SERVER_PORT=...` overrides in your shell.

Not all settings are exposed in the Web UI (yet); refer to `config.py` for the full list. The `TRMNL_*` variables that gate the panel and the dashboard are documented under **Authentication** below.

Runtime artefacts live under `var/` inside your chosen working directory:

- `var/db/trmnl.db` – SQLite database plus future state.
- `var/logs/` – reserved for future log sinks.
- `var/generated/` – plugin BMP/PNG output served via `/generated/*`.
- `var/ssl/` – self-signed certs generated automatically if SSL is enabled.

FastAPI creates these directories during startup if they are missing, and `.gitignore` keeps `var/` out of version control.

## Authentication

Two ways to reach the control plane (`/rotation`, `/playlists`, `/devices`,
`/status`, `/server/*`), and both end in the same HMAC-signed, HttpOnly,
`SameSite=Strict` session cookie:

```
shared-secret login ─┐
                     ├─→ session cookie → control plane
OIDC code flow ──────┘
```

Both are optional and independently usable. **With neither configured the
control plane answers 503 to everything** — it fails closed rather than open.
The one thing the two do not share is how long the cookie lives: 30 days from
the shared secret, 8 hours from OIDC, because only the latter has a provider
behind it that can revoke access without telling this server. See
`TRMNL_OIDC_SESSION_TTL` below.

**The device surface is never touched by either.** `/api/setup`,
`/api/display`, `/api/log`, `/api/logs` and `/image/*` take a MAC allowlist
plus an `Access-Token` header and nothing else, because the panel is an ESP32
that follows no redirects and cannot complete an SSO round trip. Putting an
identity provider in front of `/api/*` bricks the panel, and the failure is
silent: enrolment 302s and the display simply never updates.
`main.py::_assert_route_invariants()` refuses to build the app if a
control-plane route is ever registered under `/api/`.

### Shared secret

```bash
TRMNL_UI_TOKEN_FILE=/run/secrets/trmnl-ui-token
```

A file, not a value. Rotating it invalidates every outstanding session at the
next request, with no restart and no revocation list — the cookie's signing
key is derived from it.

### OIDC

Provider-agnostic and discovery-driven: every endpoint comes out of
`<issuer>/.well-known/openid-configuration`, so there is no per-provider code.
Setting `TRMNL_OIDC_ISSUER` enables the feature.

| Variable | Meaning |
| --- | --- |
| `TRMNL_OIDC_ISSUER` | Issuer URL. Presence of this variable enables OIDC. |
| `TRMNL_OIDC_CLIENT_ID` | Client ID. |
| `TRMNL_OIDC_CLIENT_SECRET_FILE` | File holding the client secret — a file, so it never lands in a unit file, `/proc`, or `docker inspect`. |
| `TRMNL_OIDC_SCOPES` | Default `openid profile email groups`. |
| `TRMNL_OIDC_ALLOWED_GROUPS` | Optional, comma-separated. When set, a group claim must match or the login is refused. |
| `TRMNL_OIDC_GROUPS_CLAIM` | Default `groups`. A dotted value such as `resource_access.trmnl.roles` is tried as a flat key first and only then traversed as a path. |
| `TRMNL_OIDC_REDIRECT_URL` | Defaults to `<TRMNL_BASE_URL>/auth/oidc/callback`. Must be under `TRMNL_BASE_URL`. |
| `TRMNL_OIDC_PROVIDER_NAME` | Display name on the "Sign in with ..." button. Defaults to the issuer's hostname. |
| `TRMNL_OIDC_SESSION_TTL` | Seconds an OIDC session lasts. Default `28800` (8 hours). See below. |

`TRMNL_BASE_URL` is **required** for OIDC: with no fixed public origin there
is nothing to derive the redirect URI from and nothing to allowlist it
against. Register `https://<your-host>/auth/oidc/callback` with the provider.

**https is required** — for the issuer, for the redirect URI, and for every
endpoint the discovery document points at. Plaintext `http://` is accepted
only when the host is loopback (`127.0.0.0/8`, `::1`, `localhost` and
`*.localhost`), so a laptop running both the server and an IdP still works.
Anything else disables OIDC with a message saying so. The reason is in the
next paragraph: skipping the ID-token signature is only sound over TLS.

Every flow uses PKCE `S256`, and the provider has to *advertise* `S256` in
`code_challenge_methods_supported` or the flow is refused — a provider that
silently ignores PKCE is otherwise indistinguishable from one that honours it.
`plain` is never used even when offered. `state` is signed, single-use, bound
to the PKCE verifier and expires in five minutes; `nonce` is sent and checked.
There is no `next` or `redirect_uri` parameter on `/auth/oidc/login` — the
destination is always this server's own `/`.

Zero new dependencies. Local ID-token **signature** verification is
deliberately skipped under **OIDC Core §3.1.3.7 item 6** (the token is
received directly from the token endpoint over TLS with client
authentication). Its **claims** are not skipped: `iss` must be the configured
or advertised issuer, `aud` must contain the client ID, `azp` (when present)
must equal it, and `exp`/`iat` must be sane within two minutes of clock skew.
Identity is then read from the `userinfo` endpoint, which is an authenticated
call in its own right and whose `sub` must match the ID token's exactly
(OIDC Core §5.3.2). The corollary of not verifying signatures is that a
**signed** userinfo response (`Content-Type: application/jwt`) is *refused*
rather than consumed unverified — leave your provider's userinfo signing
algorithm at `none`.

**An OIDC session lasts 8 hours, not the 30 days a shared-secret session
gets** (`TRMNL_OIDC_SESSION_TTL`, in seconds). The difference is deliberate.
A shared-secret session has no external authority to fall out of step with:
holding `TRMNL_UI_TOKEN_FILE` *is* the authorization, and rotating that file
revokes every session on the next request. An OIDC session is a cached claim
about an authorization your provider granted and can withdraw at any time —
remove someone from the group in `TRMNL_OIDC_ALLOWED_GROUPS`, disable their
account, offboard them — and this server is never told. Whatever you set here
is the window in which a revoked operator still has a dashboard. The renewal
costs nothing visible: the provider's own session is normally still valid, so
it is a redirect that answers without prompting. Raise it if you want; it is
your revocation lag.

Both `/auth/oidc/login` and `/auth/oidc/callback` are rate limited, on
counters separate from `POST /auth/session`'s, so traffic against one login
path can never lock you out of the other. Those counters are sized so that
anonymous traffic cannot deny *you* a login — behind a tunnelling reverse
proxy every request shares one source address, so a tight per-source limit is
a lockout anyone can trigger for free. What keeps the panel alive under a
login flood is not the request counter but the cap on concurrent outbound
calls to the provider: eight at a time, refused rather than queued, with every
response body capped at 256 KiB, because the panel's own endpoints share this
process's threadpool and memory.

A discovery outage never locks you out: it disables the OIDC button and
nothing else. Keep `TRMNL_UI_TOKEN_FILE` configured as a way back in until
you trust the setup.

#### authentik

Applications → Create with Provider → OAuth2/OpenID. Client type
**Confidential**. Redirect URI, **Strict**: `https://trmnl.example.com/auth/oidc/callback`.
Leave the default scopes (`openid`, `email`, `profile`) — group membership
rides on `profile`.

```bash
TRMNL_OIDC_ISSUER=https://authentik.example.com/application/o/trmnl/
TRMNL_OIDC_CLIENT_ID=<client id>
TRMNL_OIDC_CLIENT_SECRET_FILE=/run/secrets/trmnl-oidc-secret
TRMNL_OIDC_SCOPES=openid profile email
TRMNL_OIDC_GROUPS_CLAIM=groups
TRMNL_OIDC_ALLOWED_GROUPS=trmnl-admins
```

> authentik has no `groups` scope — do not add one, it is silently dropped.
> Use the exact per-application issuer URL **including the trailing slash**,
> even if the provider's issuer mode is "global": the discovery document is
> only ever served under `/application/o/<slug>/`, never at the root. (In
> global mode the advertised `iss` differs from the discovery base; this
> server logs a warning and continues, rather than refusing a valid setup.)
> For per-application roles instead of directory groups, add the
> `entitlements` scope and set `TRMNL_OIDC_GROUPS_CLAIM=entitlements`.
> If you have edited or removed the shipped `profile` scope mapping, `groups`
> will not be emitted.

#### Keycloak

1. Clients → Create client `trmnl`, Client authentication **On**, Standard
   flow only. Valid redirect URIs: `https://trmnl.example.com/auth/oidc/callback`.
2. Client scopes → **Create client scope** `groups`, Type **Default**,
   Protocol `openid-connect`, Include in token scope **On**.
3. In that scope: Mappers → Configure a new mapper → **Group Membership**.
   Name `groups`, Token Claim Name `groups`, **Full group path Off**, Add to
   ID token **On**, Add to access token **On**, **Add to userinfo On**.
4. Clients → `trmnl` → Client scopes → Add client scope → `groups`, as
   **Default**.

```bash
TRMNL_OIDC_ISSUER=https://keycloak.example.com/realms/home
TRMNL_OIDC_CLIENT_ID=trmnl
TRMNL_OIDC_CLIENT_SECRET_FILE=/run/secrets/trmnl-oidc-secret
TRMNL_OIDC_SCOPES=openid profile email groups
TRMNL_OIDC_GROUPS_CLAIM=groups
TRMNL_OIDC_ALLOWED_GROUPS=trmnl-admins
```

> **Step 3's "Add to userinfo" is mandatory.** Keycloak's built-in role
> mappers write `realm_access.roles` and `resource_access.<client>.roles` to
> the *access token only* — they are excluded from both the ID token and
> userinfo, so no claim path reaches them from a client. A dotted
> `TRMNL_OIDC_GROUPS_CLAIM` does not rescue this.
> **Step 2 is also mandatory**: without a client scope named `groups`
> assigned to the client, Keycloak rejects the authorization request outright
> with `400 invalid_scope` before the user ever sees a login page.
> To use realm roles instead of groups, make step 3's mapper a **User Realm
> Role** mapper with Token Claim Name `groups`, Multivalued **On**, Add to
> userinfo **On**.
> Do **not** use the built-in `microprofile-jwt` scope: its `groups` claim is
> realm roles, not group membership, and it is excluded from userinfo.
> Keycloak 16 and older prefix endpoints with `/auth`:
> `https://keycloak.example.com/auth/realms/home`.

#### Authelia

```yaml
identity_providers:
  oidc:
    clients:
      - client_id: 'trmnl'
        client_name: 'TRMNL'
        client_secret: '$pbkdf2-sha512$310000$...'   # authelia crypto hash generate pbkdf2 --variant sha512
        public: false
        authorization_policy: 'two_factor'
        require_pkce: true
        pkce_challenge_method: 'S256'
        token_endpoint_auth_method: 'client_secret_basic'
        userinfo_signed_response_alg: 'none'
        redirect_uris:
          - 'https://trmnl.example.com/auth/oidc/callback'
        scopes: ['openid', 'profile', 'email', 'groups']
```

```bash
TRMNL_OIDC_ISSUER=https://auth.example.com
TRMNL_OIDC_CLIENT_ID=trmnl
TRMNL_OIDC_CLIENT_SECRET_FILE=/run/secrets/trmnl-oidc-secret
TRMNL_OIDC_SCOPES=openid profile email groups
TRMNL_OIDC_GROUPS_CLAIM=groups
TRMNL_OIDC_ALLOWED_GROUPS=trmnl-admins
```

> No claims policy is needed. Authelia delivers `groups` at the **userinfo**
> endpoint by default and documents putting claims in the ID token as a
> discouraged compatibility escape hatch — this server reads userinfo, which
> is the path Authelia intends.
> Leave `userinfo_signed_response_alg` at `none`; a signed userinfo response
> returns `application/jwt`, which this server refuses rather than consume
> without verifying.

#### Pocket ID

OIDC Clients → Add client `TRMNL`. Callback URL
`https://trmnl.example.com/auth/oidc/callback`.

```bash
TRMNL_OIDC_ISSUER=https://id.example.com
TRMNL_OIDC_CLIENT_ID=<client id>
TRMNL_OIDC_CLIENT_SECRET_FILE=/run/secrets/trmnl-oidc-secret
TRMNL_OIDC_SCOPES=openid profile email groups
TRMNL_OIDC_GROUPS_CLAIM=groups
TRMNL_OIDC_ALLOWED_GROUPS=trmnl-admins
```

> The `groups` claim contains group **names**. If you also set "Allowed user
> groups" on the Pocket ID client itself, Pocket ID refuses the authorization
> before this server ever sees it — that denial is separate from
> `TRMNL_OIDC_ALLOWED_GROUPS`.

#### Google

Google Cloud Console → APIs & Services → Credentials → OAuth client ID →
**Web application**. Authorized redirect URI:
`https://trmnl.example.com/auth/oidc/callback`.

```bash
TRMNL_OIDC_ISSUER=https://accounts.google.com
TRMNL_OIDC_CLIENT_ID=<id>.apps.googleusercontent.com
TRMNL_OIDC_CLIENT_SECRET_FILE=/run/secrets/trmnl-oidc-secret
TRMNL_OIDC_SCOPES=openid profile email
# TRMNL_OIDC_ALLOWED_GROUPS must stay unset — Google returns no group claim.
```

> **Google's OIDC provides no group or role claim of any kind.** Its
> `claims_supported` is `aud, email, email_verified, exp, family_name,
> given_name, iat, iss, name, picture, sub`, and `scopes_supported` is
> `openid, email, profile`. Workspace group membership requires the Admin SDK
> Directory API, which this server does not use. Setting
> `TRMNL_OIDC_ALLOWED_GROUPS` with Google will lock you out — restrict access
> on the Google side instead (User type **Internal**, or an explicit
> allowlist on the consent screen).

### Troubleshooting

The login overlay reports a code from a fixed vocabulary; nothing the
provider said is ever rendered.

| What you see | What it means |
| --- | --- |
| Your account is not in an allowed group | The claim arrived and matched nothing in `TRMNL_OIDC_ALLOWED_GROUPS`. The server log names both lists. |
| The identity provider returned no groups claim | The claim was absent from *both* userinfo and the ID token. Check the scope and that the mapper includes the claim in the **userinfo** response. |
| That sign-in attempt expired, or it did not start in this browser | The state cookie was missing, expired, forged, already redeemed, or did not match the `state` parameter. Usually a bookmarked callback URL or a back-button replay. |
| The identity provider could not be reached | Discovery, the token exchange or userinfo failed. The server log has the URL and the error. |
| Too many failed sign-in attempts | Ten failures per five minutes per client, one hundred across the server. Only failures count, and a success clears the caller's counter. |

## Plugins & registry

- Plugins are auto-discovered from `trmnl_server/plugins/` by the scheduler; any class inheriting `PluginBase` with `AUTO_REGISTER=True` is registered.
- Set `AUTO_REGISTER = False` on a plugin class to opt it out of the registry.
- Set `CALIBRATION_PLUGIN_ENABLED=false` (ENV or `/settings`) to remove all calibration plugins from the registry and skip generating calibration assets.
- `python -m trmnl_server --list-plugins` shows the active registry; `--run-plugin <Name>` respects these toggles.

## API + Static Surface

| Path                                          | Description                                                                                    |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `GET /api/setup`, `/api/setup/`               | Enrolment. MAC allowlist only — the device does not hold a token yet.                          |
| `GET /api/display`                            | Main firmware endpoint: returns `image_url`, `filename` and refresh hints. MAC + Access-Token. |
| `POST /api/log`, `/api/logs`                  | Device log ingestion. Unauthenticated by necessity; body-capped, rate-limited, row-capped.     |
| `GET /image/screen-NNN-<16 hex>.bmp`          | The current panel frame. The unguessable name *is* the capability — never log it.              |
| `GET /preview/<slug>.png`                     | Browser preview of one screen. Access-Token required.                                          |
| `GET /web/*`                                  | Static dashboard assets (HTML/JS/CSS/fonts and fallback imagery).                              |
| `GET /generated/*`                            | Plugin output, but only URLs the current rotation publishes, served from memory. Not a mount.  |
| `POST`/`DELETE`/`GET /auth/session`           | Mint, clear and inspect the control-plane session cookie (`TRMNL_UI_TOKEN_FILE`).              |
| `GET /auth/oidc/login`, `/auth/oidc/callback` | The OIDC code flow. Ends in the same session cookie. Takes no caller-supplied destination.     |
| control plane                                 | `/rotation`, `/playlists`, `/devices`, `/status`, `/server/*` — all require the UI session.    |

Only `/api/*` and `/image/*` are outside the edge's SSO gate, because the
ESP32 cannot follow an SSO redirect. Nothing else may be registered under
`/api/` — `main.py::_assert_route_invariants()` refuses to build the app if
it is.

The UI under `web/` shows plugin output previews and rotation metadata; templates in `templates/` are used by specific plugins (e.g., weather renderer).
