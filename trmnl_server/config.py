from __future__ import annotations

import logging
from os import environ, getcwd
from os.path import abspath, dirname, isdir, join
from sys import stdout

# Logging Configuration
LOG_LEVEL = environ.get('LOG_LEVEL', 'DEBUG').upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.DEBUG),
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=stdout
)
logger = logging.getLogger('trmnlServer')

# Pillow emits very noisy DEBUG logs (PNG chunk dumps). Keep them at INFO+.
logging.getLogger('PIL').setLevel(logging.INFO)
logging.getLogger('PIL.PngImagePlugin').setLevel(logging.INFO)
logging.getLogger('httpx').setLevel(logging.WARNING)
logging.getLogger('httpcore').setLevel(logging.WARNING)

logger.info('[Config] loading module')

_TRUE_VALUES = {'true', '1', 't', 'yes', 'on'}

IMAGE_PATH = 'images/screen.bmp'
REFRESH_TIME = 900
BATTERY_MAX_VOLTAGE = 4.1
BATTERY_MIN_VOLTAGE = 2.3
TIME_ZONE = 'UTC'
SERVER_PORT = 4567
ENABLE_SSL = False
SERVER_SCHEME = 'http'
SETUP_API_KEY = ''
SETUP_FRIENDLY_ID = 'trmnl-byod'
SETUP_MESSAGE = 'Configured'
DITHERING_MODE = 'none'
ASSETS_ROOT = 'web'
STATIC_ROOT = 'web'
GENERATED_ROOT = 'var/generated'

# Hard limit for generated grayscale PNG assets (bytes).
PNG_MAX_BYTES = 90000

# Photographic plugin grading
#
# When enabled, photographic plugins apply additional histogram and shadow grading
# prior to tone-curve-aware quantization/dithering.
# When disabled, photographic plugins output raw grayscale (no extra grading),
# which makes it easier to reason about the tone curve/LUT calibration.
PHOTO_GRADING_ENABLED = True

# Calibration plugin control
#
# When disabled, calibration plugins are excluded from the plugin registry and
# no calibration assets are generated.
CALIBRATION_PLUGIN_ENABLED = False

# E-ink grayscale response compensation
#
# These settings allow quantization and dithering to operate in a non-linear
# "panel space" so the resulting grays are closer to perceptually uniform on
# real e-ink panels.
#
# - EINK_TONE_POINTS: optional anchor list "in:out" in 0-255, comma-separated
#   e.g. "0:0,32:40,128:160,255:255" (digital input -> observed panel output).
# - EINK_TONE_GAMMA: fallback forward gamma (digital -> panel) when points unset.
EINK_TONE_POINTS = '0:0,32:6,64:18,85:32,128:95,170:155,192:190,224:225,255:250'
EINK_TONE_GAMMA = 1.0

CONFIG_DIR = getcwd()

# Upstream resolves every runtime directory relative to the working
# directory. Under the NixOS unit there is no WorkingDirectory and
# DynamicUser starts in `/`, so `web` and `var/generated` would resolve to
# `/web` and `/var/generated` — neither of which exists, and both of which
# `ProtectSystem = "strict"` makes unwritable. For the static root that is
# fatal: StaticFiles() raises at construction when its directory is
# missing, taking the whole unit down at startup rather than merely
# breaking the UI. The generated root is no longer served by StaticFiles
# (routes/images.py serves an allowlist from memory instead), but it is
# still the plugin scheduler's write target and the base that
# `utils.path_to_web_url()` maps to `/generated/...`, so it must stay
# pinned to a writable location with a stable path — the persisted
# playlist IDs embed those URLs.
#
# Both roots are therefore pinned to locations that are correct by
# construction: the static assets to the copy installed inside the package,
# and the generated (volatile) assets to the service's StateDirectory. The
# pins survive `_refresh_path_constants()`, so a persisted `static_root` /
# `generated_root` row cannot move them back out from under a running
# deployment.
_PACKAGED_WEB_DIR = join(dirname(abspath(__file__)), 'web')
_PINNED_WEB_STATIC_DIR: str | None = (
    _PACKAGED_WEB_DIR if isdir(_PACKAGED_WEB_DIR) else None
)
_PINNED_WEB_GENERATED_DIR: str | None = None
# Same treatment for the SQLite file, and for the same reason: without it
# `_refresh_path_constants()` silently resets DATABASE_PATH back to
# `$PWD/var/db/trmnl.db` every time anything touches a path constant, which
# discards TRMNL_DB_PATH. Under the unit that path is unwritable, so the
# effect is a service that will not start — and `pin_generated_assets_dir()`
# calls `_refresh_path_constants()`, so it happened on every boot that set
# TRMNL_DB_PATH.
_PINNED_DATABASE_PATH: str | None = None

VAR_ROOT = join(CONFIG_DIR, 'var')
DATABASE_PATH = join(VAR_ROOT, 'db', 'trmnl.db')
LOGS_DIR = join(VAR_ROOT, 'logs')
SSL_DIR = join(VAR_ROOT, 'ssl')
WEB_ROOT_DIR = _PINNED_WEB_STATIC_DIR or join(CONFIG_DIR, ASSETS_ROOT)
WEB_STATIC_DIR = _PINNED_WEB_STATIC_DIR or join(CONFIG_DIR, STATIC_ROOT)
WEB_GENERATED_DIR = join(CONFIG_DIR, GENERATED_ROOT)

_ENV_OVERRIDES: set[str] = set()


def _env_str(name: str, default: str, config_key: str) -> str:
    value = environ.get(name)
    if value is None:
        return default
    _ENV_OVERRIDES.add(config_key)
    return value


def _env_bool(name: str, default: bool, config_key: str) -> bool:
    value = environ.get(name)
    if value is None:
        return default
    _ENV_OVERRIDES.add(config_key)
    return value.strip().lower() in _TRUE_VALUES


def _env_int(name: str, default: int, config_key: str) -> int:
    value = environ.get(name)
    if value is None:
        return default
    try:
        number = int(value)
        _ENV_OVERRIDES.add(config_key)
        return number
    except ValueError:
        logger.warning('[Config] Invalid int for %s: %s', name, value)
        return default


def _env_float(name: str, default: float, config_key: str) -> float:
    value = environ.get(name)
    if value is None:
        return default
    try:
        number = float(value)
        _ENV_OVERRIDES.add(config_key)
        return number
    except ValueError:
        logger.warning('[Config] Invalid float for %s: %s', name, value)
        return default


def _apply_environment_overrides() -> None:
    global IMAGE_PATH, REFRESH_TIME
    global BATTERY_MAX_VOLTAGE, BATTERY_MIN_VOLTAGE, TIME_ZONE
    global SERVER_PORT, ENABLE_SSL, SERVER_SCHEME
    global SETUP_API_KEY, SETUP_FRIENDLY_ID, SETUP_MESSAGE
    global DITHERING_MODE, ASSETS_ROOT, STATIC_ROOT, GENERATED_ROOT
    global PNG_MAX_BYTES
    global EINK_TONE_POINTS, EINK_TONE_GAMMA
    global PHOTO_GRADING_ENABLED, CALIBRATION_PLUGIN_ENABLED
    _ENV_OVERRIDES.clear()

    default_eink_tone_points = EINK_TONE_POINTS
    default_eink_tone_gamma = EINK_TONE_GAMMA

    IMAGE_PATH = _env_str('IMAGE_PATH', 'images/screen.bmp', 'image_path')
    REFRESH_TIME = _env_int('REFRESH_TIME', 900, 'refresh_time')
    BATTERY_MAX_VOLTAGE = _env_float('BATTERY_MAX_VOLTAGE', 4.1, 'battery_max_voltage')
    BATTERY_MIN_VOLTAGE = _env_float('BATTERY_MIN_VOLTAGE', 2.3, 'battery_min_voltage')
    TIME_ZONE = _env_str('TIME_ZONE', 'UTC', 'time_zone')
    SERVER_PORT = _env_int('SERVER_PORT', 4567, 'server_port')
    ENABLE_SSL = _env_bool('ENABLE_SSL', False, 'enable_ssl')
    SETUP_API_KEY = _env_str('SETUP_API_KEY', '', 'setup_api_key')
    SETUP_FRIENDLY_ID = _env_str('SETUP_FRIENDLY_ID', 'trmnl-byod', 'setup_friendly_id')
    SETUP_MESSAGE = _env_str('SETUP_MESSAGE', 'Configured', 'setup_message')
    DITHERING_MODE = _env_str('DITHERING_MODE', 'none', 'dithering_mode')
    ASSETS_ROOT = _env_str('ASSETS_ROOT', 'web', 'assets_root')
    STATIC_ROOT = _env_str('STATIC_ROOT', 'web', 'static_root')
    GENERATED_ROOT = _env_str('GENERATED_ROOT', 'var/generated', 'generated_root')
    PNG_MAX_BYTES = _env_int('PNG_MAX_BYTES', 90000, 'png_max_bytes')
    EINK_TONE_POINTS = _env_str('EINK_TONE_POINTS', default_eink_tone_points, 'eink_tone_points')
    EINK_TONE_GAMMA = _env_float('EINK_TONE_GAMMA', default_eink_tone_gamma, 'eink_tone_gamma')
    PHOTO_GRADING_ENABLED = _env_bool('PHOTO_GRADING_ENABLED', PHOTO_GRADING_ENABLED, 'photo_grading_enabled')
    CALIBRATION_PLUGIN_ENABLED = _env_bool('CALIBRATION_PLUGIN_ENABLED', CALIBRATION_PLUGIN_ENABLED, 'calibration_plugin_enabled')
    _refresh_server_scheme()


def _refresh_server_scheme() -> None:
    global SERVER_SCHEME
    SERVER_SCHEME = 'https' if ENABLE_SSL else 'http'


def _refresh_path_constants() -> None:
    global VAR_ROOT, DATABASE_PATH, LOGS_DIR, SSL_DIR
    global WEB_ROOT_DIR, WEB_STATIC_DIR, WEB_GENERATED_DIR
    VAR_ROOT = join(CONFIG_DIR, 'var')
    DATABASE_PATH = _PINNED_DATABASE_PATH or join(VAR_ROOT, 'db', 'trmnl.db')
    LOGS_DIR = join(VAR_ROOT, 'logs')
    SSL_DIR = join(VAR_ROOT, 'ssl')
    WEB_ROOT_DIR = _PINNED_WEB_STATIC_DIR or join(CONFIG_DIR, ASSETS_ROOT)
    WEB_STATIC_DIR = _PINNED_WEB_STATIC_DIR or join(CONFIG_DIR, STATIC_ROOT)
    WEB_GENERATED_DIR = _PINNED_WEB_GENERATED_DIR or join(CONFIG_DIR, GENERATED_ROOT)


def pin_generated_assets_dir(path: str) -> None:
    """Point the generated-asset root at `path`.

    Called once from `create_app()` with `<TRMNL_STATE_DIR>/generated`, the
    one directory the unit is guaranteed to be able to write to. This is the
    plugin scheduler's output directory and the root
    `utils.path_to_web_url()` rewrites to the `/generated/...` URL prefix; it
    is not an HTTP document root (nothing is served straight off disk from
    here — see `routes/images.py::serve_generated`).
    """
    global _PINNED_WEB_GENERATED_DIR
    _PINNED_WEB_GENERATED_DIR = abspath(path)
    _refresh_path_constants()


def pin_database_path(path: str) -> None:
    """Pin the SQLite location so path refreshes cannot move it.

    Assigning `DATABASE_PATH` directly does not survive: any later call into
    `_refresh_path_constants()` — `pin_generated_assets_dir()` makes one —
    recomputes it from CONFIG_DIR.
    """
    global _PINNED_DATABASE_PATH
    _PINNED_DATABASE_PATH = abspath(path)
    _refresh_path_constants()


def load_config(base_dir: str | None = None) -> None:
    """Apply environment overrides and update path constants for the provided base directory."""
    global CONFIG_DIR
    _apply_environment_overrides()
    if base_dir:
        candidate = abspath(base_dir)
        if not isdir(candidate):
            logger.warning('[Config] Provided base_dir %s is not a directory; using current working directory', base_dir)
            candidate = getcwd()
        CONFIG_DIR = candidate
    else:
        CONFIG_DIR = getcwd()
    _refresh_path_constants()


def _coerce_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in _TRUE_VALUES
    return bool(value)


def update_config(key: str, value) -> None:
    """Update an in-memory configuration value."""
    global IMAGE_PATH, REFRESH_TIME
    global BATTERY_MAX_VOLTAGE, BATTERY_MIN_VOLTAGE, TIME_ZONE
    global SERVER_PORT, ENABLE_SSL, SETUP_API_KEY
    global SETUP_FRIENDLY_ID, SETUP_MESSAGE, DITHERING_MODE
    global ASSETS_ROOT, STATIC_ROOT, GENERATED_ROOT
    global EINK_TONE_POINTS, EINK_TONE_GAMMA
    global PHOTO_GRADING_ENABLED, CALIBRATION_PLUGIN_ENABLED

    logger.info('[Config] Updating %s to %s', key, value)

    if key == 'image_path':
        IMAGE_PATH = str(value)
    elif key == 'refresh_time':
        REFRESH_TIME = int(value)
    elif key == 'battery_max_voltage':
        BATTERY_MAX_VOLTAGE = float(value)
    elif key == 'battery_min_voltage':
        BATTERY_MIN_VOLTAGE = float(value)
    elif key == 'time_zone':
        TIME_ZONE = str(value)
    elif key == 'server_port':
        SERVER_PORT = int(value)
    elif key == 'enable_ssl':
        ENABLE_SSL = _coerce_bool(value)
        _refresh_server_scheme()
    elif key == 'setup_api_key':
        SETUP_API_KEY = str(value)
    elif key == 'setup_friendly_id':
        SETUP_FRIENDLY_ID = str(value)
    elif key == 'setup_message':
        SETUP_MESSAGE = str(value)
    elif key == 'dithering_mode':
        DITHERING_MODE = str(value)
    elif key == 'assets_root':
        ASSETS_ROOT = str(value)
        _refresh_path_constants()
    elif key == 'static_root':
        STATIC_ROOT = str(value)
        _refresh_path_constants()
    elif key == 'generated_root':
        GENERATED_ROOT = str(value)
        _refresh_path_constants()
    elif key == 'eink_tone_points':
        EINK_TONE_POINTS = str(value)
    elif key == 'eink_tone_gamma':
        EINK_TONE_GAMMA = float(value)
    elif key == 'photo_grading_enabled':
        PHOTO_GRADING_ENABLED = _coerce_bool(value)
    elif key == 'calibration_plugin_enabled':
        CALIBRATION_PLUGIN_ENABLED = _coerce_bool(value)
    else:
        logger.warning('[Config] Unknown config key: %s', key)


def apply_persisted_config(entries: dict[str, str]) -> None:
    """Apply database-backed configuration entries unless overridden by env vars."""
    for key, raw_value in entries.items():
        if key in _ENV_OVERRIDES:
            continue
        update_config(key, raw_value)


_apply_environment_overrides()
_refresh_path_constants()


# ---------------------------------------------------------------------------
# Panel (BYOS) configuration.
#
# Entirely env-var driven: the NixOS module is the only intended writer of
# these variables, and the names are load-bearing — modules/services/web/
# trmnl.nix sets them verbatim. The defaults exist so `preview` works from a
# source checkout.
# ---------------------------------------------------------------------------

from dataclasses import dataclass, field  # noqa: E402


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = environ.get(name, '')
    items = [p.strip() for p in raw.split(',') if p.strip()]
    return items or default


def normalise_mac(value: str) -> str:
    """Lowercase, strip separators — the firmware's casing is not stable."""
    return ''.join(c for c in value.lower() if c.isalnum())


# What a device's poll interval may be, in seconds. `/api/display` hands this
# number straight to the ESP32's deep-sleep timer, so it is a write into
# physical hardware behaviour: 1 s flattens the battery in hours, 86400 s
# freezes the glass for a day.
#
# Enforced in TWO places, and both are load-bearing. `PATCH /devices/{id}`
# rejects an out-of-range value (routes/api.py) so the UI cannot store one;
# `api_display()` clamps whatever it reads back (routes/panel.py) so a row
# that got into `device_profiles` some other way cannot reach the panel. A
# write-side check alone is worth nothing here — the row outlives the code
# that wrote it, and anything with the SQLite file (an older build whose
# PATCH was unauthenticated, a restore from backup, a future bug, an
# operator with sqlite3) can put a 1 in that column. Read-side clamping is
# what actually protects the hardware.
MIN_REFRESH_INTERVAL = 60
MAX_REFRESH_INTERVAL = 21600


class TokenUnavailable(RuntimeError):
    """A secret file is configured but its contents could not be read.

    Distinct from "no secret configured", which is a deployment choice
    (LAN-only) and means the check is skipped. This one is an operational
    fault — a bad mode, a missing bind mount, a truncated file — and callers
    must fail closed on it. See `Config.token()`.
    """


@dataclass
class Config:
    host: str = field(default_factory=lambda: environ.get(
        'TRMNL_HOST', '127.0.0.1'))
    port: int = field(default_factory=lambda: _env_int(
        'TRMNL_PORT', 8095, 'trmnl_port'))
    # Where rendered BMPs are written and served from.
    state_dir: str = field(default_factory=lambda: environ.get(
        'TRMNL_STATE_DIR', '/var/lib/trmnl'))
    garmin_db_dir: str = field(default_factory=lambda: environ.get(
        'TRMNL_GARMIN_DB_DIR', '/mnt/storage/garmin/DBs'))
    # Playlist: screens are served round-robin in this order.
    playlist: list[str] = field(default_factory=lambda: _env_list(
        'TRMNL_PLAYLIST', ['readiness']))
    width: int = field(default_factory=lambda: _env_int(
        'TRMNL_WIDTH', 800, 'trmnl_width'))
    height: int = field(default_factory=lambda: _env_int(
        'TRMNL_HEIGHT', 480, 'trmnl_height'))
    # Shared secret the device echoes back in the Access-Token header.
    # Read from a file so it never appears in the systemd unit or /proc.
    token_file: str = field(default_factory=lambda: environ.get(
        'TRMNL_TOKEN_FILE', ''))
    # Shared secret for the *browser* control plane (routes/auth.py). This is
    # deliberately a second, independent secret: a leak of the panel's
    # Access-Token must not become a control-plane write, and a leak of the
    # UI secret must not let anyone impersonate the panel. Never accept one
    # where the other is expected.
    ui_token_file: str = field(default_factory=lambda: environ.get(
        'TRMNL_UI_TOKEN_FILE', ''))
    # MAC addresses permitted to enrol. /api/setup necessarily predates the
    # device holding a token, so on a publicly-reachable deployment this
    # allowlist is the only thing standing between a passer-by and a free
    # copy of the access token.
    allowed_devices: list[str] = field(default_factory=lambda: [
        normalise_mac(m) for m in _env_list('TRMNL_ALLOWED_DEVICES', [])
    ])
    # Public base URL, needed because /api/display hands the firmware an
    # absolute image_url rather than a relative path.
    base_url: str = field(default_factory=lambda: environ.get(
        'TRMNL_BASE_URL', '').rstrip('/'))

    # --- OIDC: the second way to mint the same session ---------------------
    #
    # Entirely optional and entirely discovery-driven: the presence of
    # `TRMNL_OIDC_ISSUER` is what turns the feature on, and every endpoint is
    # read out of `<issuer>/.well-known/openid-configuration` rather than
    # configured by hand, which is what makes one code path work across
    # authentik, Keycloak, Authelia, Pocket ID and Google.
    #
    # These are plain fields on Config, read through `panel_config()` at
    # request time, so a test (or a future settings endpoint) can change them
    # on the live object — see `trmnl_server/oidc.py`.
    oidc_issuer: str = field(default_factory=lambda: environ.get(
        'TRMNL_OIDC_ISSUER', '').strip())
    oidc_client_id: str = field(default_factory=lambda: environ.get(
        'TRMNL_OIDC_CLIENT_ID', '').strip())
    # A file, like every other secret here, so it never lands in a unit file,
    # `/proc/<pid>/environ` or `docker inspect`.
    oidc_client_secret_file: str = field(default_factory=lambda: environ.get(
        'TRMNL_OIDC_CLIENT_SECRET_FILE', '').strip())
    # `groups` is in the default set deliberately. Requesting it costs
    # nothing on authentik (unknown scopes are silently dropped) and is
    # required on Authelia and Pocket ID; Keycloak rejects the authorization
    # request outright with `invalid_scope` until the operator creates the
    # matching client scope — which is a loud, self-describing failure on the
    # IdP's own error page, and strictly better than the silent "you are not
    # in an allowed group" that omitting it would produce everywhere else.
    oidc_scopes: str = field(default_factory=lambda: (
        environ.get('TRMNL_OIDC_SCOPES', '').strip()
        or 'openid profile email groups'))
    # Comma-separated. Empty means "any successfully authenticated user",
    # which is the only workable default for an IdP with no group concept at
    # all (Google). When it is non-empty the check fails closed.
    oidc_allowed_groups: list[str] = field(default_factory=lambda: [
        g.strip()
        for g in environ.get('TRMNL_OIDC_ALLOWED_GROUPS', '').split(',')
        if g.strip()
    ])
    # Claim holding the group list. A dotted value is tried as a flat key
    # first and only then as a path, so an IdP that legitimately emits a
    # claim with a dot in its name keeps working.
    oidc_groups_claim: str = field(default_factory=lambda: (
        environ.get('TRMNL_OIDC_GROUPS_CLAIM', '').strip() or 'groups'))
    # Defaults to `<base_url>/auth/oidc/callback`. When set explicitly it
    # must still sit under `base_url` — see `oidc.configuration_problem()`.
    # Nothing caller-supplied ever reaches this value.
    oidc_redirect_url: str = field(default_factory=lambda: environ.get(
        'TRMNL_OIDC_REDIRECT_URL', '').strip())
    # Display name for the "Sign in with ..." button. Falls back to the
    # issuer's hostname, which is right often enough to be a sane default.
    oidc_provider_name: str = field(default_factory=lambda: environ.get(
        'TRMNL_OIDC_PROVIDER_NAME', '').strip())

    # Serve fabricated data instead of reading GarminDB. Lets the unit be
    # smoke-tested on a host where the import has not run yet.
    synthetic: bool = field(default_factory=lambda: bool(
        environ.get('TRMNL_SYNTHETIC')))

    def device_allowed(self, device_id: str | None) -> bool:
        """An empty allowlist means "any device", which is LAN-only sane."""
        if not self.allowed_devices:
            return True
        return normalise_mac(device_id or '') in self.allowed_devices

    def token(self) -> str | None:
        """The panel's Access-Token, or None when none is configured.

        Two different "no token" cases, and conflating them is a fail-open.
        `TRMNL_TOKEN_FILE` unset is a deployment *decision* — LAN-only, no
        token required — and `routes/panel.py::authorised()` treats it as
        "the check does not apply". A configured file that cannot be read,
        or that is empty, is an operational *fault*: a bad mode, a missing
        bind mount, a truncated write, a `chmod 000`. Returning None there
        would silently drop the Access-Token requirement from /api/display,
        /preview and /generated on a deployment that asked for one — on the
        open internet, since /api/* bypasses the edge's SSO. So this raises
        instead, and every caller fails closed on it.
        """
        if not self.token_file:
            return None
        try:
            with open(self.token_file, encoding='utf-8') as fh:
                value = fh.read().strip()
        except OSError as exc:
            raise TokenUnavailable(
                f'TRMNL_TOKEN_FILE {self.token_file!r} is configured but '
                f'could not be read: {exc}'
            ) from exc
        if not value:
            raise TokenUnavailable(
                f'TRMNL_TOKEN_FILE {self.token_file!r} is configured but empty'
            )
        return value

    @staticmethod
    def _read_optional_secret(
        env_name: str, path: str, consequence: str
    ) -> str | None:
        """Contents of a secret file, or None with a loud log line.

        The None-on-fault shape (rather than `token()`'s raise) is only
        correct where None is *already* fail-closed for every caller. Both
        current users qualify: no session secret means the control plane
        answers 503, and no OIDC client secret means OIDC is off.
        """
        if not path:
            return None
        try:
            with open(path, encoding='utf-8') as fh:
                value = fh.read().strip()
        except OSError as exc:
            logger.error(
                '%s %r could not be read (%s) — %s', env_name, path, exc,
                consequence,
            )
            return None
        if not value:
            logger.error('%s %r is empty — %s', env_name, path, consequence)
            return None
        return value

    def ui_token(self) -> str | None:
        """Secret that mints a control-plane session cookie.

        Read on every use rather than cached, so rotating the file
        invalidates every outstanding session at the next request without a
        restart (the cookie's HMAC key is derived from this value).

        Unlike `token()` this returns None on an unreadable file rather than
        raising, because None is *already* fail-closed here:
        `require_ui_session()` refuses the whole control plane with 503 when
        there is no secret, and `create_session()` will not mint a cookie
        without one. The error is logged so the cause is not a mystery.
        """
        return self._read_optional_secret(
            'TRMNL_UI_TOKEN_FILE', self.ui_token_file,
            'the shared-secret login path is unavailable',
        )

    def oidc_client_secret(self) -> str | None:
        """The OIDC client secret, or None when OIDC cannot be used.

        Same fail-closed shape as `ui_token()`: an unreadable or empty file
        is a fault, and the fault disables the OIDC login path rather than
        weakening it. The shared-secret path is untouched either way.
        """
        return self._read_optional_secret(
            'TRMNL_OIDC_CLIENT_SECRET_FILE', self.oidc_client_secret_file,
            'the OIDC login path is disabled',
        )

    def oidc_callback_url(self) -> str:
        """Where the IdP is told to send the browser back to.

        Derived from `base_url`, never from anything the caller sent. An
        explicit `TRMNL_OIDC_REDIRECT_URL` still has to sit under `base_url`
        (`oidc.configuration_problem()` refuses to enable the feature
        otherwise), so there is no value of any environment variable — let
        alone of any request — that turns this into an open redirect.
        """
        if self.oidc_redirect_url:
            return self.oidc_redirect_url
        return f"{self.base_url.rstrip('/')}/auth/oidc/callback"

    def session_secret(self) -> str | None:
        """Key material for the `trmnl_ui` cookie, from either login path.

        The cookie's HMAC key is derived from a secret this server owns, and
        until OIDC existed that secret was necessarily `TRMNL_UI_TOKEN_FILE`
        — which meant an operator who configured *only* OIDC had nothing to
        sign a session with, and `require_ui_session()` answered 503 to every
        request even after a flawless code flow. So the key source
        generalises: the UI secret when there is one, otherwise the OIDC
        client secret.

        Two consequences worth knowing, both acceptable and both documented
        in the README:

        * Rotating either file invalidates outstanding sessions, exactly as
          rotating `TRMNL_UI_TOKEN_FILE` always has.
        * On an OIDC-only deployment the IdP also holds the client secret, so
          it could in principle derive the cookie key. It can already mint an
          identity for anyone, so this is not an escalation — but it is why
          `TRMNL_UI_TOKEN_FILE` remains the preferred source when both are
          set.

        None means *neither* login method is configured, which is the state
        `require_ui_session()` refuses the whole control plane for. Invariant
        preserved, with a two-input predicate instead of a one-input one.
        """
        return self.ui_token() or self.oidc_client_secret()


_PANEL: 'Config | None' = None


def panel_config() -> Config:
    """The process-wide panel config, built from the environment on first use."""
    global _PANEL
    if _PANEL is None:
        _PANEL = Config()
    return _PANEL


def set_panel_config(cfg: Config) -> None:
    """Install `cfg` as the process-wide panel config.

    The plugin scheduler runs on a background task with no request context,
    so the Garmin screen adapter has to reach the same Config the HTTP
    surface was built with. `create_app()` calls this before anything else
    so `panel_config()` is that object everywhere, rather than a second
    instance re-read from the environment.
    """
    global _PANEL
    _PANEL = cfg


# models.py builds its SQLAlchemy engine at import time, so the database
# location has to be pinned via the environment before the process starts.
_db_override = environ.get('TRMNL_DB_PATH')
if _db_override:
    pin_database_path(_db_override)
