"""FastAPI entrypoint and CLI for the TRMNL BYOS panel server.

CLI: `trmnl-server serve`, `trmnl-server screens`, `trmnl-server preview`.
The subcommand shape deliberately matches the previous stdlib server so the
NixOS module's ExecStart carries over unchanged.
"""

from __future__ import annotations

import argparse
import os
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import config, models, oidc
from .config import Config
from .routes import (
    api_router,
    auth_router,
    image_router,
    oidc_router,
    page_router,
    panel_router,
)
from .routes.auth import require_ui_session
from .routes.panel import configure
from .screens import available

logger = config.logger

# The firmware's entire surface under /api/. The Pangolin edge bypasses SSO
# for /api/* because an ESP32 cannot follow an SSO redirect, so anything
# registered under this prefix is reachable from the open internet with
# whatever credentials the route itself demands and nothing more. This list
# is the allowlist enforced by `_assert_route_invariants()`; adding to it is
# a deliberate act, not something a stray `APIRouter(prefix="/api")` can do
# by accident.
_DEVICE_API_PATHS = frozenset({
    "/api/setup", "/api/setup/",
    "/api/display", "/api/display/",
    "/api/log", "/api/log/",
    "/api/logs", "/api/logs/",
})


def _prepare_runtime(cfg: Config) -> None:
    """Pin the paths the restored UI depends on before anything reads them."""
    config.set_panel_config(cfg)
    os.makedirs(cfg.state_dir, exist_ok=True)
    # Where the plugin scheduler writes rotation frames, and the root
    # `utils.path_to_web_url()` maps to the `/generated/...` URLs the UI's
    # thumbnails use. It has to be writable, which under systemd means the
    # StateDirectory and nothing else. Nothing is served straight off this
    # directory — `routes/images.py::serve_generated` serves an allowlist of
    # current rotation members from memory instead.
    config.pin_generated_assets_dir(os.path.join(cfg.state_dir, "generated"))
    os.makedirs(config.WEB_GENERATED_DIR, exist_ok=True)

    # Keep the battery/log/rotation SQLite next to the rendered frames
    # unless the deployment pinned a location via TRMNL_DB_PATH. init_db()
    # re-reads this through reconfigure_engine(), so setting it here is
    # enough — but it must happen before services.state is imported, since
    # the rotation playlists are loaded out of it at startup.
    if not os.environ.get("TRMNL_DB_PATH"):
        config.pin_database_path(os.path.join(cfg.state_dir, "trmnl.db"))
    models.init_db()


def _mount_static(app: FastAPI) -> None:
    # index.html references /web/... absolutely, so without this mount the
    # UI loads as unstyled, inert HTML. StaticFiles raises at construction
    # when its directory is missing, so guard rather than take down a unit
    # that would otherwise still be serving the panel perfectly well.
    if os.path.isdir(config.WEB_STATIC_DIR):
        app.mount(
            "/web",
            StaticFiles(directory=config.WEB_STATIC_DIR),
            name="web-static",
        )
    else:
        logger.error(
            "web assets not found at %s — the UI at / will not render. "
            "This is a packaging fault: trmnl_server/web must ship with "
            "the package.",
            config.WEB_STATIC_DIR,
        )
    # There is deliberately no StaticFiles mount for /generated. A mount is a
    # standing HTTP grant on a *directory*: it serves whatever happens to be
    # in <state_dir>/generated now and forever, so a future plugin writing
    # there publishes its output with no review step, and a render stays
    # reachable at a stable, guessable path long after it has left the
    # rotation. `routes/images.py::serve_generated` replaces it with an
    # allowlist of the URLs the current rotation snapshot actually publishes,
    # served from the bytes already held in memory. Mounts cannot carry
    # Depends(), which is the other half of why this had to become a route.


def _walk_routes(routes, prefix: str = ""):
    """Yield `(effective_path, route_like)` for every leaf route in `routes`.

    `app.routes` is not a flat list of `APIRoute`s, and has not been one
    since FastAPI ~0.137: `include_router()` now leaves an opaque
    `_IncludedRouter` in the table that exposes neither `.path` nor
    `.routes`, and resolves its children lazily through
    `effective_route_contexts()`. Both invariants below are of the form "no
    route does X", so the moment iteration stops seeing real routes they
    stop failing — silently, correctly, and for the wrong reason. Verified:
    with fastapi 0.136.3 the suite is 50 passed; with 0.139.2 the two route
    invariants were the only failures, and they failed by finding nothing at
    all to check. A nixpkgs bump is all it would have taken in production.

    So: recurse, and duck-type rather than isinstance-check, so this keeps
    working on the versions that do and do not have the wrapper.

    * anything exposing `effective_route_contexts()` is a FastAPI >= 0.137
      include wrapper — its contexts already carry the fully-prefixed path;
    * anything exposing `.routes` is a Starlette `Mount`/`Router`, whose
      children's paths are relative to its own;
    * everything else is a leaf.
    """
    for route in routes:
        contexts = getattr(route, "effective_route_contexts", None)
        if callable(contexts):
            for ctx in contexts():
                yield prefix + (getattr(ctx, "path", "") or ""), ctx
            continue
        path = prefix + (getattr(route, "path", "") or "")
        nested = getattr(route, "routes", None)
        if nested:
            yield from _walk_routes(nested, path)
            continue
        yield path, route


def route_paths(app: FastAPI) -> set[str]:
    """Every path the built app actually serves. Also used by the tests."""
    return {path for path, _route in _walk_routes(app.router.routes)}


def _under_api(path: str) -> bool:
    """True for the prefix the edge bypasses SSO for — and only that prefix.

    `/api` itself counts (a sub-application mounted there would serve
    `/api/anything`); `/apidocs` does not.
    """
    return path == "/api" or path.startswith("/api/")


def _assert_route_invariants(app: FastAPI) -> None:
    """Fail at startup rather than in production on an auth-shape regression.

    Two invariants that were previously only comments:

    1. Nothing but the firmware's fixed device surface may live under
       `/api/`, because the edge bypasses SSO for that whole prefix. A
       browser endpoint registered there would silently lose its Authentik
       gate.
    2. Every control-plane route must carry `require_ui_session`. The
       dependency is attached to the router, so this holds by construction —
       this asserts that it *stayed* attached.

    Both are negative assertions, so the dangerous failure is not a false
    alarm but an empty walk. Everything below therefore proves it looked at
    something before concluding anything: a non-zero route count, a non-empty
    control-plane router, and every control-plane path actually reachable in
    the built app.
    """
    collected = list(_walk_routes(app.router.routes))
    if not collected:
        raise RuntimeError(
            "route invariant check walked the app and found no routes at "
            "all. That is not a clean bill of health — every check below is "
            'of the form "no route does X", so an empty walk passes them '
            "vacuously. The route container shape has changed (see "
            "_walk_routes); fix the walk before trusting this app."
        )

    for path, _route in collected:
        if _under_api(path) and path not in _DEVICE_API_PATHS:
            raise RuntimeError(
                f"route {path!r} is registered under /api/, which the Pangolin "
                "edge bypasses SSO for. Control-plane routes must live "
                "outside /api/ (see routes/api.py). If this really is a "
                "firmware endpoint, add it to _DEVICE_API_PATHS explicitly."
            )

    guarded = {getattr(route, "path", "") for route in api_router.routes}
    guarded.discard("")
    if not guarded:
        raise RuntimeError(
            "the control-plane router exposes no routes, so invariant 2 "
            "would hold vacuously — see routes/api.py"
        )
    seen = {path for path, _route in collected}
    missing = guarded - seen
    if missing:
        raise RuntimeError(
            f"control-plane routes {sorted(missing)} are registered on "
            "api_router but were not found in the built app. The walk is "
            "not seeing them, so their require_ui_session check below is "
            "not being made — see _walk_routes."
        )

    for path, route in collected:
        if path not in guarded:
            continue
        dependant = getattr(route, "dependant", None)
        calls = [dep.call for dep in dependant.dependencies] if dependant else []
        if require_ui_session not in calls:
            raise RuntimeError(
                f"control-plane route {path!r} is not guarded by "
                "require_ui_session — see routes/auth.py"
            )


def create_app(cfg: Config) -> FastAPI:
    _prepare_runtime(cfg)

    # Imported here, not at module scope: building the plugin registry
    # instantiates every plugin class, which reaches into the screen
    # registry and the panel config. Doing that at import time would run it
    # before `set_panel_config()` above.
    from .services import plugins, state

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        state.set_server_base_url(cfg.base_url)
        state.initialize_rotation_playlists_from_storage()
        # Render once up front so the UI has rotation entries (and the
        # Playlists tab has something to show) on the very first page load
        # rather than after the first refresh interval elapses.
        await plugins.refresh_plugin_assets()
        await plugins.start_plugin_refreshers()
        try:
            yield
        finally:
            await plugins.stop_plugin_refreshers()

    app = FastAPI(
        title="trmnl-byos",
        lifespan=lifespan,
        # Swagger/ReDoc/OpenAPI publish the full route table — including the
        # shape of /preview and /image — and Swagger's own assets are
        # CDN-hosted, so /docs would also pull third-party JS into the
        # browser. Nothing here consumes them; turn them off rather than
        # rely on the edge gate alone.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    configure(cfg)
    # panel_router first — see routes/__init__.py for why the order is
    # load-bearing rather than cosmetic.
    app.include_router(panel_router)
    app.include_router(api_router)
    app.include_router(auth_router)
    # Immediately after auth_router and before image_router: `/auth/oidc/*`
    # is prefix-less like every other router here, so it cannot be shadowed
    # by image_router's `/generated/{path:path}` catch-all or by
    # page_router's `/`.
    app.include_router(oidc_router)
    app.include_router(image_router)
    app.include_router(page_router)
    _mount_static(app)

    # No CORSMiddleware, and its absence is load-bearing rather than an
    # omission: FastAPI only parses a body as JSON when the content-type says
    # so, which 422s a `text/plain` simple-request forgery, and PATCH/DELETE
    # are preflighted into oblivion with no Access-Control-Allow-Origin
    # header. Adding CORS would hand cross-site JS the control plane that
    # SameSite=Strict and the origin pin exist to deny it.
    # tests/test_panel.py::test_no_cors_middleware_is_installed asserts it is
    # still absent.

    # OIDC status is decided from the config *shape* only. Discovery is never
    # fetched here: an IdP that is down at boot must not delay startup, and it
    # certainly must not take the shared-secret login path with it.
    level, message = oidc.startup_report(cfg)
    getattr(logger, level)(message)

    if not cfg.ui_token_file and not oidc.enabled(cfg):
        logger.error(
            "neither TRMNL_UI_TOKEN_FILE nor a working TRMNL_OIDC_ISSUER is "
            "configured — the browser control plane (/rotation, /devices, "
            "/status, /server/*) will refuse every request with 503. Point "
            "TRMNL_UI_TOKEN_FILE at a file holding the UI secret, or "
            "configure OIDC."
        )

    _assert_route_invariants(app)
    return app


def _serve(cfg: Config) -> None:
    if not cfg.base_url:
        # image_url must be absolute for the firmware to fetch it; falling
        # back to the bind address only works on a flat LAN, so say so.
        cfg.base_url = f"http://{cfg.host}:{cfg.port}"
        logger.warning(
            "TRMNL_BASE_URL unset — using %s. Set it to the URL the device "
            "actually reaches, or it will fail to load images.",
            cfg.base_url,
        )

    app = create_app(cfg)
    logger.info(
        "listening on %s:%s, playlist=%s",
        cfg.host, cfg.port, ",".join(cfg.playlist),
    )
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="info")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trmnl-server")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("screens", help="list registered screens")

    p_serve = sub.add_parser("serve", help="run the BYOS HTTP server")
    p_serve.add_argument("--host")
    p_serve.add_argument("--port", type=int)

    p_prev = sub.add_parser("preview", help="render one screen to a file")
    p_prev.add_argument("screen")
    p_prev.add_argument("-o", "--output", default="preview.png")
    p_prev.add_argument(
        "--synthetic", action="store_true",
        help="use fabricated data instead of reading GarminDB",
    )

    args = parser.parse_args(argv)
    cfg = Config()

    if args.cmd == "screens":
        for slug in available():
            print(slug)
        return 0

    if args.cmd == "preview":
        from .render import render_to_file

        path, refresh = render_to_file(
            args.screen, cfg, args.output, synthetic=args.synthetic
        )
        print(f"wrote {path} (refresh {refresh}s)")
        return 0

    if args.cmd == "serve":
        if args.host:
            cfg.host = args.host
        if args.port:
            cfg.port = args.port
        _serve(cfg)
        return 0

    return 1


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
