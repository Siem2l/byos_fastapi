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

from . import config, models
from .config import Config
from .routes import api_router, image_router, page_router, panel_router
from .routes.panel import configure
from .screens import available

logger = config.logger


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
    app.include_router(image_router)
    app.include_router(page_router)
    _mount_static(app)

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
