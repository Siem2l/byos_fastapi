"""FastAPI entrypoint and CLI for the TRMNL BYOS panel server.

CLI: `trmnl-server serve`, `trmnl-server screens`, `trmnl-server preview`.
The subcommand shape deliberately matches the previous stdlib server so the
NixOS module's ExecStart carries over unchanged.
"""

from __future__ import annotations

import argparse
import os
import sys

import uvicorn
from fastapi import FastAPI

from . import config, models
from .config import Config
from .routes import panel_router
from .routes.panel import configure
from .screens import available

logger = config.logger


def create_app(cfg: Config) -> FastAPI:
    app = FastAPI(title="trmnl-byos")
    configure(cfg)
    app.include_router(panel_router)
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

    os.makedirs(cfg.state_dir, exist_ok=True)
    # Keep the battery/log SQLite next to the rendered frames unless the
    # deployment pinned a location via TRMNL_DB_PATH. init_db() re-reads
    # this through reconfigure_engine(), so setting it here is enough.
    if not os.environ.get("TRMNL_DB_PATH"):
        config.DATABASE_PATH = os.path.join(cfg.state_dir, "trmnl.db")
    models.init_db()

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
