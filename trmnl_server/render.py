"""Wire a screen to its sources and produce an image."""

from __future__ import annotations

from pathlib import Path

from .canvas import Canvas
from .config import Config
from .screens import Context, get
from .sources import (
    GarminSource,
    PrometheusSource,
    SyntheticGarminSource,
    SyntheticPrometheusSource,
)


def build_sources(config: Config, *, synthetic: bool = False) -> dict:
    if synthetic or config.synthetic:
        return {
            "garmin": SyntheticGarminSource(),
            "prometheus": SyntheticPrometheusSource(),
        }
    return {
        "garmin": GarminSource(config.garmin_db_dir),
        # Always constructed, even with no URL configured: the source
        # knows it is switched off and says so when asked, which turns
        # an unconfigured deployment into one legible notice on the
        # glass instead of a LookupError from `ctx.source()` that reads
        # as a missing screen.
        "prometheus": PrometheusSource(config.prometheus_url),
    }


def render_screen(
    slug: str,
    config: Config,
    *,
    synthetic: bool = False,
) -> tuple[Canvas, int]:
    """Render `slug`. Returns the canvas and the screen's refresh interval."""
    screen = get(slug)
    ctx = Context(config, build_sources(config, synthetic=synthetic))
    data = screen.fetch(ctx)
    canvas = Canvas(config.width, config.height)
    screen.render(canvas, data)
    return canvas, screen.refresh_seconds


def render_notice(config: Config, title: str, detail: str) -> Canvas:
    """A legible failure screen.

    A panel showing a stale dashboard is indistinguishable from a healthy
    one, which is the worst possible failure mode for a device with no
    other status indicator. Saying "this is broken, and here is why" on
    the glass is the whole point.
    """
    canvas = Canvas(config.width, config.height)
    canvas.text(24, 24, title.upper(), size=30, bold=True, tracking=2)
    canvas.hline(24, 66, config.width - 24, weight=3)

    y = 96
    for line in detail.splitlines():
        for chunk in _wrap(canvas, line.strip(), config.width - 48, 18):
            canvas.text(24, y, chunk, size=18)
            y += 26
    return canvas


def _wrap(canvas: Canvas, text: str, width: int, size: int) -> list[str]:
    if not text:
        return [""]
    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}".strip()
        if current and canvas.text_width(candidate, size=size) > width:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def render_to_file(
    slug: str,
    config: Config,
    path: str | Path,
    *,
    synthetic: bool = False,
) -> tuple[Path, int]:
    canvas, refresh = render_screen(slug, config, synthetic=synthetic)
    return canvas.save(path), refresh
