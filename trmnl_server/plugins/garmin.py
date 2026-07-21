"""Expose this fork's `Screen` implementations to upstream's plugin system.

Upstream's UI has no concept of a "screen": the Playlists tab, the device
card's "Now showing" line and every thumbnail are all driven by rotation
entries, and rotation entries are produced by plugins. So each registered
screen gets a generated `PluginBase` subclass here, which is the entire
integration — `services.plugins` discovers plugins by walking this package,
so a class existing in this module's namespace *is* the registration.

The classes are synthesised from `screens.REGISTRY` rather than written out
one per screen on purpose: `screens/base.py` is already the single source of
truth for what a screen is, and a hand-maintained parallel list would
silently drift the moment someone adds a screen and forgets to add a plugin.

Two upstream conventions are deliberately not followed:

* `PluginBase.save_assets()` is bypassed. It converts to mode "L" and then
  re-quantises to four dithered grey levels, which is precisely what this
  fork's rendering stack exists to avoid — a `Canvas` is a mode-"1" image so
  that FreeType uses its monochrome rasteriser and hatching stands in for
  grey. Both files are written straight from the canvas, so the BMP is a
  true 1-bit BMP and the "grayscale" PNG is the same 1-bit bitmap. The
  scheduler requires both paths to exist; it does not require them to
  differ.

* `run()` renders through `render_screen()` rather than reimplementing
  fetch/render. `fetch()` hits SQLite (GarminDB) and `render()` is pure CPU,
  so both go to a worker thread — the refresh worker shares the event loop
  with `/api/display`, and blocking it would stall the panel.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Dict, Optional

from .. import config as config_module
from ..config import panel_config
from ..render import render_screen
from ..screens import REGISTRY as SCREEN_REGISTRY
from .base import PluginBase, PluginOutput

logger = config_module.logger

# Where generated frames land under WEB_GENERATED_DIR, hence the second
# path segment of their public /generated/... URL.
OUTPUT_SUBDIR = 'garmin'


class ScreenPlugin(PluginBase):
    """Adapts one `Screen` slug to the plugin contract."""

    # Never registered itself: it has no slug, and the concrete subclasses
    # below live in this same module so the `__module__` filter in
    # `_discover_plugin_classes` would otherwise let it through.
    AUTO_REGISTER = False

    SLUG: str = ''
    OUTPUT_SUBDIR = OUTPUT_SUBDIR

    async def run(self, **kwargs) -> Optional[PluginOutput]:
        output_dir = Path(kwargs.get('output_dir') or '.')
        output_dir.mkdir(parents=True, exist_ok=True)

        # No try/except: letting the exception out is what makes the
        # scheduler re-arm in PLUGIN_REFRESH_RETRY (300 s) instead of
        # caching a failure frame for a full TTL, and it leaves the
        # rotation entry stale rather than replacing a good dashboard with
        # an error card. The panel still gets a rendered "unavailable"
        # notice, because routes/panel.py renders on request and handles
        # its own failures.
        canvas, _refresh = await asyncio.to_thread(
            render_screen, self.SLUG, panel_config()
        )

        bmp = await asyncio.to_thread(
            canvas.save, output_dir / f'{self.BASENAME}.bmp', fmt='bmp'
        )
        png = await asyncio.to_thread(
            canvas.save, output_dir / f'{self.BASENAME}.png', fmt='png'
        )
        return PluginOutput(monochrome_path=str(bmp), grayscale_path=str(png))

    def get_content_ttl(self) -> int:
        screen = SCREEN_REGISTRY.get(self.SLUG)
        return max(60, int(getattr(screen, 'refresh_seconds', 900)))

    def get_adjustment_settings(self) -> tuple[bool, float, float]:
        # Identity. The bitmap is final by the time it leaves the canvas;
        # contrast or gamma applied on top would only reintroduce grey.
        return (False, 1.0, 0.0)


def _plugin_class_name(slug: str) -> str:
    """`morning-load` -> `MorningLoadScreenPlugin`.

    The scheduler and the persisted rotation entry IDs both key on the
    class name, so this mapping has to stay stable across restarts.
    """
    parts = [part for part in slug.replace('-', '_').split('_') if part]
    return ''.join(part.capitalize() for part in parts) + 'ScreenPlugin'


def _build_screen_plugins() -> Dict[str, type[ScreenPlugin]]:
    built: Dict[str, type[ScreenPlugin]] = {}
    for order, (slug, screen_cls) in enumerate(sorted(SCREEN_REGISTRY.items())):
        name = _plugin_class_name(slug)
        built[name] = type(name, (ScreenPlugin,), {
            # Explicit, and load-bearing: `PluginBase` is an ABC, so this
            # `type()` call dispatches through `ABCMeta.__new__` and the
            # implicit `__module__` would be inferred as "abc" — which
            # `_discover_plugin_classes` rejects, silently leaving the
            # rotation empty.
            '__module__': __name__,
            '__qualname__': name,
            'SLUG': slug,
            'BASENAME': slug,
            'DISPLAY_NAME': getattr(screen_cls, 'title', None) or slug,
            'AUTO_REGISTER': True,
            'REGISTRY_ORDER': 10 + order,
            '__doc__': f"Rotation entry for the {slug!r} screen.",
        })
    return built


# `type()` stamps __module__ from this module, which is what
# `_discover_plugin_classes` matches on; injecting into globals() is what
# puts the classes in `vars(module)` for it to find.
SCREEN_PLUGINS: Dict[str, type[ScreenPlugin]] = _build_screen_plugins()
globals().update(SCREEN_PLUGINS)

# plugin class name -> screen slug. routes/panel.py uses this to turn a
# UI-managed rotation playlist back into the slug order it renders.
SLUG_BY_PLUGIN: Dict[str, str] = {
    name: cls.SLUG for name, cls in SCREEN_PLUGINS.items()
}

logger.info(
    '[plugins] exposing screens as rotation entries: %s',
    ', '.join(sorted(SLUG_BY_PLUGIN.values())) or '<none>',
)
