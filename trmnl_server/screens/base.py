"""Screen contract and registry.

A screen is a pure function of data → pixels, split in two halves so the
render side can be exercised without touching a data source:

    fetch(ctx)  -> a plain dict of already-shaped values
    render(c,d) -> draws `d` onto canvas `c`

Keeping `fetch` separate is what lets `--preview --synthetic` produce a
pixel-exact rendering on a laptop that has no GarminDB, no Prometheus and
no network.
"""

from __future__ import annotations

from typing import Protocol

from ..canvas import Canvas


class Source(Protocol):
    """Marker protocol — sources are duck-typed per screen."""


class Context:
    """What a screen is handed at fetch time."""

    def __init__(self, config, sources: dict[str, object]) -> None:
        self.config = config
        self.sources = sources

    def source(self, name: str):
        try:
            return self.sources[name]
        except KeyError:
            raise LookupError(
                f"screen requested source {name!r}, which is not configured "
                f"(have: {sorted(self.sources)})"
            ) from None


class Screen:
    slug: str = ""
    title: str = ""
    # How long the device should sleep before asking for this screen again.
    # E-ink refreshes cost battery, so screens declare their own cadence
    # rather than inheriting one global interval.
    refresh_seconds: int = 900

    def fetch(self, ctx: Context) -> dict:
        raise NotImplementedError

    def render(self, canvas: Canvas, data: dict) -> None:
        raise NotImplementedError


REGISTRY: dict[str, type[Screen]] = {}


def register(cls: type[Screen]) -> type[Screen]:
    if not cls.slug:
        raise ValueError(f"{cls.__name__} must define a slug")
    if cls.slug in REGISTRY:
        raise ValueError(f"duplicate screen slug {cls.slug!r}")
    REGISTRY[cls.slug] = cls
    return cls


def get(slug: str) -> Screen:
    try:
        return REGISTRY[slug]()
    except KeyError:
        raise LookupError(
            f"unknown screen {slug!r} (have: {sorted(REGISTRY)})"
        ) from None


def available() -> list[str]:
    return sorted(REGISTRY)
