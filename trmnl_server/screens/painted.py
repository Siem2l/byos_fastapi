"""The `sketch` styles, steered by a painting instead of noise.

Each style reads the painting's darkness where it would otherwise read
noise, so the drawing stays a drawing — lines, rings, arcs — while the
painting shows through it roughly, the way a face shows through a
halftone:

* ridgelines — lines that swell where the painting is dark, an engraving;
* contours — a topographic map of its light and dark;
* flow — streamlines that follow its edges and crowd into its shadows;
* circles — small solid dots in the dark, open rings in the light;
* truchet — arcs that thicken in the dark.

The paintings are public domain, stored as 360×200 greyscale PNGs
already cropped to the panel's proportions around their subject
(`paintings/`), so rendering needs no network.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageFilter

from ..canvas import BLACK, Box, Canvas

PAINTINGS_DIR = Path(__file__).parent / "paintings"


@dataclass(frozen=True)
class Painting:
    slug: str
    title: str
    artist: str


PAINTINGS = [
    Painting("great-wave", "The Great Wave", "Hokusai"),
    Painting("starry-night", "The Starry Night", "Van Gogh"),
    Painting("pearl-earring", "Girl with a Pearl Earring", "Vermeer"),
    Painting("mona-lisa", "Mona Lisa", "Leonardo"),
    Painting("the-scream", "The Scream", "Munch"),
    Painting("wanderer", "Wanderer above the Sea of Fog", "Friedrich"),
]


class Darkness:
    """The painting's darkness, 0 (white) to 1 (black), at panel pixels."""

    def __init__(self, slug: str, box: Box, blur: int = 0) -> None:
        self.box = box
        self._slug = slug
        self.pixels, self.w, self.h = _load(slug, blur)

    @property
    def slug(self) -> str:
        return self._slug

    def __call__(self, x: float, y: float) -> float:
        # Bilinear: the source is ~half the panel's resolution, and nearest
        # sampling would print its pixel grid into every line.
        u = (x - self.box.x) / self.box.w * (self.w - 1)
        v = (y - self.box.y) / self.box.h * (self.h - 1)
        u = min(max(u, 0.0), self.w - 1.001)
        v = min(max(v, 0.0), self.h - 1.001)
        x0, y0 = int(u), int(v)
        fx, fy = u - x0, v - y0
        p, w = self.pixels, self.w
        top = p[y0 * w + x0] * (1 - fx) + p[y0 * w + x0 + 1] * fx
        bottom = p[(y0 + 1) * w + x0] * (1 - fx) + p[(y0 + 1) * w + x0 + 1] * fx
        # Clamped: rounding can land a hair below 0, and a negative base
        # raised to a fractional power is complex.
        return min(1.0, max(0.0, 1.0 - (top * (1 - fy) + bottom * fy) / 255.0))


@lru_cache(maxsize=2 * len(PAINTINGS))
def _load(slug: str, blur: int) -> tuple[tuple[int, ...], int, int]:
    with Image.open(PAINTINGS_DIR / f"{slug}.png") as im:
        im = im.convert("L")
        if blur:
            im = im.filter(ImageFilter.GaussianBlur(blur))
        return tuple(im.getdata()), im.width, im.height


# ---- styles -------------------------------------------------------------

def ridgelines(c: Canvas, box: Box, dark: Darkness,
               rng: random.Random) -> None:
    # Lifting each line by darkness, as the generative version does, turns
    # a dark background into one even plateau. Here the lines swell with
    # darkness instead — the banknote engraving — which keeps faces.
    lines = 80
    spacing = box.h / lines
    wave = rng.uniform(0.012, 0.02)
    for i in range(lines):
        base = box.y + (i + 0.5) * spacing
        top, bottom = [], []
        for x in range(box.x, box.right + 1, 2):
            y = base + math.sin(x * wave + i * 0.15) * spacing * 0.35
            half = max(0.35, dark(x, y) ** 1.1 * spacing * 0.40)
            top.append((x, y - half))
            bottom.append((x, y + half))
        c.draw.polygon(top + bottom[::-1], fill=BLACK)


def contours(c: Canvas, box: Box, dark: Darkness,
             rng: random.Random) -> None:
    from .sketch import _crossings

    step = 4
    cols, rows = box.w // step + 1, box.h // step + 1
    field = [[dark(box.x + i * step, box.y + j * step) for i in range(cols)]
             for j in range(rows)]
    levels = 9
    for j in range(rows - 1):
        for i in range(cols - 1):
            corners = (field[j][i], field[j][i + 1], field[j + 1][i + 1],
                       field[j + 1][i])
            first = max(1, math.ceil(min(corners) * levels))
            last = min(levels - 1, math.floor(max(corners) * levels))
            for k in range(first, last + 1):
                pts = _crossings(corners, k / levels, box.x + i * step,
                                 box.y + j * step, step)
                width = 2 if k >= levels - 3 else 1
                for a in range(0, len(pts) - 1, 2):
                    c.draw.line([pts[a], pts[a + 1]], fill=BLACK, width=width)


def flow(c: Canvas, box: Box, dark: Darkness, rng: random.Random) -> None:
    cell = 5
    cols, rows = box.w // cell + 1, box.h // cell + 1
    taken = [[False] * cols for _ in range(rows)]
    g = 4
    gw, gh = box.w // g + 2, box.h // g + 2
    # Angles from a blurred copy: the raw painting's brush strokes would
    # turn every line at every step; blurred, the big shapes steer.
    soft = Darkness(dark_slug(dark), box, blur=4)
    d = [[soft(box.x + i * g, box.y + j * g) for i in range(gw)]
         for j in range(gh)]
    # Lines run along the painting's edges: perpendicular to the gradient
    # of its darkness. Where it is flat, a slow drift keeps them moving.
    angle = [[0.0] * gw for _ in range(gh)]
    for j in range(gh):
        for i in range(gw):
            gx = d[j][min(i + 1, gw - 1)] - d[j][max(i - 1, 0)]
            gy = d[min(j + 1, gh - 1)][i] - d[max(j - 1, 0)][i]
            angle[j][i] = (math.atan2(gy, gx) + math.pi / 2
                           if abs(gx) + abs(gy) > 0.02 else 0.3)

    def free(x: float, y: float):
        cx, cy = int((x - box.x) // cell), int((y - box.y) // cell)
        if 0 <= cx < cols and 0 <= cy < rows and not taken[cy][cx]:
            return cx, cy
        return None

    for _ in range(9000):
        x = rng.uniform(box.x, box.right - 1)
        y = rng.uniform(box.y, box.bottom - 1)
        # Seeds land in proportion to darkness, which is what makes the
        # painting's shadows read as dense ink and its highlights as paper.
        if free(x, y) is None or rng.random() > dark(x, y) ** 1.2:
            continue
        line, cells = [(x, y)], []
        for _ in range(140):
            a = angle[int((y - box.y) // g)][int((x - box.x) // g)]
            x, y = x + math.cos(a) * 2.5, y + math.sin(a) * 2.5
            spot = free(x, y)
            if spot is None or dark(x, y) < 0.1:
                break
            if not cells or cells[-1] != spot:
                cells.append(spot)
            line.append((x, y))
        if len(line) > 4:
            for cx, cy in cells:
                taken[cy][cx] = True
            c.draw.line(line, fill=BLACK, width=1)


def circles(c: Canvas, box: Box, dark: Darkness,
            rng: random.Random) -> None:
    grid = 24
    buckets: dict[tuple[int, int], list[tuple[float, float, float]]] = {}
    placed = []
    for _ in range(14000):
        x = rng.uniform(box.x, box.right)
        y = rng.uniform(box.y, box.bottom)
        light = 1.0 - dark(x, y)
        r = 1.6 + light ** 1.5 * 13 * rng.uniform(0.6, 1.0)
        if x - r < box.x or x + r > box.right or y - r < box.y \
                or y + r > box.bottom:
            continue
        bx, by = int(x // grid), int(y // grid)
        near = [p for dx in (-1, 0, 1) for dy in (-1, 0, 1)
                for p in buckets.get((bx + dx, by + dy), ())]
        if all(math.hypot(x - px, y - py) > r + pr + 1.2
               for px, py, pr in near):
            buckets.setdefault((bx, by), []).append((x, y, r))
            placed.append((x, y, r, light))
    for x, y, r, light in placed:
        if light < 0.5:
            c.draw.ellipse([x - r, y - r, x + r, y + r], fill=BLACK)
        elif light < 0.85:
            c.draw.ellipse([x - r, y - r, x + r, y + r], outline=BLACK,
                           width=1)


def truchet(c: Canvas, box: Box, dark: Darkness,
            rng: random.Random) -> None:
    size = 16
    cols, rows = box.w // size, box.h // size
    ox = box.x + (box.w - cols * size) // 2
    oy = box.y + (box.h - rows * size) // 2
    h = size // 2
    for gy in range(rows):
        for gx in range(cols):
            x, y = ox + gx * size, oy + gy * size
            width = round(dark(x + h, y + h) ** 1.3 * 7)
            if width == 0:
                continue
            if rng.random() < 0.5:
                arcs = [((x - h, y - h), 0, 90), ((x + h, y + h), 180, 270)]
            else:
                arcs = [((x + h, y - h), 90, 180), ((x - h, y + h), 270, 360)]
            for (ax, ay), start, end in arcs:
                c.draw.arc([ax, ay, ax + size, ay + size], start, end,
                           fill=BLACK, width=width)


def dark_slug(dark: Darkness) -> str:
    return dark.slug


DRAW = {
    "ridgelines": ridgelines,
    "flow": flow,
    "truchet": truchet,
    "contours": contours,
    "circles": circles,
}


def draw(c: Canvas, box: Box, style: str, painting: Painting,
         rng: random.Random) -> None:
    DRAW[style](c, box, Darkness(painting.slug, box), rng)
