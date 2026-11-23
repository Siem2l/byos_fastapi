"""A generative drawing that changes once an hour.

The opposite of `life`: nothing here is live. Each hour gets one piece,
seeded by the hour itself, so every look within that hour shows the same
drawing and the panel reads as a print on the wall rather than a feed.
The styles rotate so consecutive hours never repeat one:

* ridgelines — stacked noise profiles, each hiding the ones behind it;
* flow — evenly spaced streamlines through a noise field;
* truchet — quarter-circle tiles that join into one maze of curves;
* contours — a topographic map of a noise field, every fourth line bold;
* circles — a packing of rings, outlines and solid dots.

Every other hour the same styles draw a painting instead of noise
(`painted.py`): the drawing stays lines and rings, and the painting shows
through it roughly. Six paintings, cycling independently of the styles,
so each comes back in a different style.

Everything is drawn as 1-bit lines on purpose: e-ink renders a crisp
stroke beautifully and a dithered grey as mud.
"""

from __future__ import annotations

import math
import random
from datetime import datetime

from ..canvas import BLACK, WHITE, Box, Canvas
from . import painted
from .base import Context, Screen, register

PIECE_MINUTES = 60
STYLES = ["ridgelines", "flow", "truchet", "contours", "circles"]
ART = Box(24, 20, 752, 418)


class Noise:
    """Smooth 2-D value noise with a seeded lattice."""

    def __init__(self, rng: random.Random) -> None:
        self.perm = list(range(256))
        rng.shuffle(self.perm)
        self.perm += self.perm
        self.values = [rng.random() for _ in range(256)]

    def _lattice(self, x: int, y: int) -> float:
        return self.values[self.perm[(self.perm[x & 255] + y) & 255]]

    def __call__(self, x: float, y: float) -> float:
        x0, y0 = math.floor(x), math.floor(y)
        fx, fy = x - x0, y - y0
        sx, sy = fx * fx * (3 - 2 * fx), fy * fy * (3 - 2 * fy)
        top = self._lattice(x0, y0) + sx * (
            self._lattice(x0 + 1, y0) - self._lattice(x0, y0))
        bottom = self._lattice(x0, y0 + 1) + sx * (
            self._lattice(x0 + 1, y0 + 1) - self._lattice(x0, y0 + 1))
        return top + sy * (bottom - top)

    def fbm(self, x: float, y: float, octaves: int = 4) -> float:
        total, amp, norm = 0.0, 1.0, 0.0
        for _ in range(octaves):
            total += amp * self(x, y)
            norm += amp
            x, y, amp = x * 2.03, y * 2.03, amp * 0.5
        return total / norm


def piece_number(now: datetime) -> int:
    return int(now.timestamp() // (PIECE_MINUTES * 60))


def style_for(number: int) -> str:
    return STYLES[number % len(STYLES)]


def painting_for(number: int) -> painted.Painting | None:
    """The painting an hour draws, or None for a purely generative hour."""
    if number % 2 == 0:
        return None
    return painted.PAINTINGS[(number // 2) % len(painted.PAINTINGS)]


# ---- styles -------------------------------------------------------------

def ridgelines(c: Canvas, box: Box, rng: random.Random) -> None:
    noise = Noise(rng)
    lines = rng.randint(30, 42)
    peak = 120
    spacing = (box.h - peak - 10) / lines
    centre = box.x + box.w * rng.uniform(0.4, 0.6)
    spread = box.w * rng.uniform(0.16, 0.24)
    for i in range(lines):
        base = box.y + peak + 10 + i * spacing
        pts = []
        for x in range(box.x, box.right + 1, 3):
            # Quiet at the edges, wild in the middle: the bell envelope is
            # what makes it read as a range of peaks rather than static.
            env = math.exp(-((x - centre) / spread) ** 2)
            n = noise.fbm(x * 0.012, i * 0.35)
            pts.append((x, base - (n ** 2.2) * peak * env - n * 6))
        c.draw.polygon(pts + [(box.right, base + spacing),
                              (box.x, base + spacing)], fill=WHITE)
        c.draw.line(pts, fill=BLACK, width=2)


def flow(c: Canvas, box: Box, rng: random.Random) -> None:
    noise = Noise(rng)
    scale = rng.uniform(0.0035, 0.006)
    turn = rng.uniform(2.5, 4.5) * math.pi
    cell = 7
    cols, rows = box.w // cell + 1, box.h // cell + 1
    taken = [[False] * cols for _ in range(rows)]

    def free(x: float, y: float) -> tuple[int, int] | None:
        gx, gy = int((x - box.x) // cell), int((y - box.y) // cell)
        if 0 <= gx < cols and 0 <= gy < rows and not taken[gy][gx]:
            return gx, gy
        return None

    # Angles on a 4 px grid, looked up per step: walking the noise for
    # every step of every line is what made this the slowest style.
    g = 4
    angle = [[noise.fbm((box.x + i * g) * scale, (box.y + j * g) * scale, 3)
              * turn for i in range(box.w // g + 2)]
             for j in range(box.h // g + 2)]
    for _ in range(2600):
        x = rng.uniform(box.x, box.right)
        y = rng.uniform(box.y, box.bottom)
        if free(x, y) is None:
            continue
        line, cells = [(x, y)], []
        for _ in range(rng.randint(30, 90)):
            a = angle[int((y - box.y) // g)][int((x - box.x) // g)]
            x, y = x + math.cos(a) * 3, y + math.sin(a) * 3
            spot = free(x, y)
            if spot is None:
                break
            if not cells or cells[-1] != spot:
                cells.append(spot)
            line.append((x, y))
        if len(line) > 8:
            for gx, gy in cells:
                taken[gy][gx] = True
            c.draw.line(line, fill=BLACK, width=2 if rng.random() < 0.2
                        else 1)


def truchet(c: Canvas, box: Box, rng: random.Random) -> None:
    size = rng.choice([28, 32, 38])
    cols, rows = box.w // size, box.h // size
    ox = box.x + (box.w - cols * size) // 2
    oy = box.y + (box.h - rows * size) // 2
    width = max(2, size // 10)
    for gy in range(rows):
        for gx in range(cols):
            x, y = ox + gx * size, oy + gy * size
            h = size // 2
            if rng.random() < 0.5:
                arcs = [((x - h, y - h), 0, 90), ((x + h, y + h), 180, 270)]
            else:
                arcs = [((x + h, y - h), 90, 180), ((x - h, y + h), 270, 360)]
            for (ax, ay), start, end in arcs:
                c.draw.arc([ax, ay, ax + size, ay + size], start, end,
                           fill=BLACK, width=width)
    c.rect(Box(ox - 1, oy - 1, cols * size + 2, rows * size + 2), weight=2)


def contours(c: Canvas, box: Box, rng: random.Random) -> None:
    noise = Noise(rng)
    step = 5
    scale = rng.uniform(0.004, 0.007)
    cols, rows = box.w // step + 1, box.h // step + 1
    field = [[noise.fbm((box.x + i * step) * scale,
                        (box.y + j * step) * scale, 3) for i in range(cols)]
             for j in range(rows)]
    lo = min(min(r) for r in field)
    hi = max(max(r) for r in field)
    levels = 18
    band = (hi - lo) / levels
    for j in range(rows - 1):
        for i in range(cols - 1):
            corners = (field[j][i], field[j][i + 1],
                       field[j + 1][i + 1], field[j + 1][i])
            # Only the levels between this cell's lowest and highest
            # corner cross it; most cells hold none or one.
            first = max(1, math.ceil((min(corners) - lo) / band))
            last = min(levels - 1, math.floor((max(corners) - lo) / band))
            for k in range(first, last + 1):
                pts = _crossings(corners, lo + band * k, box.x + i * step,
                                 box.y + j * step, step)
                width = 2 if k % 4 == 0 else 1
                for a in range(0, len(pts) - 1, 2):
                    c.draw.line([pts[a], pts[a + 1]], fill=BLACK,
                                width=width)


def _crossings(v, level, x, y, s):
    """Where `level` crosses the edges of one marching-squares cell."""
    corners = [(x, y), (x + s, y), (x + s, y + s), (x, y + s)]
    out = []
    for e in range(4):
        a, b = v[e], v[(e + 1) % 4]
        if (a < level) != (b < level):
            t = (level - a) / (b - a)
            (x0, y0), (x1, y1) = corners[e], corners[(e + 1) % 4]
            out.append((x0 + (x1 - x0) * t, y0 + (y1 - y0) * t))
    return out


def circles(c: Canvas, box: Box, rng: random.Random) -> None:
    placed: list[tuple[float, float, float]] = []
    for _ in range(4000):
        r = 4 + (rng.random() ** 3) * 70
        x = rng.uniform(box.x + r, box.right - r)
        y = rng.uniform(box.y + r, box.bottom - r)
        if all(math.hypot(x - px, y - py) > r + pr + 3
               for px, py, pr in placed):
            placed.append((x, y, r))
    for x, y, r in placed:
        if r < 9:
            c.draw.ellipse([x - r, y - r, x + r, y + r], fill=BLACK)
        elif rng.random() < 0.55:
            ring = r
            while ring > 2:
                c.draw.ellipse([x - ring, y - ring, x + ring, y + ring],
                               outline=BLACK, width=1)
                ring -= rng.choice([4, 5, 6])
        else:
            c.draw.ellipse([x - r, y - r, x + r, y + r], outline=BLACK,
                           width=2)


DRAW = {
    "ridgelines": ridgelines,
    "flow": flow,
    "truchet": truchet,
    "contours": contours,
    "circles": circles,
}


def compose(c: Canvas, number: int) -> str:
    """Draw piece `number`; return its caption."""
    style = style_for(number)
    painting = painting_for(number)
    if painting is None:
        DRAW[style](c, ART, random.Random(number))
        return style.upper()
    painted.draw(c, ART, style, painting, random.Random(number))
    return f"{painting.title} · {painting.artist} · {style}".upper()


@register
class SketchScreen(Screen):
    slug = "sketch"
    title = "Sketch"
    refresh_seconds = 300

    def fetch(self, ctx: Context) -> dict:
        now = datetime.now()
        return {"number": piece_number(now), "at": now}

    def render(self, c: Canvas, d: dict) -> None:
        caption = compose(c, d["number"])
        y = c.height - 30
        c.hline(ART.x, y, ART.right, weight=1)
        stamp = (f"NO. {d['number'] % 100000:05d} · "
                 f"{d['at'].strftime('%a %d %b %H:00').upper()}")
        stamp_w = c.text_width(stamp, size=11, bold=True, tracking=1)
        c.text(ART.x, y + 8, c.clip(caption, ART.w - stamp_w - 16, size=11,
                                    bold=True), size=11, bold=True, tracking=2)
        c.text(ART.right, y + 8, stamp, size=11, bold=True, anchor="ra",
               tracking=1)
