"""Drawing primitives for 1-bit e-paper panels.

Everything is rendered directly into a PIL mode-"1" image. That matters:
when the target image is 1-bit, FreeType renders glyphs with a monochrome
rasteriser instead of an antialiased one, so text comes out crisp rather
than as a smear of dithered grey that e-ink turns to mud. The corollary is
that there is no grey — where a design wants a lighter tone we hatch a
pattern instead (see `SHADE`).

Coordinates are pixels, origin top-left. Boxes are (x, y, w, h).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from PIL import Image, ImageDraw, ImageFont

BLACK = 0
WHITE = 1

# Hatch densities as the period of a diagonal fill: period 2 reads as ~50%
# ink, 4 as ~25%. Only these four steps are offered on purpose — adjacent
# periods (3 vs 4) are indistinguishable at arm's length, so a palette with
# more steps than this would imply differences the panel cannot show.
SHADE = {"solid": 1, "dense": 2, "sparse": 4, "empty": 0}

_FONT_DIRS = [
    Path(p)
    for p in os.environ.get("TRMNL_FONT_PATH", "").split(":")
    if p
] + [
    Path("/run/current-system/sw/share/X11/fonts"),
    Path("/usr/share/fonts/truetype/dejavu"),
    Path("/Library/Fonts"),
]

_FONT_FILES = {
    ("sans", False): "DejaVuSans.ttf",
    ("sans", True): "DejaVuSans-Bold.ttf",
    ("cond", False): "DejaVuSansCondensed.ttf",
    ("cond", True): "DejaVuSansCondensed-Bold.ttf",
}


def _find_font(family: str, bold: bool) -> Path:
    name = _FONT_FILES[(family, bold)]
    for d in _FONT_DIRS:
        hit = d / name
        if hit.exists():
            return hit
        # Font dirs are often nested (…/share/fonts/truetype/DejaVuSans.ttf).
        for found in d.rglob(name):
            return found
    raise FileNotFoundError(
        f"{name} not found. Set TRMNL_FONT_PATH to a directory containing "
        f"the DejaVu TTFs (searched: {[str(d) for d in _FONT_DIRS]})"
    )


class Fonts:
    """Lazily-loaded, memoised font cache keyed by (family, size, bold)."""

    def __init__(self) -> None:
        self._cache: dict[tuple[str, int, bool], ImageFont.FreeTypeFont] = {}

    def get(self, size: int, *, bold: bool = False, family: str = "sans"):
        key = (family, size, bold)
        if key not in self._cache:
            self._cache[key] = ImageFont.truetype(
                str(_find_font(family, bold)), size
            )
        return self._cache[key]


FONTS = Fonts()


@dataclass(frozen=True)
class Box:
    x: int
    y: int
    w: int
    h: int

    @property
    def right(self) -> int:
        return self.x + self.w

    @property
    def bottom(self) -> int:
        return self.y + self.h

    def inset(self, dx: int, dy: int | None = None) -> "Box":
        dy = dx if dy is None else dy
        return Box(self.x + dx, self.y + dy, self.w - 2 * dx, self.h - 2 * dy)

    def split_h(self, n: int, gap: int = 0) -> list["Box"]:
        """Split into n equal columns separated by `gap` px."""
        each = (self.w - gap * (n - 1)) // n
        return [
            Box(self.x + i * (each + gap), self.y, each, self.h)
            for i in range(n)
        ]

    def split_v(self, n: int, gap: int = 0) -> list["Box"]:
        each = (self.h - gap * (n - 1)) // n
        return [
            Box(self.x, self.y + i * (each + gap), self.w, each)
            for i in range(n)
        ]


class Canvas:
    """A 1-bit drawing surface with chart primitives."""

    def __init__(self, width: int = 800, height: int = 480) -> None:
        self.width = width
        self.height = height
        self.image = Image.new("1", (width, height), WHITE)
        self.draw = ImageDraw.Draw(self.image)

    @property
    def bounds(self) -> Box:
        return Box(0, 0, self.width, self.height)

    # ---- text -----------------------------------------------------------

    def text(
        self,
        x: int,
        y: int,
        s: str,
        *,
        size: int = 16,
        bold: bool = False,
        family: str = "sans",
        anchor: str = "la",
        tracking: int = 0,
    ) -> None:
        """Draw `s`. `anchor` is a PIL anchor ("la" = left-ascender).

        `tracking` adds letter-spacing, which rescues all-caps labels at
        small sizes on e-ink where glyphs otherwise crowd together.
        """
        font = FONTS.get(size, bold=bold, family=family)
        if not tracking:
            self.draw.text((x, y), s, font=font, fill=BLACK, anchor=anchor)
            return

        # PIL has no letter-spacing, so place glyphs individually. Only the
        # left-anchored case is meaningful here; right/centre are computed
        # by measuring first.
        total = self.text_width(s, size=size, bold=bold, family=family,
                                tracking=tracking)
        if anchor[0] == "m":
            x -= total // 2
        elif anchor[0] == "r":
            x -= total
        cursor = x
        for ch in s:
            self.draw.text((cursor, y), ch, font=font, fill=BLACK,
                           anchor="l" + anchor[1])
            cursor += int(self.draw.textlength(ch, font=font)) + tracking

    def text_width(
        self,
        s: str,
        *,
        size: int = 16,
        bold: bool = False,
        family: str = "sans",
        tracking: int = 0,
    ) -> int:
        font = FONTS.get(size, bold=bold, family=family)
        base = int(self.draw.textlength(s, font=font))
        return base + tracking * max(len(s) - 1, 0)

    def label(self, x: int, y: int, s: str, *, size: int = 13,
              anchor: str = "la") -> None:
        """A small-caps section label — the workhorse for metric headings."""
        self.text(x, y, s.upper(), size=size, bold=True, anchor=anchor,
                  tracking=1)

    # ---- lines & shapes -------------------------------------------------

    def hline(self, x0: int, y: int, x1: int, *, weight: int = 1) -> None:
        self.draw.rectangle([x0, y, x1, y + weight - 1], fill=BLACK)

    def vline(self, x: int, y0: int, y1: int, *, weight: int = 1) -> None:
        self.draw.rectangle([x, y0, x + weight - 1, y1], fill=BLACK)

    def rect(self, box: Box, *, weight: int = 1) -> None:
        self.draw.rectangle(
            [box.x, box.y, box.right - 1, box.bottom - 1],
            outline=BLACK, width=weight,
        )

    def fill(self, box: Box, *, shade: str = "solid") -> None:
        """Fill `box`, hatching when `shade` asks for less than 100% ink."""
        period = SHADE[shade]
        if period == 0:
            return
        if period == 1:
            self.draw.rectangle(
                [box.x, box.y, box.right - 1, box.bottom - 1], fill=BLACK
            )
            return
        for py in range(box.y, box.bottom):
            # Offsetting each row by the row index turns a dotted grid into
            # a diagonal weave, which reads as a smoother tone than columns.
            for px in range(box.x + (py % period), box.right, period):
                self.draw.point((px, py), fill=BLACK)

    def dotted_hline(self, x0: int, y: int, x1: int, *, period: int = 3) -> None:
        for px in range(x0, x1, period):
            self.draw.point((px, y), fill=BLACK)

    def tri_up(self, x: int, y: int, size: int = 7) -> None:
        h = size // 2
        self.draw.polygon(
            [(x, y), (x + size, y), (x + h, y - h - 1)], fill=BLACK
        )

    def tri_down(self, x: int, y: int, size: int = 7) -> None:
        h = size // 2
        self.draw.polygon(
            [(x, y - h - 1), (x + size, y - h - 1), (x + h, y)], fill=BLACK
        )

    def delta(self, x: int, y: int, value: float, *, size: int = 13,
              suffix: str = "") -> int:
        """Draw a signed change as arrow + magnitude. Returns width drawn."""
        if value == 0:
            self.text(x, y, "flat", size=size, bold=True)
            return self.text_width("flat", size=size, bold=True)
        mag = f"{abs(value):g}{suffix}"
        if value > 0:
            self.tri_up(x, y + size - 3, 7)
        else:
            self.tri_down(x, y + size - 3, 7)
        self.text(x + 11, y, mag, size=size, bold=True)
        return 11 + self.text_width(mag, size=size, bold=True)

    # ---- charts ---------------------------------------------------------

    def sparkline(
        self,
        box: Box,
        values: Sequence[float | None],
        *,
        weight: int = 2,
        baseline: float | None = None,
        marker: bool = True,
    ) -> None:
        """Line chart with no axes. `None` values break the line.

        `baseline` draws a dotted reference rule (e.g. a 7-day average) and
        is included in the y-range so the line never escapes the box.
        `marker` puts a dot on the most recent point, which is what stops a
        14-day trace from reading as an anonymous squiggle.
        """
        pts = [v for v in values if v is not None]
        if len(pts) < 2:
            return
        lo, hi = min(pts), max(pts)
        if baseline is not None:
            lo, hi = min(lo, baseline), max(hi, baseline)
        # Pad the range by a tenth. Without this, autoscaling pins the min
        # and max to the box edges and a flat-ish week of resting HR looks
        # like a mountain range.
        pad = (hi - lo) * 0.10 or 1.0
        lo, hi = lo - pad, hi + pad
        span = (hi - lo) or 1.0
        # Leave headroom so a peak sitting exactly on the top edge still
        # renders its full stroke width.
        top = box.y + weight
        usable = box.h - 2 * weight

        def xy(i: int, v: float) -> tuple[int, int]:
            px = box.x + round(i * (box.w - 1) / (len(values) - 1))
            py = top + round((hi - v) / span * usable)
            return px, py

        if baseline is not None:
            _, by = xy(0, baseline)
            self.dotted_hline(box.x, by, box.right)

        run: list[tuple[int, int]] = []
        for i, v in enumerate(values):
            if v is None:
                if len(run) > 1:
                    self.draw.line(run, fill=BLACK, width=weight, joint="curve")
                run = []
            else:
                run.append(xy(i, v))
        if len(run) > 1:
            self.draw.line(run, fill=BLACK, width=weight, joint="curve")

        if marker and run:
            mx, my = run[-1]
            r = weight + 1
            self.draw.ellipse([mx - r, my - r, mx + r, my + r], fill=BLACK)

    def bars(
        self,
        box: Box,
        values: Sequence[float],
        *,
        gap: int = 3,
        shades: Sequence[str] | None = None,
        zero_at_bottom: bool = True,
    ) -> None:
        """Vertical bar chart scaled to the largest value."""
        if not values:
            return
        hi = max(values) or 1.0
        width = max((box.w - gap * (len(values) - 1)) // len(values), 1)
        for i, v in enumerate(values):
            bh = max(round(v / hi * box.h), 1 if v > 0 else 0)
            if not bh:
                continue
            bx = box.x + i * (width + gap)
            by = box.bottom - bh if zero_at_bottom else box.y
            shade = shades[i] if shades else "solid"
            self.fill(Box(bx, by, width, bh), shade=shade)

    def stacked_bar(
        self,
        box: Box,
        segments: Iterable[tuple[float, str]],
        *,
        divider: bool = True,
    ) -> None:
        """Horizontal 100%-stacked bar of (magnitude, shade) pairs."""
        segs = [(v, s) for v, s in segments if v > 0]
        total = sum(v for v, _ in segs)
        if total <= 0:
            return
        self.rect(box)
        cursor = box.x + 1
        remaining = box.w - 2
        for idx, (v, shade) in enumerate(segs):
            # Give the last segment whatever rounding left behind so the
            # stack always reaches the far edge exactly.
            seg_w = (
                remaining
                if idx == len(segs) - 1
                else round(v / total * (box.w - 2))
            )
            seg_w = min(seg_w, remaining)
            if seg_w <= 0:
                continue
            self.fill(Box(cursor, box.y + 1, seg_w, box.h - 2), shade=shade)
            if divider and idx < len(segs) - 1:
                self.vline(cursor + seg_w - 1, box.y + 1, box.bottom - 2)
            cursor += seg_w
            remaining -= seg_w

    def gauge(self, box: Box, fraction: float, *, shade: str = "solid") -> None:
        """Horizontal progress bar, `fraction` clamped to 0..1."""
        frac = min(max(fraction, 0.0), 1.0)
        self.rect(box)
        inner = box.inset(2)
        filled = round(inner.w * frac)
        if filled > 0:
            self.fill(Box(inner.x, inner.y, filled, inner.h), shade=shade)

    # ---- output ---------------------------------------------------------

    def save(self, path: str | Path, *, fmt: str | None = None) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "bmp" or (fmt is None and path.suffix.lower() == ".bmp"):
            # The stock firmware expects a 1-bit BMP at native resolution.
            self.image.save(path, format="BMP")
        else:
            self.image.save(path, format="PNG", optimize=True)
        return path
