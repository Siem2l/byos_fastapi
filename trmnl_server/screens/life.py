"""Conway's Game of Life — something alive on the wall between dashboards.

The simulation lives in `sources/life.py` and keeps running between
looks; this screen only draws it. Two marks per cell, because the panel
shows a still image every few minutes:

* a solid square is alive now;
* a small dot was alive at some point since the previous frame.

The dots are the point of the screen. Without them a frame is a random
scatter of squares; with them a glider leaves a diagonal wake and an
exploding methuselah shows where it grew.
"""

from __future__ import annotations

from ..canvas import BLACK, Box, Canvas
from .base import Context, Screen, register

MARGIN = 24
CELL = 5
BOARD_Y = 66


def _age(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes:02d}m"
    return f"{hours // 24}d {hours % 24}h"


def _bits(row: int):
    while row:
        low = row & -row
        yield low.bit_length() - 1
        row ^= low


@register
class LifeScreen(Screen):
    slug = "life"
    title = "Game of Life"
    # Matches the other screens in the rotation; the simulation advances
    # by wall-clock time, so any cadence shows a consistent pace.
    refresh_seconds = 300

    def fetch(self, ctx: Context) -> dict:
        return ctx.source("life").world()

    def render(self, c: Canvas, d: dict) -> None:
        c.text(MARGIN, 16, "LIFE", size=30, bold=True, tracking=2)
        c.text(
            c.width - MARGIN, 24,
            f"WORLD {d['world']} · {d['seed'].upper()}",
            size=13, bold=True, anchor="ra", tracking=1,
        )
        c.hline(MARGIN, 54, c.width - MARGIN, weight=3)

        board = Box((c.width - d["width"] * CELL) // 2, BOARD_Y,
                    d["width"] * CELL, d["height"] * CELL)
        self._board(c, board, d["rows"], d["trail"])

        foot = board.bottom + 10
        c.hline(MARGIN, foot, c.width - MARGIN, weight=1)
        self._stats(c, foot + 8, d)

    def _board(self, c: Canvas, box: Box, rows: list[int],
               trail: list[int]) -> None:
        # A frame around the torus: without one, a quiet board is a few
        # specks floating on blank paper and reads as a rendering fault.
        c.rect(Box(box.x - 4, box.y - 4, box.w + 8, box.h + 8))
        draw = c.draw
        for y, (row, past) in enumerate(zip(rows, trail)):
            py = box.y + y * CELL
            for x in _bits(past):
                px = box.x + x * CELL
                draw.rectangle([px + 1, py + 1, px + 2, py + 2], fill=BLACK)
            for x in _bits(row):
                px = box.x + x * CELL
                draw.rectangle([px, py, px + CELL - 2, py + CELL - 2],
                               fill=BLACK)

    def _stats(self, c: Canvas, y: int, d: dict) -> None:
        columns = (
            ("generation", f"{d['generation']:,}"),
            ("alive", f"{d['population']:,}"),
            ("age", _age(d["age_seconds"])),
        )
        for i, (label, value) in enumerate(columns):
            x = MARGIN + i * 150
            c.label(x, y, label, size=11)
            c.text(x, y + 16, value, size=24, bold=True)

        spark = Box(MARGIN + 3 * 150, y + 2, c.width - 2 * MARGIN - 3 * 150,
                    34)
        c.label(spark.x, y, "population", size=11)
        c.sparkline(Box(spark.x, spark.y + 14, spark.w, spark.h - 8),
                    d["history"], weight=2)

        prev = d["previous"]
        if prev:
            line = (f"world {prev['world']} ({prev['seed']}) "
                    f"{prev['reason']} after {prev['generations']:,} "
                    "generations")
        else:
            line = "first world since the panel started"
        c.text(MARGIN, y + 48, c.clip(line, c.width - 2 * MARGIN, size=12),
               size=12)
