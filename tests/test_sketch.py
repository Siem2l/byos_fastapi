"""The hourly generative drawing."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from trmnl_server.canvas import Canvas
from trmnl_server.screens.sketch import (
    STYLES,
    SketchScreen,
    piece_number,
    style_for,
)

HOUR = datetime(2026, 11, 23, 14, 5)


def _render(number: int) -> Canvas:
    canvas = Canvas(800, 480)
    SketchScreen().render(canvas, {"number": number, "at": HOUR})
    return canvas


def test_one_piece_per_hour():
    assert piece_number(HOUR) == piece_number(HOUR + timedelta(minutes=50))
    assert piece_number(HOUR) != piece_number(HOUR + timedelta(hours=1))


def test_consecutive_hours_never_repeat_a_style():
    n = piece_number(HOUR)
    assert [style_for(n + k) for k in range(len(STYLES))] != [style_for(n)] * 5
    assert len({style_for(n + k) for k in range(len(STYLES))}) == len(STYLES)


@pytest.mark.parametrize("offset", range(len(STYLES)))
def test_every_style_is_a_legible_1bit_print(offset):
    # Even pieces are the generative ones; stepping by two still visits
    # every style, five being odd.
    first = piece_number(HOUR) // 2 * 2
    canvas = _render(first + 2 * offset)
    ink = canvas.image.histogram()[0] / (800 * 480)
    assert canvas.image.mode == "1"
    assert 0.03 < ink < 0.30


@pytest.mark.parametrize("offset", range(len(STYLES)))
def test_the_same_hour_draws_the_same_piece(offset):
    number = piece_number(HOUR) + offset
    assert _render(number).image.tobytes() == _render(number).image.tobytes()


from trmnl_server.screens import painted  # noqa: E402
from trmnl_server.screens.sketch import ART, painting_for  # noqa: E402


def test_every_other_hour_is_a_painting():
    n = piece_number(HOUR)
    kinds = [painting_for(n + k) is not None for k in range(4)]
    assert kinds.count(True) == 2 and kinds[0] != kinds[1]


def test_every_painting_comes_back_in_every_style():
    seen = {(painting_for(n).slug, style_for(n))
            for n in range(1, 2 * 5 * len(painted.PAINTINGS) * 2, 2)}
    assert len(seen) == len(painted.PAINTINGS) * len(STYLES)


@pytest.mark.parametrize("painting", painted.PAINTINGS, ids=lambda p: p.slug)
@pytest.mark.parametrize("style", STYLES)
def test_a_painting_draws_in_every_style(painting, style):
    import random

    canvas = Canvas(800, 480)
    painted.draw(canvas, ART, style, painting, random.Random(1))
    ink = canvas.image.histogram()[0] / (800 * 480)
    # Dark paintings print dark: an engraving of the Pearl Earring's black
    # background is mostly ink, and that is the point. Blank is the failure.
    assert 0.03 < ink < 0.75


def test_the_paintings_ship_with_the_package():
    for p in painted.PAINTINGS:
        assert (painted.PAINTINGS_DIR / f"{p.slug}.png").is_file()
