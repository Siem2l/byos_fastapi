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
    canvas = _render(piece_number(HOUR) + offset)
    ink = canvas.image.histogram()[0] / (800 * 480)
    assert canvas.image.mode == "1"
    assert 0.03 < ink < 0.30


@pytest.mark.parametrize("offset", range(len(STYLES)))
def test_the_same_hour_draws_the_same_piece(offset):
    number = piece_number(HOUR) + offset
    assert _render(number).image.tobytes() == _render(number).image.tobytes()
