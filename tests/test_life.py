"""The Game of Life source: the rules, the clock, and the file."""

from __future__ import annotations

import json
import random

from trmnl_server.sources import life
from trmnl_server.sources.life import (
    GEN_SECONDS,
    H,
    MAX_CATCH_UP,
    W,
    LifeSource,
    SyntheticLifeSource,
    advance,
    new_world,
    population,
    step,
)


def _board(cells: set[tuple[int, int]]) -> list[int]:
    rows = [0] * H
    for x, y in cells:
        rows[y] |= 1 << x
    return rows


def _cells(rows: list[int]) -> set[tuple[int, int]]:
    return {(x, y) for y, r in enumerate(rows) for x in range(W) if r >> x & 1}


def _world(cells: set[tuple[int, int]]) -> dict:
    state = new_world(1, 0.0, random.Random(0))
    state["rows"] = _board(cells)
    state["history"] = [len(cells)]
    return state


GLIDER = {(1, 0), (2, 1), (0, 2), (1, 2), (2, 2)}


def test_a_blinker_turns_and_turns_back():
    across = {(10, 10), (11, 10), (12, 10)}
    down = {(11, 9), (11, 10), (11, 11)}
    assert _cells(step(_board(across))) == down
    assert _cells(step(step(_board(across)))) == across


def test_a_glider_moves_one_cell_diagonally_every_four_generations():
    rows = _board(GLIDER)
    for _ in range(4):
        rows = step(rows)
    assert _cells(rows) == {(x + 1, y + 1) for x, y in GLIDER}


def test_the_board_wraps_at_every_edge():
    # Straddling the corner: a blinker cut by both seams still turns.
    across = {(W - 1, 0), (0, 0), (1, 0)}
    assert _cells(step(_board(across))) == {(0, H - 1), (0, 0), (0, 1)}


def test_the_clock_decides_how_far_the_world_moves():
    state = _world(GLIDER)
    advance(state, 7 * GEN_SECONDS + 3, random.Random(0))
    assert state["generation"] == 7
    # The leftover 3 s carries over rather than being dropped.
    advance(state, 8 * GEN_SECONDS, random.Random(0))
    assert state["generation"] == 8


def test_no_time_passed_means_no_change():
    state = _world(GLIDER)
    assert advance(state, GEN_SECONDS - 1, random.Random(0)) is False
    assert state["generation"] == 0


def test_catching_up_after_downtime_is_capped(monkeypatch):
    # A lone glider would otherwise end the world for being quiet.
    monkeypatch.setattr(life, "QUIET_GENS", 10**9)
    state = _world(GLIDER)
    advance(state, 10**7, random.Random(0))
    assert state["generation"] == MAX_CATCH_UP
    assert state["updated"] == 10**7


def test_the_trail_holds_where_the_glider_has_been():
    state = _world(GLIDER)
    advance(state, 4 * GEN_SECONDS, random.Random(0))
    trail = _cells(state["trail"])
    assert GLIDER <= trail
    assert population(state["rows"]) == 5


def test_a_still_life_ends_the_world_and_starts_the_next():
    block = {(5, 5), (6, 5), (5, 6), (6, 6)}
    state = _world(block)
    advance(state, 3 * GEN_SECONDS, random.Random(0))
    assert state["world"] == 2
    assert state["generation"] == 0
    assert state["previous"]["reason"] == "settled"
    assert state["previous"]["world"] == 1


def test_an_empty_board_has_died_out():
    state = _world({(5, 5)})
    advance(state, GEN_SECONDS, random.Random(0))
    assert state["previous"]["reason"] == "died out"


def test_worlds_cycle_through_soups_and_named_patterns():
    seeds = [new_world(n, 0.0, random.Random(n))["seed"] for n in range(1, 9)]
    assert seeds.count("soup") == 4
    assert {"acorn", "r-pentomino", "glider gun", "rabbits"} <= set(seeds)


def test_the_world_survives_a_restart(tmp_path):
    clock = [1000.0]
    LifeSource(tmp_path, clock=lambda: clock[0]).world()
    clock[0] += 5 * GEN_SECONDS
    again = LifeSource(tmp_path, clock=lambda: clock[0]).world()
    assert again["world"] == 1
    assert again["generation"] == 5


def test_a_broken_file_starts_a_fresh_world(tmp_path):
    (tmp_path / "life.json").write_text("{not json")
    assert LifeSource(tmp_path, clock=lambda: 0.0).world()["generation"] == 0


def test_a_board_of_another_size_is_not_loaded(tmp_path):
    LifeSource(tmp_path, clock=lambda: 0.0).world()
    raw = json.loads((tmp_path / "life.json").read_text())
    raw["width"] = W + 1
    (tmp_path / "life.json").write_text(json.dumps(raw))
    fresh = LifeSource(tmp_path, clock=lambda: 50.0 * GEN_SECONDS).world()
    assert fresh["generation"] == 0


def test_the_synthetic_world_is_reproducible_and_writes_nothing(tmp_path,
                                                                monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert SyntheticLifeSource().world() == SyntheticLifeSource().world()
    assert list(tmp_path.iterdir()) == []
