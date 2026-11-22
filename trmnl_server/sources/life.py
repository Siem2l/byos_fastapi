"""Conway's Game of Life, kept running between panel refreshes.

The panel looks once every few minutes, so the world is advanced by the
time that has passed since the last look (`GEN_SECONDS` per generation),
not by one step per frame. Each frame is then a time-lapse: the board as
it is now, plus a trail of every cell that was alive since the previous
frame, which is what makes a glider's path readable on a still image.

The board is a torus held as one Python int per row, `W` bits wide. A
generation is a bit-sliced neighbour count over the eight shifted rows,
so catching up a few hours after downtime costs milliseconds, not the
seconds a cell-by-cell loop would.

A world ends when it dies out, settles into a loop short enough to see
(`LOOKBACK`), or goes quiet — a few gliders circling a torus never repeat
within any useful window, but they are not worth watching for a week.
The next world starts straight away and the old one is remembered for
one line on the panel.
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
import zlib
from pathlib import Path

W, H = 150, 64
MASK = (1 << W) - 1

# Thirty generations per five-minute refresh: enough movement between
# frames to leave a trail, slow enough that an acorn's ~5,000 generations
# unfold over most of a day instead of in one look.
GEN_SECONDS = 10
# After downtime, catch up at most this far (about four hours) rather
# than fast-forwarding a week in one request.
MAX_CATCH_UP = 1500
# A state seen again within this many generations is a loop: still lifes
# (period 1), blinkers (2), pulsars (3) and the like.
LOOKBACK = 120
# Fewer changed cells than this per generation, for this many
# generations in a row, and the world is called quiet.
QUIET_CELLS = 12
QUIET_GENS = 600
# Population samples kept for the sparkline, one per advance.
HISTORY = 96

STATE_VERSION = 1

# Plaintext patterns, `O` alive. Chosen for long, varied lives: the acorn
# and the R-pentomino are methuselahs, the gun never stops on its own,
# and rabbits spread across the whole torus before they collide.
PATTERNS = {
    "acorn": [".O.....", "...O...", "OO..OOO"],
    "r-pentomino": [".OO", "OO.", ".O."],
    "rabbits": ["O...OOO", "OOO..O.", ".O....."],
    "glider gun": [
        "........................O...........",
        "......................O.O...........",
        "............OO......OO............OO",
        "...........O...O....OO............OO",
        "OO........O.....O...OO..............",
        "OO........O...O.OO....O.O...........",
        "..........O.....O.......O...........",
        "...........O...O....................",
        "............OO......................",
    ],
}
# Random soups between the named patterns: they are the most varied
# worlds, and the named ones are more fun as an occasional event.
ORDER = ["soup", "acorn", "soup", "r-pentomino", "soup", "glider gun",
         "soup", "rabbits"]
SOUP_DENSITY = 0.3


def step(rows: list[int]) -> list[int]:
    """One generation on the torus."""
    left = [((r << 1) | (r >> (W - 1))) & MASK for r in rows]
    right = [((r >> 1) | (r << (W - 1))) & MASK for r in rows]
    out = []
    for y in range(H):
        above, below = (y - 1) % H, (y + 1) % H
        ones = twos = fours = 0
        for n in (left[above], rows[above], right[above], left[y],
                  right[y], left[below], rows[below], right[below]):
            carry = ones & n
            ones ^= n
            # `fours` is sticky: any count of four or more is death, so
            # there is no need to count past it.
            fours |= twos & carry
            twos ^= carry
        # Alive next: exactly three neighbours, or two and alive now.
        out.append(twos & ~fours & (ones | rows[y]) & MASK)
    return out


def population(rows: list[int]) -> int:
    return sum(r.bit_count() for r in rows)


def _fingerprint(rows: list[int]) -> int:
    return zlib.crc32(b"".join(r.to_bytes((W + 7) // 8, "little")
                               for r in rows))


def place(lines: list[str]) -> list[int]:
    """A pattern centred on an empty board."""
    rows = [0] * H
    top = (H - len(lines)) // 2
    left = (W - max(len(line) for line in lines)) // 2
    for dy, line in enumerate(lines):
        for dx, ch in enumerate(line):
            if ch == "O":
                rows[top + dy] |= 1 << (left + dx)
    return rows


def soup(rng: random.Random) -> list[int]:
    return [sum(1 << x for x in range(W) if rng.random() < SOUP_DENSITY)
            for _ in range(H)]


def new_world(number: int, now: float, rng: random.Random,
              previous: dict | None = None) -> dict:
    seed = ORDER[(number - 1) % len(ORDER)]
    rows = soup(rng) if seed == "soup" else place(PATTERNS[seed])
    return {
        "version": STATE_VERSION,
        "width": W,
        "height": H,
        "world": number,
        "seed": seed,
        "born": now,
        "updated": now,
        "generation": 0,
        "rows": rows,
        "trail": [0] * H,
        "recent": [],
        "quiet": 0,
        "history": [population(rows)],
        "previous": previous,
    }


def _ending(state: dict, rows: list[int]) -> str | None:
    if not any(rows):
        return "died out"
    if _fingerprint(rows) in state["recent"]:
        return "settled"
    if state["quiet"] >= QUIET_GENS:
        return "went quiet"
    return None


def advance(state: dict, now: float, rng: random.Random) -> bool:
    """Bring `state` up to `now` in place. False when nothing changed."""
    steps = int((now - state["updated"]) // GEN_SECONDS)
    if steps <= 0:
        return False
    if steps > MAX_CATCH_UP:
        steps = MAX_CATCH_UP
        state["updated"] = now
    else:
        # Keep the remainder, so a refresh every 290 s does not lose a
        # generation each time and drift slower than the clock.
        state["updated"] += steps * GEN_SECONDS

    rows = state["rows"]
    trail = [0] * H
    recent = state["recent"]
    for _ in range(steps):
        recent.append(_fingerprint(rows))
        del recent[:-LOOKBACK]
        nxt = step(rows)
        changed = sum((a ^ b).bit_count() for a, b in zip(rows, nxt))
        state["quiet"] = state["quiet"] + 1 if changed < QUIET_CELLS else 0
        state["generation"] += 1
        trail = [t | r for t, r in zip(trail, rows)]
        rows = nxt
        reason = _ending(state, rows)
        if reason:
            ended = {"seed": state["seed"], "world": state["world"],
                     "generations": state["generation"], "reason": reason}
            state.clear()
            state.update(new_world(ended["world"] + 1, now, rng, ended))
            return True
    state["rows"] = rows
    state["trail"] = trail
    state["history"] = (state["history"] + [population(rows)])[-HISTORY:]
    return True


def snapshot(state: dict, now: float) -> dict:
    """What the screen draws. A copy, so rendering never sees a half-step."""
    rows = list(state["rows"])
    return {
        "world": state["world"],
        "seed": state["seed"],
        "generation": state["generation"],
        "age_seconds": max(0.0, now - state["born"]),
        "rows": rows,
        "trail": [t & ~r & MASK for t, r in zip(state["trail"], rows)],
        "population": population(rows),
        "history": list(state["history"]),
        "previous": state["previous"],
        "width": W,
        "height": H,
    }


def _encode(state: dict) -> dict:
    out = dict(state)
    out["rows"] = [format(r, "x") for r in state["rows"]]
    out["trail"] = [format(r, "x") for r in state["trail"]]
    return out


def _decode(raw: dict) -> dict | None:
    if (raw.get("version") != STATE_VERSION or raw.get("width") != W
            or raw.get("height") != H):
        return None
    try:
        raw["rows"] = [int(r, 16) & MASK for r in raw["rows"]]
        raw["trail"] = [int(r, 16) & MASK for r in raw["trail"]]
    except (KeyError, TypeError, ValueError):
        return None
    if len(raw["rows"]) != H or len(raw["trail"]) != H:
        return None
    return raw


# The scheduler and an on-request render can both reach `world()` from
# worker threads; without this they would advance the same state twice.
_LOCK = threading.Lock()


class LifeSource:
    """The world on disk, under the server's state directory."""

    def __init__(self, state_dir: str | os.PathLike, *, clock=time.time,
                 rng: random.Random | None = None) -> None:
        self.path = Path(state_dir) / "life.json"
        self.clock = clock
        self.rng = rng or random.Random()

    def world(self) -> dict:
        now = self.clock()
        with _LOCK:
            state = self._load()
            if state is None:
                state = new_world(1, now, self.rng)
                changed = True
            else:
                changed = advance(state, now, self.rng)
            if changed:
                self._save(state)
            return snapshot(state, now)

    def _load(self) -> dict | None:
        try:
            return _decode(json.loads(self.path.read_text()))
        except (OSError, ValueError, AttributeError):
            # Missing or unreadable: a fresh world is the right answer,
            # not a broken screen.
            return None

    def _save(self, state: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(_encode(state)))
        os.replace(tmp, self.path)


class SyntheticLifeSource:
    """A fixed soup a few hours in, computed in memory and never saved.

    Same seed, same clock, same frame: previews and tests diff only when
    the code changes.
    """

    def __init__(self, generations: int = 180) -> None:
        self.generations = generations

    def world(self) -> dict:
        rng = random.Random(1970)
        state = new_world(1, 0.0, rng)
        start = state["generation"]
        now = 0.0
        while state["generation"] - start < self.generations:
            now += GEN_SECONDS * 30
            advance(state, now, rng)
        return snapshot(state, now)
