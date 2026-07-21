"""A stand-in for GarminSource that fabricates plausible data.

Used by `--preview --synthetic` so layouts can be iterated on a machine
with no GarminDB. The numbers are deterministic (seeded) so a rendering
diff between two runs only ever reflects a code change, never noise.
"""

from __future__ import annotations

import random
from datetime import date, timedelta


class SyntheticGarminSource:
    def __init__(self, seed: int = 20260721) -> None:
        self.rng = random.Random(seed)

    def available(self) -> bool:
        return True

    def daily_series(self, days: int = 14, today: date | None = None
                     ) -> list[dict]:
        today = today or date.today()
        start = today - timedelta(days=days - 1)
        out = []
        for i in range(days):
            # Drop one mid-range day entirely to exercise the gap handling
            # in the sparklines — a watch left on the charger overnight.
            missing = i == days - 6
            out.append(
                {
                    "day": (start + timedelta(days=i)).isoformat(),
                    "rhr": None if missing else 50 + self.rng.randint(-3, 5),
                    "stress": None if missing else self.rng.randint(22, 44),
                    "bb_min": None if missing else self.rng.randint(12, 30),
                    "bb_max": None if missing else self.rng.randint(70, 96),
                    "steps": None if missing else self.rng.randint(4000, 15000),
                    "spo2": None if missing else self.rng.randint(93, 98),
                    "respiration": None if missing else round(
                        self.rng.uniform(12.0, 15.5), 1
                    ),
                    "intensity_minutes": 0 if missing else self.rng.choice(
                        [0, 0, 22, 35, 48, 61, 90]
                    ),
                }
            )
        return out

    def hrv_series(self, days: int = 14, today: date | None = None
                   ) -> list[float | None]:
        return [
            None if i == days - 6 else 40 + self.rng.randint(-8, 12)
            for i in range(days)
        ]

    def sleep_series(self, days: int = 14, today: date | None = None
                     ) -> list[float | None]:
        return [
            None if i == days - 6 else 360 + self.rng.randint(-70, 90)
            for i in range(days)
        ]

    def last_sleep(self, today: date | None = None) -> dict:
        deep, rem, awake = 62.0, 78.0, 19.0
        light = 434.0 - deep - rem - awake
        return {
            "day": (today or date.today()).isoformat(),
            "total": 434.0,
            "deep": deep,
            "light": light,
            "rem": rem,
            "awake": awake,
            "score": 84,
            "qualifier": "good",
        }

    def recent_activities(self, limit: int = 3, today: date | None = None
                          ) -> list[dict]:
        pool = [
            {"name": "Morning Ride", "sport": "cycling", "minutes": 84.0,
             "distance": 41.2, "avg_hr": 142},
            {"name": "Threshold Intervals", "sport": "running",
             "minutes": 52.0, "distance": 10.4, "avg_hr": 168},
            {"name": "Easy Walk", "sport": "walking", "minutes": 38.0,
             "distance": 3.6, "avg_hr": 96},
        ]
        return pool[:limit]
