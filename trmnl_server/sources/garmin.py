"""Read-only access to the SQLite databases GarminDB maintains.

GarminDB splits its data across four files; this only touches two:

    garmin.db            daily_summary, sleep, hrv, weight, stress
    garmin_activities.db activities

Every connection is opened read-only via a file: URI so a running
`garmindb` import can never be blocked or corrupted by this process. The
service also only ever holds the group-read bit on those files.
"""

from __future__ import annotations

import sqlite3
from datetime import date, timedelta
from pathlib import Path
from typing import Any


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def _hhmmss_to_minutes(value: Any) -> float | None:
    """GarminDB stores durations as 'HH:MM:SS' strings, not intervals."""
    if not value:
        return None
    parts = str(value).split(":")
    try:
        h, m, s = (float(p) for p in (parts + ["0", "0"])[:3])
    except ValueError:
        return None
    return h * 60 + m + s / 60


class GarminSource:
    def __init__(self, db_dir: str | Path) -> None:
        self.db_dir = Path(db_dir)
        self.main = self.db_dir / "garmin.db"
        self.activities = self.db_dir / "garmin_activities.db"

    def available(self) -> bool:
        return self.main.exists()

    # ---- daily metrics --------------------------------------------------

    def daily_series(self, days: int = 14, today: date | None = None
                     ) -> list[dict]:
        """One row per calendar day, oldest first, gaps filled with None.

        Filling the gaps matters for the sparklines: a missing day has to
        break the line rather than silently compress the x-axis and imply
        continuity that was not measured.
        """
        today = today or date.today()
        start = today - timedelta(days=days - 1)
        with _connect(self.main) as conn:
            rows = conn.execute(
                """
                SELECT day, rhr, stress_avg, bb_min, bb_max, steps,
                       spo2_avg, rr_waking_avg, hr_min,
                       moderate_activity_time, vigorous_activity_time
                  FROM daily_summary
                 WHERE day BETWEEN ? AND ?
                 ORDER BY day
                """,
                (start.isoformat(), today.isoformat()),
            ).fetchall()
        by_day = {str(r["day"])[:10]: dict(r) for r in rows}
        out = []
        for i in range(days):
            d = (start + timedelta(days=i)).isoformat()
            row = by_day.get(d, {})
            out.append(
                {
                    "day": d,
                    "rhr": row.get("rhr"),
                    "stress": row.get("stress_avg"),
                    "bb_min": row.get("bb_min"),
                    "bb_max": row.get("bb_max"),
                    "steps": row.get("steps"),
                    "spo2": row.get("spo2_avg"),
                    "respiration": row.get("rr_waking_avg"),
                    "intensity_minutes": (
                        _hhmmss_to_minutes(row.get("moderate_activity_time")) or 0
                    )
                    + 2
                    * (
                        _hhmmss_to_minutes(row.get("vigorous_activity_time")) or 0
                    ),
                }
            )
        return out

    def hrv_series(self, days: int = 14, today: date | None = None
                   ) -> list[float | None]:
        today = today or date.today()
        start = today - timedelta(days=days - 1)
        with _connect(self.main) as conn:
            rows = conn.execute(
                """
                SELECT day, last_night_avg
                  FROM hrv
                 WHERE day BETWEEN ? AND ?
                 ORDER BY day
                """,
                (start.isoformat(), today.isoformat()),
            ).fetchall()
        by_day = {str(r["day"])[:10]: r["last_night_avg"] for r in rows}
        return [
            by_day.get((start + timedelta(days=i)).isoformat())
            for i in range(days)
        ]

    def sleep_series(self, days: int = 14, today: date | None = None
                     ) -> list[float | None]:
        """Total sleep in minutes per night, oldest first."""
        today = today or date.today()
        start = today - timedelta(days=days - 1)
        with _connect(self.main) as conn:
            rows = conn.execute(
                """
                SELECT day, total_sleep
                  FROM sleep
                 WHERE day BETWEEN ? AND ?
                 ORDER BY day
                """,
                (start.isoformat(), today.isoformat()),
            ).fetchall()
        by_day = {
            str(r["day"])[:10]: _hhmmss_to_minutes(r["total_sleep"])
            for r in rows
        }
        return [
            by_day.get((start + timedelta(days=i)).isoformat())
            for i in range(days)
        ]

    def last_sleep(self, today: date | None = None) -> dict | None:
        today = today or date.today()
        with _connect(self.main) as conn:
            row = conn.execute(
                """
                SELECT day, total_sleep, deep_sleep, light_sleep, rem_sleep,
                       awake, score, qualifier
                  FROM sleep
                 WHERE day <= ? AND total_sleep IS NOT NULL
                 ORDER BY day DESC
                 LIMIT 1
                """,
                (today.isoformat(),),
            ).fetchone()
        if row is None:
            return None
        return {
            "day": str(row["day"])[:10],
            "total": _hhmmss_to_minutes(row["total_sleep"]),
            "deep": _hhmmss_to_minutes(row["deep_sleep"]),
            "light": _hhmmss_to_minutes(row["light_sleep"]),
            "rem": _hhmmss_to_minutes(row["rem_sleep"]),
            "awake": _hhmmss_to_minutes(row["awake"]),
            "score": row["score"],
            "qualifier": row["qualifier"],
        }

    def recent_activities(self, limit: int = 3, today: date | None = None
                          ) -> list[dict]:
        if not self.activities.exists():
            return []
        with _connect(self.activities) as conn:
            rows = conn.execute(
                """
                SELECT name, sport, start_time, elapsed_time, distance,
                       calories, avg_hr
                  FROM activities
                 ORDER BY start_time DESC
                 LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                "name": r["name"],
                "sport": r["sport"],
                "start": str(r["start_time"]),
                "minutes": _hhmmss_to_minutes(r["elapsed_time"]),
                "distance": r["distance"],
                "avg_hr": r["avg_hr"],
            }
            for r in rows
        ]
