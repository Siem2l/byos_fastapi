"""Stand-ins for the real sources, fabricating plausible data.

Used by `--preview --synthetic` so layouts can be iterated on a machine
with no GarminDB, no Prometheus and no network. The numbers are
deterministic (seeded) so a rendering diff between two runs only ever
reflects a code change, never noise.
"""

from __future__ import annotations

import random
from datetime import date, timedelta

from .prometheus import Sample


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


# The scrape targets the fake homelab exposes, as (job, instance) pairs.
# Built to the shape of the real one — a single node exporter, a large
# blackbox job probing public URLs, and one target per self-hosted
# service — because the target grid's job is to make an outage in a set
# of this size visible, and it has to be laid out against a realistic
# count to be worth looking at.
_SYNTHETIC_JOBS: list[tuple[str, str]] = (
    [("node", "127.0.0.1:9002")]
    + [
        ("blackbox-http", f"https://{name}.siem2l.nl/")
        for name in (
            "assets", "grafana", "prometheus", "alertmanager", "auth",
            "vault", "git", "ci", "wiki", "photos", "music", "books",
            "budget", "recipes", "notes", "paperless", "immich", "nextcloud",
            "jellyfin", "sonarr", "radarr", "bazarr", "prowlarr", "qbit",
            "home", "matrix", "ntfy", "uptime", "mail", "dns", "vpn",
            "search", "rss", "read", "share", "status", "hive", "chat",
        )
    ]
    + [
        (job, f"127.0.0.1:{port}")
        for job, port in (
            ("blackbox-exporter", 9115), ("crowdsec", 6060),
            ("actual-budget", 9189), ("litellm", 8888),
            ("flaresolverr", 8192), ("maigret-runner", 8080),
            ("hivemind", 8830), ("trmnl", 8095),
        )
    ]
)

# What is broken in the non-calm scenario. Named rather than picked at
# random so the preview is stable across runs and the hollow cells land
# in the same places every time.
#
# Two *different* faults, deliberately: an exporter that stopped
# answering (`up == 0`) and a public site that answers the probe with a
# failure while its blackbox scrape stays perfectly healthy
# (`probe_success == 0`, `up == 1`). Those are the two things the top
# band's two grids separate, and a preview where the same host is
# broken in both would make the distinction invisible.
_SYNTHETIC_DOWN = "127.0.0.1:8830"
_SYNTHETIC_PROBE_DOWN = "https://immich.siem2l.nl/"

# (mountpoint, device, size bytes, free bytes). Ordered so the join in
# `screens/homelab.py` has to do the sorting, not this table.
# Today's spend, in one place because two answers have to agree: the
# headline instant and the last bar of the 14-day history.
SYNTHETIC_COST_TODAY = 18.42

_SYNTHETIC_FILESYSTEMS = [
    ("/", "/dev/disk/by-label/nixos", 500 << 30, 92 << 30),
    ("/boot", "/dev/disk/by-label/boot", 1 << 30, 780 << 20),
    ("/mnt/storage", "storage", 8 << 40, 660 << 30),
    ("/mnt/backup", "backup", 4 << 40, 1229 << 30),
]


class SyntheticPrometheusSource:
    """A stand-in for PrometheusSource, answering the queries the screens ask.

    Keyed on the literal PromQL string, and a query this table has never
    heard of comes back **empty** rather than fabricated. That is the
    honest default: a screen asking for a metric this table does not know
    should show exactly the empty state it would show against a real
    Prometheus that does not export it, so a typo in a PromQL string is
    visible in the preview instead of hidden behind a plausible number.
    `tests/test_screens.py` walks a real `fetch()` and asserts every
    query a screen issues is answered here, which is what stops the two
    drifting apart.

    `calm` chooses between the two shapes worth looking at. The default
    is a homelab with something wrong in it — a target down, alerts
    firing, a filesystem past its threshold — because those are the
    branches that can collide or overflow, and so the ones a layout pass
    has to see. `calm=True` is the state the panel is actually in almost
    all of the time, and it is the one that must not look like a bug.
    """

    def __init__(self, seed: int = 20260721, *, calm: bool = False) -> None:
        self.seed = seed
        self.calm = calm

    def available(self) -> bool:
        return True

    # ---- the same three methods PrometheusSource offers ------------------

    def instant(self, query: str) -> float | None:
        samples = self.vector(query)
        return samples[0].value if samples else None

    def vector(self, query: str) -> list[Sample]:
        return list(self._table().get(query, []))

    def series(self, query: str, *, minutes: int = 60, points: int = 60
               ) -> list[float | None]:
        from ..screens import homelab as hl
        from ..screens import stats as st

        # Seeded per query, not per instance: asking the same question
        # twice in one render gives the same answer, and a second run of
        # the same preview is byte-identical to the first.
        rng = random.Random(f"{self.seed}:{query}")
        if query == hl.Q_LOAD:
            return _load_series(rng, points, calm=self.calm)
        if query == st.Q_COST_DAILY:
            return _daily_cost(rng, points)
        return [None] * points

    # ---- the answers -----------------------------------------------------

    def _table(self) -> dict[str, list[Sample]]:
        from ..screens import homelab as hl
        from ..screens import stats as st

        down = () if self.calm else (_SYNTHETIC_DOWN,)
        probe_down = () if self.calm else (_SYNTHETIC_PROBE_DOWN,)
        targets = [
            Sample({"job": job, "instance": instance},
                   0.0 if instance in down else 1.0)
            for job, instance in _SYNTHETIC_JOBS
        ]
        probes = [
            Sample({"job": "blackbox-http", "instance": instance},
                   0.0 if instance in probe_down else 1.0)
            for job, instance in _SYNTHETIC_JOBS
            if job == "blackbox-http"
        ]

        alerts: list[Sample] = []
        failed: list[Sample] = []
        if not self.calm:
            alerts = [
                Sample({"alertname": "DiskFillingUp", "severity": "warning",
                        "instance": "127.0.0.1:9002",
                        "mountpoint": "/mnt/storage"}, 1.0),
                Sample({"alertname": "PublicTunnelEndpointDown",
                        "severity": "critical",
                        "instance": _SYNTHETIC_PROBE_DOWN}, 1.0),
            ]
            failed = [Sample({"name": "actual-ai.service",
                              "state": "failed"}, 1.0)]

        table: dict[str, list[Sample]] = {
            hl.Q_TARGETS: targets,
            hl.Q_PROBES: probes,
            hl.Q_ALERTS: alerts,
            hl.Q_FAILED_UNITS: failed,
            # The instant reading is the newest point of the sparkline
            # beside it, not an independent number: "3.87" over a chart
            # whose peak is captioned 3.76 reads as a rendering bug, and
            # a preview that looks broken cannot be used to judge one.
            hl.Q_LOAD: [Sample({}, _latest(
                self.series(hl.Q_LOAD, points=hl.LOAD_POINTS)
            ))],
            hl.Q_FS_AVAIL: [
                Sample({"instance": "127.0.0.1:9002", "device": device,
                        "mountpoint": mount}, float(free))
                for mount, device, _size, free in _SYNTHETIC_FILESYSTEMS
            ],
            hl.Q_FS_SIZE: [
                Sample({"instance": "127.0.0.1:9002", "device": device,
                        "mountpoint": mount}, float(size))
                for mount, device, size, _free in _SYNTHETIC_FILESYSTEMS
            ],
            st.Q_TOKENS_TODAY: _typed({
                "input": 412_000, "output": 96_400,
                "cache_creation": 1_840_000, "cache_read": 22_400_000,
            }),
            st.Q_COST_TODAY: [Sample({}, SYNTHETIC_COST_TODAY)],
            st.Q_TOKENS_TOTAL: _typed({
                "input": 9_420_000, "output": 2_180_000,
                "cache_creation": 41_300_000, "cache_read": 512_600_000,
            }),
            st.Q_COST_TOTAL: [Sample({}, 1204.55)],
            st.Q_BLOCK_TOKENS: [Sample({}, 3_120_000.0)],
            st.Q_BLOCK_COST: [Sample({}, 4.10)],
            st.Q_BLOCK_REMAINING: [Sample({}, 134.0)],
            st.Q_BLOCK_PROJECTED: [Sample({}, 5_400_000.0)],
            st.Q_DATA_READY: [Sample({}, 1.0)],
            # Two and a half minutes old: inside the staleness threshold,
            # so the header shows a clock. The stale branch is exercised
            # in the tests rather than here, because a preview that
            # always claimed to be stale would train the eye to ignore
            # the warning.
            st.Q_STALENESS: [Sample({}, 152.0)],
        }
        return table


def _typed(values: dict[str, float]) -> list[Sample]:
    return [Sample({"type": key}, float(value)) for key, value in values.items()]


def _latest(series: list[float | None]) -> float:
    """The newest reading in `series`, scanning back past any gap."""
    for value in reversed(series):
        if value is not None:
            return value
    return 0.0


def _load_series(rng: random.Random, points: int, *, calm: bool
                 ) -> list[float | None]:
    """An hour of load average with one scrape missing.

    The gap is deliberate: `Canvas.sparkline` breaks its line on None,
    and a preview that never contains a gap cannot show whether that
    still works.
    """
    high = 1.8 if calm else 3.9
    out: list[float | None] = [
        round(rng.uniform(0.4, high), 2) for _ in range(points)
    ]
    if points > 12:
        out[points // 3] = None
    return out


def _daily_cost(rng: random.Random, points: int) -> list[float | None]:
    """A fortnight of daily spend, with the quiet days genuinely quiet.

    The last point is pinned to the same figure `claude_code_cost_usd_today`
    reports. A preview whose headline says $18 while the rightmost bar of
    its own history says zero is worse than useless for judging a layout:
    every look at it is spent wondering which number is the bug.
    """
    out: list[float | None] = [
        0.0 if rng.random() < 0.15 else round(rng.uniform(1.5, 31.0), 2)
        for _ in range(points)
    ]
    if out:
        out[-1] = SYNTHETIC_COST_TODAY
    return out
