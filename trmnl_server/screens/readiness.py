"""Morning readiness — body battery, HRV, resting HR, sleep, 7-day load."""

from __future__ import annotations

from datetime import date, datetime

from ..canvas import Box, Canvas
from .base import Context, Screen, register

DAYS = 14
LOAD_DAYS = 7


def _mean(values) -> float | None:
    pts = [v for v in values if v is not None]
    return sum(pts) / len(pts) if pts else None


def _hm(minutes: float | None) -> str:
    if not minutes:
        return "--"
    return f"{int(minutes // 60)}h{int(minutes % 60):02d}"


def _latest(values) -> tuple[object, int | None]:
    """Most recent non-null value and its index, scanning backwards.

    Today's row does not exist until Garmin has synced, and it never
    arrives at all while the importer is down. Reading `values[-1]`
    blanks the headline numbers in both cases while the sparklines below
    them stay full, which reads as a rendering bug rather than as missing
    data. Fall back to the freshest reading actually on hand and let the
    header disclose how old it is.
    """
    for i in range(len(values) - 1, -1, -1):
        if values[i] is not None:
            return values[i], i
    return None, None


@register
class ReadinessScreen(Screen):
    slug = "readiness"
    title = "Morning readiness"
    # Garmin's overnight metrics land once, shortly after wake. Polling
    # faster than this just burns battery redrawing identical pixels.
    refresh_seconds = 1800

    def fetch(self, ctx: Context) -> dict:
        garmin = ctx.source("garmin")
        today = date.today()
        daily = garmin.daily_series(DAYS, today)
        hrv = garmin.hrv_series(DAYS, today)
        sleep = garmin.last_sleep(today)

        rhr_series = [d["rhr"] for d in daily]
        bb_series = [d["bb_max"] for d in daily]
        bb, bb_i = _latest(bb_series)
        hrv_now, hrv_i = _latest(hrv)
        rhr_now, rhr_i = _latest(rhr_series)

        # Baselines exclude the reading they are compared against, so the
        # arrow measures today against its own history rather than partly
        # against itself.
        freshest = max(
            (i for i in (bb_i, hrv_i, rhr_i) if i is not None), default=None
        )
        return {
            "today": today,
            "generated_at": datetime.now(),
            "data_day": daily[freshest]["day"] if freshest is not None else None,
            "body_battery": bb,
            "body_battery_low": (
                daily[bb_i]["bb_min"] if bb_i is not None else None
            ),
            "bb_series": bb_series,
            "hrv": hrv_now,
            "hrv_baseline": _mean(hrv[:hrv_i][-7:]) if hrv_i else None,
            "hrv_series": hrv,
            "rhr": rhr_now,
            "rhr_baseline": (
                _mean(rhr_series[:rhr_i][-7:]) if rhr_i else None
            ),
            "rhr_series": rhr_series,
            "sleep": sleep,
            "sleep_series": garmin.sleep_series(DAYS, today),
            "load_series": [d["intensity_minutes"] or 0 for d in daily][
                -LOAD_DAYS:
            ],
            "load_days": [d["day"] for d in daily][-LOAD_DAYS:],
        }

    # ---- rendering ------------------------------------------------------

    def render(self, c: Canvas, d: dict) -> None:
        self._header(c, d)
        self._metrics(c, Box(0, 62, c.width, 168), d)
        self._sleep(c, Box(0, 236, c.width, 116), d)
        self._load(c, Box(0, 360, c.width, 120), d)

    def _header(self, c: Canvas, d: dict) -> None:
        today: date = d["today"]
        c.text(24, 16, today.strftime("%a %d %b").upper(), size=30, bold=True,
               tracking=2)
        stamp = d["generated_at"].strftime("%H:%M")
        note = f"UPDATED {stamp}"

        # Showing a stale reading without saying so is worse than showing
        # nothing: the number looks like this morning's. Name the day the
        # data actually came from whenever it is not today.
        data_day = d.get("data_day")
        if data_day and data_day != today.isoformat():
            age = (today - date.fromisoformat(data_day)).days
            note = (
                f"DATA {date.fromisoformat(data_day).strftime('%d %b').upper()}"
                f" · {age}D OLD"
            )
        c.text(c.width - 24, 24, note, size=13, bold=True,
               anchor="ra", tracking=1)
        c.hline(24, 54, c.width - 24, weight=3)

    def _metrics(self, c: Canvas, box: Box, d: dict) -> None:
        # Deliberately unequal: body battery is the one number that answers
        # "how much have I got today", so it gets roughly half the row and a
        # larger face. The other two are supporting evidence.
        inner = Box(box.x + 24, box.y, box.w - 48, box.h)
        hero = Box(inner.x, inner.y, 262, inner.h)
        rest = Box(hero.right + 26, inner.y, inner.right - hero.right - 26,
                   inner.h)
        cols = rest.split_h(2, gap=26)

        self._metric(
            c, hero, "Body battery",
            value=d["body_battery"], unit="",
            series=d["bb_series"],
            footnote=f"drained to {d['body_battery_low']} overnight"
            if d["body_battery_low"] is not None else None,
            size=76, spark_h=42,
        )
        self._metric(
            c, cols[0], "HRV last night",
            value=d["hrv"], unit="ms",
            series=d["hrv_series"], baseline=d["hrv_baseline"],
        )
        self._metric(
            c, cols[1], "Resting HR",
            value=d["rhr"], unit="bpm",
            series=d["rhr_series"], baseline=d["rhr_baseline"],
        )

        c.vline(hero.right + 12, box.y + 6, box.bottom - 14)
        c.vline(cols[1].x - 13, box.y + 6, box.bottom - 14)

    def _metric(
        self,
        c: Canvas,
        box: Box,
        label: str,
        *,
        value,
        unit: str,
        series,
        baseline: float | None = None,
        footnote: str | None = None,
        size: int = 62,
        spark_h: int = 40,
    ) -> None:
        c.label(box.x, box.y + 6, label)

        shown = "--" if value is None else f"{round(value):g}"
        c.text(box.x, box.y + 22, shown, size=size, bold=True)
        num_w = c.text_width(shown, size=size, bold=True)
        if unit:
            c.text(box.x + num_w + 8, box.y + size, unit, size=17, bold=True)

        # The comparison line reads as prose rather than a floating arrow —
        # direction is shown but never judged, because "good" is
        # metric-dependent (HRV up is good, resting HR up is not).
        sub_y = box.y + size + 26
        if baseline is not None and value is not None:
            diff = round(value - baseline)
            w = c.delta(box.x, sub_y, diff, size=14)
            c.text(box.x + w + 8, sub_y, f"vs base {round(baseline)}", size=14)
        elif footnote:
            c.text(box.x, sub_y, footnote, size=14)

        c.sparkline(
            Box(box.x, box.bottom - spark_h, box.w, spark_h),
            series, baseline=baseline,
        )

    def _sleep(self, c: Canvas, box: Box, d: dict) -> None:
        c.hline(24, box.y, c.width - 24, weight=1)
        sleep = d["sleep"]
        c.label(24, box.y + 14, "Sleep")

        if not sleep:
            c.text(24, box.y + 40, "no data", size=28, bold=True)
            return

        c.text(24, box.y + 34, _hm(sleep["total"]), size=42, bold=True)
        total_w = c.text_width(_hm(sleep["total"]), size=42, bold=True)
        if sleep.get("score") is not None:
            c.text(24 + total_w + 22, box.y + 52, f"score {sleep['score']}",
                   size=17, bold=True)

        # A fortnight of nightly totals against their own mean, so one good
        # night after a bad week cannot masquerade as being rested. Left
        # uncaptioned to match the sparklines in the row above.
        c.sparkline(
            Box(320, box.y + 32, 300, 44), d["sleep_series"],
            baseline=_mean(d["sleep_series"]),
        )

        bar = Box(24, box.y + 86, c.width - 48, 20)
        c.stacked_bar(
            bar,
            [
                (sleep["deep"] or 0, "solid"),
                (sleep["light"] or 0, "dense"),
                (sleep["rem"] or 0, "sparse"),
                # Awake is left blank on purpose: a gap in the bar is the
                # most literal possible rendering of not being asleep.
                (sleep["awake"] or 0, "empty"),
            ],
        )

        # Legend rides the section-header row, right-aligned, so it reads as
        # a caption for the whole block rather than competing with the total.
        legend = [
            ("deep", sleep["deep"]),
            ("light", sleep["light"]),
            ("rem", sleep["rem"]),
            ("awake", sleep["awake"]),
        ]
        x = c.width - 24
        for name, minutes in reversed(legend):
            chunk = f"{name} {_hm(minutes)}"
            x -= c.text_width(chunk, size=13, bold=True)
            c.text(x, box.y + 14, chunk, size=13, bold=True)
            x -= 20

    def _load(self, c: Canvas, box: Box, d: dict) -> None:
        c.hline(24, box.y, c.width - 24, weight=1)
        c.label(24, box.y + 14, f"{LOAD_DAYS}-day load")

        series = d["load_series"]
        total = round(sum(series))
        hard = sum(1 for v in series if v >= 45)

        c.text(24, box.y + 36, f"{total}", size=42, bold=True)
        total_w = c.text_width(f"{total}", size=42, bold=True)
        c.text(24 + total_w + 10, box.y + 56, "intensity min", size=15,
               bold=True)
        c.text(24, box.y + 88, f"{hard} hard {'day' if hard == 1 else 'days'}",
               size=13)

        chart = Box(c.width - 24 - 330, box.y + 24, 330, 56)
        c.bars(chart, series, gap=8)
        c.hline(chart.x, chart.bottom + 2, chart.right, weight=1)

        # Weekday initials under each bar — without them a bar chart of
        # "the last seven days" gives no way to tell which day was hard.
        width = (chart.w - 8 * (len(series) - 1)) // len(series)
        for i, iso in enumerate(d["load_days"]):
            initial = date.fromisoformat(iso).strftime("%a")[0]
            c.text(chart.x + i * (width + 8) + width // 2, chart.bottom + 8,
                   initial, size=12, bold=True, anchor="ma")
