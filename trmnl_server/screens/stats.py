"""Claude Code usage — today's tokens and spend, the live 5h block, 14 days.

The vanity screen. Everything on it comes from one exporter: the
ccusage textfile collector, which runs `ccusage` every five minutes and
writes `claude_code_*` into node_exporter's textfile directory. Those
metric names are the reason this screen shows what it shows — see the
report accompanying this change for the things it deliberately does
*not* show, because nothing in this homelab exports them.

Two states get first-class treatment rather than a dash, because both
are ordinary:

* **No active 5h block.** ccusage emits the four `claude_code_block_*`
  series only while a block is running, so between sessions they are
  simply absent. That is "not working right now", not "the exporter is
  broken", and the band says so.
* **A stale exporter.** The timer can fire while the script fails (this
  is what the `CcusageStale` alert watches for). Numbers that are hours
  old look exactly like fresh ones unless the screen says otherwise, so
  the header names the age instead of the time whenever the last
  refresh is old — the same rule the readiness screen applies to a
  Garmin sync that has not happened.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta

from ..canvas import Box, Canvas
from ..sources.prometheus import Probe, Sample
from .base import Context, Screen, register

MARGIN = 24

# Days of history in the bottom-left bar chart.
DAYS = 14

# The `CcusageStale` alert fires at 30 minutes, so the panel starts
# disclosing staleness at the same moment. Below it, the header shows a
# clock; above it, an age.
STALE_AFTER = 1800

# The token classes ccusage reports, in the order they are stacked, with
# the hatch each gets. Cache reads are deliberately absent: they are
# routinely 90%+ of the total, and including them would squash the three
# classes that vary into an unreadable sliver. They are reported as a
# number beside the bar instead, which is where a share that large
# belongs anyway.
BAR_TYPES = [
    ("input", "solid", "input"),
    ("output", "dense", "output"),
    ("cache_creation", "sparse", "cache write"),
]

# --- PromQL ----------------------------------------------------------------
#
# Module constants for the same reason as in `homelab.py`: the synthetic
# stand-in answers exactly these strings and a test holds it to that.

Q_TOKENS_TODAY = "claude_code_tokens_today"
Q_COST_TODAY = "claude_code_cost_usd_today"
Q_TOKENS_TOTAL = "claude_code_tokens_total"
Q_COST_TOTAL = "claude_code_cost_usd_total"
Q_BLOCK_TOKENS = "claude_code_block_tokens"
Q_BLOCK_COST = "claude_code_block_cost_usd"
Q_BLOCK_REMAINING = "claude_code_block_remaining_minutes"
Q_BLOCK_PROJECTED = "claude_code_block_projected_tokens"
Q_DATA_READY = "claude_code_data_ready"
Q_STALENESS = "time() - claude_code_exporter_last_refresh_seconds"

# `claude_code_cost_usd_today` is a gauge that resets at midnight, so the
# peak it reached inside a trailing day is that day's final total.
# Sampled at exactly 86400 s steps (see `points=DAYS + 1` below), which
# is what makes each bar one day wide.
Q_COST_DAILY = f"max_over_time({Q_COST_TODAY}[1d])"


def _by_type(samples: list[Sample]) -> dict[str, float]:
    return {s.label("type"): s.value for s in samples}


def _tokens(value: float | None) -> str:
    if value is None:
        return "--"
    for unit, scale in (("B", 1e9), ("M", 1e6), ("k", 1e3)):
        if value >= scale:
            scaled = value / scale
            return f"{scaled:.0f}{unit}" if scaled >= 100 else f"{scaled:.1f}{unit}"
    return f"{value:.0f}"


def _money(value: float | None) -> str:
    if value is None:
        return "--"
    return f"${value:,.0f}" if value >= 100 else f"${value:.2f}"


def _hm(minutes: float | None) -> str:
    if minutes is None:
        return "--"
    total = int(round(minutes))
    return f"{total // 60}h{total % 60:02d}m" if total >= 60 else f"{total}m"


@register
class StatsScreen(Screen):
    slug = "stats"
    title = "Claude Code usage"
    # The exporter refreshes every five minutes; ten is a fair trade
    # between a live-looking block gauge and not spending an e-ink
    # refresh on a number that moved by a rounding error.
    refresh_seconds = 600

    def fetch(self, ctx: Context) -> dict:
        probe = Probe(ctx.source("prometheus"))

        today = _by_type(probe.vector(Q_TOKENS_TODAY))
        lifetime = _by_type(probe.vector(Q_TOKENS_TOTAL))
        cost_today = probe.instant(Q_COST_TODAY)
        cost_total = probe.instant(Q_COST_TOTAL)
        block = {
            "tokens": probe.instant(Q_BLOCK_TOKENS),
            "cost": probe.instant(Q_BLOCK_COST),
            "remaining": probe.instant(Q_BLOCK_REMAINING),
            "projected": probe.instant(Q_BLOCK_PROJECTED),
        }
        ready = probe.instant(Q_DATA_READY)
        staleness = probe.instant(Q_STALENESS)
        # DAYS + 1 points over DAYS days is what pins the step to exactly
        # 86400 s; the oldest point is dropped so the chart is DAYS bars
        # wide and its rightmost bar is the day in progress.
        daily_cost = probe.series(
            Q_COST_DAILY, minutes=DAYS * 1440, points=DAYS + 1
        )[-DAYS:]

        probe.check()

        anchor = date.today()
        return {
            "generated_at": datetime.now(),
            "staleness": staleness,
            # `claude_code_data_ready` is 0 when the exporter ran but
            # found no transcripts at all — a fresh machine, or a Claude
            # config directory that moved. Distinct from every series
            # being absent, which means the exporter itself is missing.
            "data_ready": ready,
            "today": today,
            "today_total": sum(today.values()) if today else None,
            "cost_today": cost_today,
            "lifetime": lifetime,
            "lifetime_total": sum(lifetime.values()) if lifetime else None,
            "cost_total": cost_total,
            "block": block,
            "daily_cost": [0.0 if v is None else v for v in daily_cost],
            "daily_days": [
                (anchor - timedelta(days=DAYS - 1 - i)).isoformat()
                for i in range(DAYS)
            ],
        }

    # ---- rendering ------------------------------------------------------

    def render(self, c: Canvas, d: dict) -> None:
        self._header(c, d)
        self._today(c, Box(0, 64, c.width, 150), d)
        self._block(c, Box(0, 230, c.width, 90), d)
        self._history(c, Box(0, 336, c.width, 134), d)

    def _header(self, c: Canvas, d: dict) -> None:
        c.text(MARGIN, 16, "CLAUDE CODE", size=30, bold=True, tracking=2)

        # An hours-old number is indistinguishable from a live one unless
        # the header admits it, and this exporter's failure mode is
        # exactly that: the timer keeps firing, the script keeps failing,
        # the last good file stays on disk.
        staleness = d["staleness"]
        if staleness is not None and staleness > STALE_AFTER:
            note = f"DATA {_hm(staleness / 60)} OLD"
        else:
            note = f"UPDATED {d['generated_at'].strftime('%H:%M')}"
        c.text(c.width - MARGIN, 24, note, size=13, bold=True, anchor="ra",
               tracking=1)
        c.hline(MARGIN, 54, c.width - MARGIN, weight=3)

    # -- today ------------------------------------------------------------

    def _today(self, c: Canvas, box: Box, d: dict) -> None:
        c.label(MARGIN, box.y + 6, "Today")
        c.text(c.width - MARGIN, box.y + 6, "SPENT", size=13, bold=True,
               anchor="ra", tracking=1)

        total = d["today_total"]
        shown = _tokens(total)
        c.text(MARGIN, box.y + 20, shown, size=56, bold=True)
        width = c.text_width(shown, size=56, bold=True)
        c.text(MARGIN + width + 10, box.y + 54, "tokens", size=18, bold=True)
        c.text(c.width - MARGIN, box.y + 20, _money(d["cost_today"]), size=44,
               bold=True, anchor="ra")

        if not total:
            reason = (
                "ccusage found no transcripts"
                if d["data_ready"] == 0
                else "nothing logged today yet"
            )
            c.text(MARGIN, box.y + 92, reason, size=18)
            return

        segments = [
            (d["today"].get(key, 0.0), shade) for key, shade, _ in BAR_TYPES
        ]
        c.stacked_bar(Box(MARGIN, box.y + 86, c.width - 2 * MARGIN, 24), segments)

        # Swatches rather than a colour key, because there are no
        # colours: each legend entry carries the literal hatch its
        # segment is drawn with, so the two can be matched by eye.
        x = MARGIN
        for key, shade, name in BAR_TYPES:
            c.rect(Box(x, box.y + 120, 13, 13))
            c.fill(Box(x + 1, box.y + 121, 11, 11), shade=shade)
            chunk = f"{name} {_tokens(d['today'].get(key))}"
            c.text(x + 19, box.y + 120, chunk, size=14)
            x += 19 + c.text_width(chunk, size=14) + 24

        cache_read = d["today"].get("cache_read")
        if cache_read:
            share = cache_read / (total or 1) * 100
            c.text(
                c.width - MARGIN, box.y + 120,
                f"cache read {_tokens(cache_read)} · {share:.0f}% of all tokens",
                size=14, anchor="ra",
            )

    # -- the live 5h block ------------------------------------------------

    def _block(self, c: Canvas, box: Box, d: dict) -> None:
        c.hline(MARGIN, box.y - 8, c.width - MARGIN, weight=1)
        c.label(MARGIN, box.y, "Active 5h block")

        block = d["block"]
        if block["tokens"] is None:
            # Not a failure: ccusage publishes these four series only
            # while a block is open, so this is what "not working right
            # now" looks like, and saying it plainly beats four dashes.
            c.text(MARGIN, box.y + 22, "NO ACTIVE BLOCK", size=30, bold=True,
                   tracking=2)
            c.text(MARGIN, box.y + 62, "the quota window opens with the next "
                   "prompt", size=14)
            return

        shown = _tokens(block["tokens"])
        c.text(MARGIN, box.y + 16, shown, size=40, bold=True)
        width = c.text_width(shown, size=40, bold=True)
        c.text(MARGIN + width + 10, box.y + 42,
               f"tokens · {_money(block['cost'])}", size=16, bold=True)

        c.text(c.width - MARGIN, box.y + 18, f"{_hm(block['remaining'])} left",
               size=24, bold=True, anchor="ra")
        projected = block["projected"]
        if projected:
            c.text(c.width - MARGIN, box.y + 48,
                   f"heading for {_tokens(projected)}", size=14, anchor="ra")

        # Filled against ccusage's own projection for the full window, so
        # a bar approaching the right-hand end means the block is on
        # course to be spent — the thing worth knowing before starting a
        # long task.
        fraction = (
            block["tokens"] / projected if projected else 0.0
        )
        c.gauge(Box(MARGIN, box.y + 66, c.width - 2 * MARGIN, 20), fraction,
                shade="dense" if fraction < 0.9 else "solid")

    # -- history + lifetime -----------------------------------------------

    def _history(self, c: Canvas, box: Box, d: dict) -> None:
        c.hline(MARGIN, box.y - 8, c.width - MARGIN, weight=1)
        c.label(MARGIN, box.y, f"Daily spend · {DAYS} days")

        series = d["daily_cost"]
        chart = Box(MARGIN, box.y + 26, 470, 74)
        c.bars(chart, series, gap=6)
        c.hline(chart.x, chart.bottom + 2, chart.right, weight=1)

        # Weekday initials, for the same reason the readiness screen
        # labels its load bars: a fortnight of unlabelled bars gives no
        # way to tell a quiet weekend from a broken exporter.
        width = (chart.w - 6 * (len(series) - 1)) // len(series)
        for i, iso in enumerate(d["daily_days"]):
            c.text(chart.x + i * (width + 6) + width // 2, chart.bottom + 8,
                   date.fromisoformat(iso).strftime("%a")[0], size=12,
                   bold=True, anchor="ma")

        peak = max(series) if series else 0
        if peak:
            c.text(chart.right, box.y, f"PEAK {_money(peak)}", size=13,
                   bold=True, anchor="ra", tracking=1)

        c.vline(516, box.y, box.bottom - 10)

        right = 540
        c.label(right, box.y, "Lifetime")
        c.text(right, box.y + 18, _money(d["cost_total"]), size=40, bold=True)
        c.text(right, box.y + 64, "at Anthropic list price", size=13)
        c.text(right, box.y + 84, f"{_tokens(d['lifetime_total'])} tokens",
               size=20, bold=True)

        cache_read = d["lifetime"].get("cache_read")
        if cache_read and d["lifetime_total"]:
            share = cache_read / d["lifetime_total"] * 100
            c.text(right, box.y + 110, f"{share:.0f}% of them cache reads",
                   size=13)
