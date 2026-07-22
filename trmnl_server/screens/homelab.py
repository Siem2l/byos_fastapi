"""Homelab status — targets up, load, firing alerts, filesystem headroom.

The organising idea is the one the readiness screen established: encode
state in *form*, not only in a number. A dashboard that has to be read
digit by digit is not a dashboard, it is a report. So:

* every scrape target is a filled square in a grid, and a target that is
  down is a hollow one — a hole in a solid block is visible from the
  other side of the room, where "47/48" is not;
* a firing alert turns the whole alerts band heavy: a solid bar down the
  left edge of the panel, rules above and below thickened, a solid
  bullet per alert. Nothing firing leaves the band light, which is what
  a quiet homelab should look like;
* filesystem headroom is a row of gauges, and the ones under the
  alerting threshold are filled solid rather than hatched, so the tight
  one is both the longest bar and the darkest.

Every query below names metrics this homelab actually exports (node
exporter with the systemd and textfile collectors, blackbox, plus
Prometheus's own `up` and `ALERTS`). Anything that returns nothing is
drawn as an empty state rather than as an error — see
`sources/prometheus.py` on why that distinction is load-bearing here:
`ALERTS{alertstate="firing"}` matching nothing is the *healthy* case and
by far the most common one.
"""

from __future__ import annotations

from datetime import datetime

from ..canvas import Box, Canvas
from ..sources.prometheus import Probe, Sample
from .base import Context, Screen, register

MARGIN = 24

# How long a window the load sparkline covers, and at how many points.
LOAD_MINUTES = 60
LOAD_POINTS = 60

# Alert rows the band has room for. Beyond this the count is summarised
# rather than the list being clipped silently.
MAX_ALERT_ROWS = 2

# Filesystem rows the bottom band has room for, tightest first.
MAX_FS_ROWS = 4

# Below this fraction free, a filesystem is drawn solid instead of
# hatched. Matches the `DiskFillingUp` alert threshold, so the screen
# starts shouting at the same moment the phone does.
FS_TIGHT = 0.10

# --- PromQL ----------------------------------------------------------------
#
# Kept as module constants rather than inlined: the synthetic stand-in in
# `sources/synthetic.py` answers exactly these strings, and a test walks
# a real `fetch()` to assert it still covers every one of them.

Q_TARGETS = "up"
# Not redundant with `up`. For the blackbox job, `up` says the *probe
# scrape* succeeded — it stays 1 while the site being probed is down,
# which is the failure this homelab actually has (see the
# PublicTunnelEndpointDown rule). `probe_success` is the endpoint's own
# health, so the two answer different questions and get separate tiles.
Q_PROBES = 'probe_success{job="blackbox-http"}'
Q_LOAD = "max(node_load1)"
Q_ALERTS = 'ALERTS{alertstate="firing"}'
Q_FAILED_UNITS = 'node_systemd_unit_state{state="failed"} == 1'

# Pseudo-filesystems are excluded at the query rather than after the
# fact: a NixOS host has a dozen tmpfs mounts sitting at 0% used, and
# they would crowd out the two filesystems anybody cares about.
_FS = '{fstype!~"tmpfs|ramfs|overlay|squashfs|nsfs|devtmpfs|autofs|fuse.*"}'
Q_FS_AVAIL = f"node_filesystem_avail_bytes{_FS}"
Q_FS_SIZE = f"node_filesystem_size_bytes{_FS}"


def _short_target(sample: Sample) -> str:
    """A name for one scrape target, short enough to sit in a footnote.

    Which label is useful depends on the job, so this picks rather than
    fixes one. For blackbox probes `instance` is the URL being probed
    and is exactly what an operator recognises, so the scheme and path
    are trimmed off it. For a locally-scraped exporter `instance` is
    `127.0.0.1:8830`, which names nothing a human thinks in — the `job`
    is "hivemind", and that is the answer to "what is broken".
    """
    instance = sample.label("instance")
    for scheme in ("https://", "http://"):
        if instance.startswith(scheme):
            instance = instance[len(scheme):]
    host = instance.split("/")[0].split(":")[0]
    if not host or host == "localhost" or host.replace(".", "").isdigit():
        return sample.label("job") or instance or "?"
    return instance.split("/")[0]


def _si_bytes(value: float | None) -> str:
    if value is None:
        return "--"
    for unit, scale in (("T", 1 << 40), ("G", 1 << 30), ("M", 1 << 20)):
        if value >= scale:
            return f"{value / scale:.0f}{unit}" if value / scale >= 10 else (
                f"{value / scale:.1f}{unit}"
            )
    return f"{value / 1024:.0f}K"


def _join_filesystems(avail: list[Sample], size: list[Sample]) -> list[dict]:
    """Join the two filesystem vectors into one row per mount, tightest first.

    Keyed on (instance, device) rather than on mountpoint: a bind mount
    reports the same device twice under two paths, and two identical
    gauges in a four-row band is a waste of half the band. The shortest
    mountpoint wins, which is the one an operator recognises.
    """
    sizes = {
        (s.label("instance"), s.label("device")): s
        for s in size
        if s.value > 0
    }
    best: dict[tuple[str, str], dict] = {}
    for a in avail:
        key = (a.label("instance"), a.label("device"))
        total = sizes.get(key)
        if total is None:
            continue
        mount = a.label("mountpoint") or a.label("device") or "?"
        existing = best.get(key)
        if existing is not None and len(existing["mount"]) <= len(mount):
            continue
        best[key] = {
            "mount": mount,
            "free": a.value,
            "size": total.value,
            "free_fraction": a.value / total.value,
        }
    return sorted(best.values(), key=lambda row: row["free_fraction"])


@register
class HomelabScreen(Screen):
    slug = "homelab"
    title = "Homelab status"
    # Five minutes. Prometheus scrapes every 15 s, so this is not the
    # limit on freshness — it is the limit on how often the panel is
    # willing to spend a full-panel e-ink refresh on it. Anything worth
    # knowing faster than this already goes to the phone via
    # Alertmanager.
    refresh_seconds = 300

    def fetch(self, ctx: Context) -> dict:
        probe = Probe(ctx.source("prometheus"))

        targets = probe.vector(Q_TARGETS)
        probes = probe.vector(Q_PROBES)
        alerts = probe.vector(Q_ALERTS)
        failed = probe.vector(Q_FAILED_UNITS)
        load = probe.instant(Q_LOAD)
        load_series = probe.series(
            Q_LOAD, minutes=LOAD_MINUTES, points=LOAD_POINTS
        )
        filesystems = _join_filesystems(
            probe.vector(Q_FS_AVAIL), probe.vector(Q_FS_SIZE)
        )

        # Nothing answered at all: that is one fact about the monitoring,
        # not eight facts about the homelab, and the panel should show
        # the notice screen rather than a board of dashes that reads as
        # healthy from across the room.
        probe.check()

        # Sorted by (job, instance) so the grid is stable between
        # refreshes: a cell that changed has actually changed, rather
        # than the whole block having been reshuffled by Prometheus
        # returning its series in a different order.
        targets = sorted(
            targets, key=lambda s: (s.label("job"), s.label("instance"))
        )
        return {
            "generated_at": datetime.now(),
            "targets": [
                {"name": _short_target(s), "up": s.value > 0} for s in targets
            ],
            "probes": [
                {"name": _short_target(s), "up": s.value > 0}
                for s in sorted(probes, key=lambda s: s.label("instance"))
            ],
            "load": load,
            "load_series": load_series,
            "alerts": [
                {
                    "name": s.label("alertname") or "alert",
                    "severity": s.label("severity"),
                    "about": (
                        s.label("mountpoint")
                        or s.label("name")
                        or _short_target(s)
                    ),
                }
                for s in sorted(alerts, key=lambda s: s.label("alertname"))
            ],
            "failed_units": [s.label("name") or "?" for s in failed],
            "filesystems": filesystems,
        }

    # ---- rendering ------------------------------------------------------

    def render(self, c: Canvas, d: dict) -> None:
        self._header(c, d)
        self._top(c, Box(0, 64, c.width, 150), d)
        self._alerts(c, Box(0, 230, c.width, 78), d)
        # The alerts band draws its own heavy closing rule when
        # something is firing; drawing a second hairline six pixels
        # below it would read as a printing artefact rather than as two
        # separate decisions.
        self._filesystems(c, Box(0, 324, c.width, 146), d,
                          rule=not d["alerts"])

    def _header(self, c: Canvas, d: dict) -> None:
        c.text(MARGIN, 16, "HOMELAB", size=30, bold=True, tracking=2)
        c.text(
            c.width - MARGIN, 24,
            f"UPDATED {d['generated_at'].strftime('%H:%M')}",
            size=13, bold=True, anchor="ra", tracking=1,
        )
        c.hline(MARGIN, 54, c.width - MARGIN, weight=3)

    # -- top band ---------------------------------------------------------

    def _top(self, c: Canvas, box: Box, d: dict) -> None:
        hero = Box(MARGIN, box.y, 296, box.h)
        cols = Box(346, box.y, c.width - MARGIN - 346, box.h).split_h(2, gap=26)

        self._roster(c, hero, "Scrape targets", d["targets"],
                     size=52, empty="no scrape targets at all",
                     healthy="every exporter responding")
        self._roster(c, cols[0], "Public endpoints", d["probes"],
                     size=44, empty="no blackbox probes",
                     healthy="every endpoint reachable")
        self._load(c, cols[1], d)

        # The same two hairlines the readiness screen uses to separate
        # its metric columns, so the two screens read as one family.
        c.vline(hero.right + 12, box.y + 6, box.bottom - 8)
        c.vline(cols[1].x - 13, box.y + 6, box.bottom - 8)

    def _roster(self, c: Canvas, box: Box, label: str, entries: list[dict],
                *, size: int, empty: str, healthy: str) -> None:
        """A count, a grid of one cell per member, and a footnote.

        Both health tiles share this shape on purpose: the two ask
        different questions — is the exporter answering, is the site
        actually up — and drawing them identically is what makes the
        difference between the two grids readable as the same *kind* of
        answer about two different things.
        """
        up = sum(1 for e in entries if e["up"])
        total = len(entries)
        down = [e["name"] for e in entries if not e["up"]]

        c.label(box.x, box.y + 6, label)
        headline = str(up) if total else "--"
        c.text(box.x, box.y + 20, headline, size=size, bold=True)
        if total:
            # Suppressed rather than shown as "/ 0": a denominator of
            # zero is not a fact about the homelab, it is the absence of
            # one, and the footnote below says so in words.
            width = c.text_width(headline, size=size, bold=True)
            c.text(box.x + width + 8, box.y + size, f"/ {total}", size=20,
                   bold=True)

        self._grid(c, Box(box.x, box.y + 82, box.w, 44), entries)

        # Naming the casualties beats counting them, but only while the
        # list is short enough to read: past two, the grid above is
        # already the better answer and a truncated list would be noise.
        if not total:
            note = empty
        elif not down:
            note = healthy
        elif len(down) <= 2:
            note = "down: " + ", ".join(down)
        else:
            note = f"{len(down)} down"
        c.text(box.x, box.bottom - 16, _clip(c, note, box.w, 13), size=13)

    def _grid(self, c: Canvas, box: Box, targets: list[dict]) -> None:
        """One cell per scrape target: filled = up, hollow = down.

        The cell size is chosen so the whole set fits rather than fixed,
        because the number of targets is a property of the homelab and
        not of this layout — adding an exporter must not push the grid
        through the footnote underneath it.
        """
        if not targets:
            return
        gap = 3
        for cell in (11, 9, 7, 5):
            per_row = max((box.w + gap) // (cell + gap), 1)
            rows = -(-len(targets) // per_row)
            if rows * (cell + gap) - gap <= box.h:
                break
        for i, target in enumerate(targets):
            x = box.x + (i % per_row) * (cell + gap)
            y = box.y + (i // per_row) * (cell + gap)
            if y + cell > box.bottom:
                break
            if target["up"]:
                c.fill(Box(x, y, cell, cell), shade="solid")
            else:
                # Hollow, not blank: a blank cell would be
                # indistinguishable from the end of the grid, and the
                # point is that a target exists here and is not
                # answering.
                c.rect(Box(x, y, cell, cell))

    def _load(self, c: Canvas, box: Box, d: dict) -> None:
        c.label(box.x, box.y + 6, "Load 1m")
        load = d["load"]
        shown = "--" if load is None else f"{load:.2f}"
        c.text(box.x, box.y + 20, shown, size=44, bold=True)

        series = d["load_series"]
        c.sparkline(Box(box.x, box.y + 76, box.w, 44), series)

        readings = [v for v in series if v is not None]
        note = (
            f"peak {max(readings):.2f} over {LOAD_MINUTES}m"
            if readings else "no history"
        )
        c.text(box.x, box.bottom - 16, note, size=13)

    # -- alerts band ------------------------------------------------------

    def _alerts(self, c: Canvas, box: Box, d: dict) -> None:
        alerts = d["alerts"]
        failed = d["failed_units"]
        firing = bool(alerts)

        # Weight is the signal. A quiet homelab gets the same hairline
        # every other section divider gets; a firing one gets a rule you
        # can see without reading, plus a solid bar in the left margin
        # that no other screen ever draws.
        c.hline(MARGIN, box.y - 8, c.width - MARGIN, weight=3 if firing else 1)
        if firing:
            c.hline(MARGIN, box.bottom + 10, c.width - MARGIN, weight=3)
            c.fill(Box(8, box.y - 8, 8, box.h + 21), shade="solid")

        label = "Alerts" if not firing else f"Alerts · {len(alerts)} firing"
        c.label(MARGIN, box.y, label)

        if not firing:
            c.text(MARGIN, box.y + 20, "NONE FIRING", size=30, bold=True,
                   tracking=2)
            # Right-aligned, so the quiet band has weight at both ends
            # rather than a headline and 500 px of nothing. Failed units
            # live here because a unit that has just died has not been
            # failed long enough for `SystemdUnitFailed` to fire, and
            # this is the only place the panel could say so.
            quiet = (
                "no failed systemd units" if not failed
                else f"{len(failed)} systemd unit"
                     f"{'' if len(failed) == 1 else 's'} failed: "
                     + ", ".join(failed[:2])
            )
            c.text(c.width - MARGIN, box.y + 32,
                   _clip(c, quiet, 340, 15), size=15, bold=bool(failed),
                   anchor="ra")
            return

        if len(alerts) > MAX_ALERT_ROWS:
            c.text(c.width - MARGIN, box.y,
                   f"+{len(alerts) - MAX_ALERT_ROWS} MORE", size=13, bold=True,
                   anchor="ra", tracking=1)

        for i, alert in enumerate(alerts[:MAX_ALERT_ROWS]):
            y = box.y + 22 + i * 26
            c.fill(Box(MARGIN, y + 3, 13, 13), shade="solid")
            name_x = MARGIN + 21
            c.text(name_x, y, alert["name"], size=18, bold=True)
            width = c.text_width(alert["name"], size=18, bold=True)
            if alert["about"]:
                c.text(name_x + width + 10, y + 4,
                       _clip(c, alert["about"], 300, 14), size=14)
            if alert["severity"]:
                c.text(c.width - MARGIN, y + 3, alert["severity"].upper(),
                       size=13, bold=True, anchor="ra", tracking=1)

    # -- filesystems band -------------------------------------------------

    def _filesystems(self, c: Canvas, box: Box, d: dict, *, rule: bool = True
                     ) -> None:
        if rule:
            c.hline(MARGIN, box.y - 6, c.width - MARGIN, weight=1)
        c.label(MARGIN, box.y, "Filesystems")

        rows = d["filesystems"][:MAX_FS_ROWS]
        if not rows:
            c.text(MARGIN, box.y + 26, "no filesystem metrics", size=18)
            return

        c.text(c.width - MARGIN, box.y, "FREE", size=13, bold=True,
               anchor="ra", tracking=1)

        for i, row in enumerate(rows):
            y = box.y + 22 + i * 30
            tight = row["free_fraction"] < FS_TIGHT
            c.text(MARGIN, y + 3, _clip(c, row["mount"], 160, 15), size=15,
                   bold=True)
            c.gauge(
                Box(200, y, 390, 20),
                1 - row["free_fraction"],
                shade="solid" if tight else "dense",
            )
            c.text(
                c.width - MARGIN, y + 3,
                f"{row['free_fraction'] * 100:.0f}% · {_si_bytes(row['free'])}",
                size=14, bold=tight, anchor="ra",
            )


def _clip(c: Canvas, text: str, width: int, size: int) -> str:
    """Trim `text` to `width` px, with an ellipsis when it had to be cut.

    Nothing on an 800 px panel may overflow into its neighbour, and the
    strings here are labels chosen by whoever configured the exporters
    — a mountpoint or a blackbox URL is as long as it happens to be.
    """
    if c.text_width(text, size=size) <= width:
        return text
    while text and c.text_width(text + "…", size=size) > width:
        text = text[:-1]
    return text + "…"
