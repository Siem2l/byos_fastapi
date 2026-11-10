"""Homelab status — is everything up, is the data safe, what is coming.

The organising idea is the one the readiness screen established: encode
state in *form*, not only in a number. A dashboard that has to be read
digit by digit is not a dashboard, it is a report. So:

* one sentence under the header answers the only question a passer-by
  asks — "is anything wrong?" — and names the worst thing when there is
  one, so the rest of the panel is detail rather than the answer;
* every scrape target and every public endpoint is a filled square in a
  grid, and one that is down is a hollow one — a hole in a solid block
  is visible from the other side of the room, where "94/96" is not;
* backups are bars that *grow with age*: a fresh run is a short hatched
  stub, an overdue one fills its whole track solid. The failure being
  guarded against is the silent one — a timer that stopped firing pages
  nobody, and the restic drill is weekly, so a dead nightly backup could
  otherwise go unnoticed for days;
* a firing alert turns the whole alerts band heavy: a solid bar down the
  left edge of the panel, rules above and below thickened. Nothing
  firing leaves the band light, which is what a quiet homelab should
  look like;
* storage is shown as *time until full*, not just percent free. A disk
  at 70% that fills in three months is the one to act on; a disk at 8%
  that has not moved in a year is not;
* "Next up" tracks the work the homelab is in the middle of, drawn from
  metrics rather than from a hand-kept list, so it moves on by itself:
  the storage pool reads "waiting for HDDs" until the second disk joins
  it, and then becomes the RAID1 health line.

Every query below names metrics this homelab actually exports (node
exporter with the systemd, hwmon, btrfs and textfile collectors,
blackbox, plus Prometheus's own `up` and `ALERTS`). Anything that
returns nothing is drawn as an empty state rather than as an error — see
`sources/prometheus.py` on why that distinction is load-bearing here:
`ALERTS{alertstate="firing"}` matching nothing is the *healthy* case and
by far the most common one.
"""

from __future__ import annotations

from datetime import datetime

from ..canvas import Box, Canvas
from ..sources.prometheus import Probe, Sample
from .base import Context, Screen, register
from .services import merge_services

MARGIN = 24

# How long a window the load sparkline covers, and at how many points.
LOAD_MINUTES = 60
LOAD_POINTS = 60

# Alert rows the band has room for. Beyond this the count is summarised
# rather than the list being clipped silently.
MAX_ALERT_ROWS = 2

# Filesystem rows the bottom band has room for, most urgent first.
MAX_FS_ROWS = 3

# Below this fraction free, a filesystem is drawn solid instead of
# hatched. Matches the `DiskFillingUp` alert threshold, so the screen
# starts shouting at the same moment the phone does.
FS_TIGHT = 0.10

# A projected fill date further out than this is not a forecast anyone
# acts on — a week of noise in `deriv` turns into "full in 40 years" —
# so it is shown as "steady" instead of as a date.
FS_HORIZON = 365 * 86400

# Closer than this, a filesystem is drawn solid even with room to spare:
# a month is about how long ordering and fitting a disk takes.
FS_URGENT = 30 * 86400

# Above this, a timer's last trigger is a timestamp of zero rather than a
# real age: systemd reports "never" as the epoch.
NEVER = 10 * 365 * 86400

DAY = 86400


# (row title, timer-name prefix, overdue after). Ordered by what losing
# it would cost: the offsite copies first, then local undo, then the
# drill that proves the offsite copies restore at all. A timer this
# table names but Prometheus does not report is drawn as "no data", not
# dropped — a backup row vanishing is the very failure this band exists
# to make visible.
BACKUPS: list[tuple[str, str, float]] = [
    ("Offsite hive", "restic-backups-homelab", 1.5 * DAY),
    ("Offsite VPS", "restic-backups-vps", 1.5 * DAY),
    ("Snapshots", "btrbk-", 3 * 3600),
    ("Restore drill", "restic-drill-homelab", 8 * DAY),
]

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
# health, so both go in the grid.
Q_PROBES = 'probe_success{job="blackbox-http"}'
Q_LOAD = 'max(node_load1{job="node"})'
Q_ALERTS = 'ALERTS{alertstate="firing"}'
Q_FAILED_UNITS = 'node_systemd_unit_state{state="failed"} == 1'
Q_UPTIME = 'time() - node_boot_time_seconds{job="node"}'
Q_TEMPS = 'max by (chip) (node_hwmon_temp_celsius{job="node"})'

# How long since each backup last *succeeded*, folded into one vector
# keyed by unit name so `BACKUPS` can match on prefixes. restic reports
# its own successes (textfile metrics written only after a clean exit);
# a timer's last trigger would say when a run started, and on the night
# this was written every restic run had started and then died waiting
# for a lock. btrbk has no success metric, so its row falls back to the
# trigger, and a failed unit still overrides every row.
Q_BACKUP_AGE = (
    'label_replace(time() - restic_backup_last_success_seconds,'
    ' "name", "restic-backups-$1", "name", "(.+)")'
    ' or label_replace(time() - restic_drill_last_success_seconds,'
    ' "name", "restic-drill-$1", "name", "(.+)")'
    ' or (time() - node_systemd_timer_last_trigger_seconds'
    '{name=~"btrbk-.*"})'
)

# Pseudo-filesystems are excluded at the query rather than after the
# fact: a NixOS host has a dozen tmpfs mounts sitting at 0% used, and
# they would crowd out the two filesystems anybody cares about.
_FS = (
    '{fstype!~"tmpfs|ramfs|overlay|squashfs|nsfs|devtmpfs|autofs|fuse.*|vfat"}'
)
Q_FS_AVAIL = f"node_filesystem_avail_bytes{_FS}"
Q_FS_SIZE = f"node_filesystem_size_bytes{_FS}"
# Seconds until empty at last week's rate. Negative when free space is
# growing, which `_join_filesystems` reads as "not filling".
Q_FS_FULL_IN = (
    f"node_filesystem_avail_bytes{_FS}"
    f" / -deriv(node_filesystem_avail_bytes{_FS}[7d])"
)

# The `storage` pool's devices, joined through `node_btrfs_info` because
# the device metrics carry only the filesystem uuid. One device is the
# SSD stopgap; two is the RAID1 the HDDs are for.
_STORAGE = '* on (uuid) group_left (label) node_btrfs_info{label="storage"}'
Q_STORAGE_DISKS = f"count(node_btrfs_device_size_bytes {_STORAGE})"
Q_STORAGE_ERRORS = f"sum(node_btrfs_device_errors_total {_STORAGE})"

# The rental-listing watcher on the VPS (textfile metrics, `rebo_*`).
Q_HOUSE_OPEN = 'sum(rebo_listings{verdict="match",available="1"})'
Q_HOUSE_APPLIED = "max(rebo_applied_total)"


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


def _age(seconds: float | None) -> str:
    """'38m', '18h', '3d': one unit, as the bar beside it is the detail."""
    if seconds is None:
        return "no data"
    if seconds >= NEVER:
        return "never"
    if seconds < 3600:
        return f"{max(seconds // 60, 1):.0f}m"
    if seconds < 2 * DAY:
        return f"{seconds // 3600:.0f}h"
    return f"{seconds // DAY:.0f}d"


def _uptime(seconds: float | None) -> str:
    if seconds is None:
        return "--"
    days, rest = divmod(int(seconds), DAY)
    hours = rest // 3600
    if days:
        return f"{days}d {hours}h"
    return f"{hours}h {rest % 3600 // 60}m"


def _horizon(seconds: float | None) -> str:
    """A fill date in the unit a person would plan in."""
    if seconds is None or seconds > FS_HORIZON:
        return "steady"
    if seconds < 2 * DAY:
        return f"full in {seconds // 3600:.0f}h"
    if seconds < 60 * DAY:
        return f"full in {seconds // DAY:.0f}d"
    return f"full in {seconds / (30 * DAY):.0f} mo"


def _mount_name(sample: Sample) -> str:
    """The mountpoint, prefixed with the host when it is not this one.

    Hive and the VPS both have a `/`, and two rows both called "/" is a
    puzzle rather than a dashboard.
    """
    mount = sample.label("mountpoint") or sample.label("device") or "?"
    instance = sample.label("instance")
    if instance and not instance.startswith(("127.", "localhost")):
        return f"{instance.split('-')[-1]}:{mount}"
    return mount


def _join_filesystems(avail: list[Sample], size: list[Sample],
                      full_in: list[Sample]) -> list[dict]:
    """Join the filesystem vectors into one row per device, most urgent first.

    Keyed on (instance, device) rather than on mountpoint: a btrfs
    volume reports the same device under every subvolume mount, and
    four identical gauges in a three-row band is a waste of the band.
    The shortest mountpoint wins, which is the one an operator
    recognises.

    Urgency is the fill date where there is a real one, and headroom
    otherwise: a disk filling in weeks outranks one that is merely
    fuller.
    """
    sizes = {
        (s.label("instance"), s.label("device")): s
        for s in size
        if s.value > 0
    }
    fills = {
        (s.label("instance"), s.label("device")): s.value
        for s in full_in
        if s.value > 0
    }
    best: dict[tuple[str, str], dict] = {}
    for a in avail:
        key = (a.label("instance"), a.label("device"))
        total = sizes.get(key)
        if total is None:
            continue
        mount = _mount_name(a)
        existing = best.get(key)
        if existing is not None and len(existing["mount"]) <= len(mount):
            continue
        best[key] = {
            "mount": mount,
            "free": a.value,
            "size": total.value,
            "free_fraction": a.value / total.value,
            "full_in": fills.get(key),
        }

    def urgency(row: dict) -> tuple[float, float]:
        fill = row["full_in"]
        return (fill if fill and fill <= FS_HORIZON else float("inf"),
                row["free_fraction"])

    return sorted(best.values(), key=urgency)


def _backups(ages: list[Sample], failed: list[str]) -> list[dict]:
    """One row per `BACKUPS` entry: how old, how overdue, whether it broke."""
    rows = []
    for title, prefix, overdue in BACKUPS:
        age = min(
            (s.value for s in ages if s.label("name").startswith(prefix)),
            default=None,
        )
        rows.append({
            "title": title,
            "age": age,
            "overdue": overdue,
            "failed": any(name.startswith(prefix) for name in failed),
        })
    return rows


def _temps(samples: list[Sample]) -> dict[str, float | None]:
    """The CPU package and the hottest drive, the two worth a glance.

    hwmon names the chips after their drivers; the HDDs arriving will
    add `drivetemp` chips beside today's NVMe one, and "hottest drive"
    keeps covering them without this function changing.
    """
    cpu = [s.value for s in samples if "coretemp" in s.label("chip")]
    drives = [
        s.value for s in samples
        if any(k in s.label("chip") for k in ("nvme", "drivetemp", "sata"))
    ]
    return {
        "cpu": max(cpu) if cpu else None,
        "drive": max(drives) if drives else None,
    }


def _headline(d: dict) -> tuple[str, bool]:
    """The one sentence a passer-by reads, and whether it is bad news.

    Worst first, and only the worst: a headline listing three problems
    is the alerts band again in a bigger font.
    """
    alerts = d["alerts"]
    if alerts:
        names = ", ".join(dict.fromkeys(a["name"] for a in alerts))
        return (f"{len(alerts)} alert{'s' if len(alerts) > 1 else ''} "
                f"firing: {names}"), True

    down = [e["name"] for e in d["services"] if not e["up"]]
    if down:
        return f"{len(down)} down: {', '.join(down)}", True

    broken = [b for b in d["backups"] if b["failed"]]
    if broken:
        return f"{broken[0]['title']} backup failed", True
    unknown = [b for b in d["backups"]
               if b["age"] is None or b["age"] >= NEVER]
    if unknown:
        return f"{unknown[0]['title']}: no successful backup on record", True
    late = [b for b in d["backups"] if b["age"] > b["overdue"]]
    if late:
        worst = late[0]
        return f"{worst['title']} backup is {_age(worst['age'])} old", True

    urgent = [f for f in d["filesystems"]
              if f["full_in"] and f["full_in"] < FS_URGENT]
    if urgent:
        return f"{urgent[0]['mount']} {_horizon(urgent[0]['full_in'])}", True

    total = len(d["services"])
    offsite = d["backups"][0]["age"]
    tail = (f" · offsite backup {_age(offsite)} ago"
            if offsite is not None and offsite < NEVER else "")
    if not total:
        return "No services reporting" + tail, False
    return f"All {total} services up" + tail, False


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
        failed = [s.label("name") or "?" for s in probe.vector(Q_FAILED_UNITS)]
        load = probe.instant(Q_LOAD)
        load_series = probe.series(
            Q_LOAD, minutes=LOAD_MINUTES, points=LOAD_POINTS
        )
        filesystems = _join_filesystems(
            probe.vector(Q_FS_AVAIL), probe.vector(Q_FS_SIZE),
            probe.vector(Q_FS_FULL_IN),
        )
        backups = _backups(probe.vector(Q_BACKUP_AGE), failed)
        uptime = probe.instant(Q_UPTIME)
        temps = _temps(probe.vector(Q_TEMPS))
        storage_disks = probe.instant(Q_STORAGE_DISKS)
        storage_errors = probe.instant(Q_STORAGE_ERRORS)
        house_open = probe.instant(Q_HOUSE_OPEN)
        house_applied = probe.instant(Q_HOUSE_APPLIED)

        # Nothing answered at all: that is one fact about the monitoring,
        # not a dozen facts about the homelab, and the panel should show
        # the notice screen rather than a board of dashes that reads as
        # healthy from across the room.
        probe.check()

        # The same one-row-per-service roll the services screen draws,
        # so the count here and the list there always agree. It comes
        # back sorted by name, which keeps the grid stable between
        # refreshes: a cell that changed has actually changed.
        services = [
            {"name": r["name"], "up": r["up"]}
            for r in merge_services(targets, probes, [], [])
        ]
        data = {
            "generated_at": datetime.now(),
            "services": services,
            "load": load,
            "load_series": load_series,
            "uptime": uptime,
            "temps": temps,
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
            "failed_units": failed,
            "filesystems": filesystems,
            "backups": backups,
            "storage": {
                "disks": None if storage_disks is None else int(storage_disks),
                "errors": storage_errors,
            },
            "house": (
                None if house_open is None and house_applied is None
                else {"open": house_open, "applied": house_applied}
            ),
        }
        data["headline"], data["headline_bad"] = _headline(data)
        return data

    # ---- rendering ------------------------------------------------------

    def render(self, c: Canvas, d: dict) -> None:
        self._header(c, d)
        self._headline(c, d)
        self._top(c, Box(0, 108, c.width, 140), d)
        self._alerts(c, Box(0, 266, c.width, 66), d)
        # The alerts band draws its own heavy closing rule when
        # something is firing; drawing a second hairline below it would
        # read as a printing artefact rather than as two decisions.
        bottom = Box(0, 352, c.width, 120)
        if not d["alerts"]:
            c.hline(MARGIN, bottom.y - 8, c.width - MARGIN, weight=1)
        self._storage(c, Box(MARGIN, bottom.y, 446, bottom.h), d)
        c.vline(482, bottom.y + 4, bottom.bottom - 10)
        self._next_up(c, Box(496, bottom.y, c.width - MARGIN - 496,
                             bottom.h), d)

    def _header(self, c: Canvas, d: dict) -> None:
        c.text(MARGIN, 16, "HOMELAB", size=30, bold=True, tracking=2)
        c.text(
            c.width - MARGIN, 24,
            f"UPDATED {d['generated_at'].strftime('%H:%M')}",
            size=13, bold=True, anchor="ra", tracking=1,
        )
        c.hline(MARGIN, 54, c.width - MARGIN, weight=3)

    def _headline(self, c: Canvas, d: dict) -> None:
        """The answer, in words. Bad news gets a solid lozenge in front."""
        x = MARGIN
        if d["headline_bad"]:
            c.fill(Box(MARGIN, 70, 14, 14), shade="solid")
            x += 24
        headline = c.clip(d["headline"], c.width - MARGIN - x, size=19,
                          bold=True)
        c.text(x, 66, headline, size=19, bold=True)
        c.hline(MARGIN, 98, c.width - MARGIN, weight=1)

    # -- top band ---------------------------------------------------------

    def _top(self, c: Canvas, box: Box, d: dict) -> None:
        services = Box(MARGIN, box.y, 268, box.h)
        backups = Box(318, box.y, 248, box.h)
        hive = Box(592, box.y, c.width - MARGIN - 592, box.h)

        self._services(c, services, d["services"])
        self._backup_rows(c, backups, d["backups"])
        self._hive(c, hive, d)

        # The same hairlines the readiness screen uses to separate its
        # metric columns, so the two screens read as one family.
        c.vline(services.right + 12, box.y + 4, box.bottom - 8)
        c.vline(hive.x - 13, box.y + 4, box.bottom - 8)

    def _services(self, c: Canvas, box: Box, entries: list[dict]) -> None:
        """A count, a grid of one cell per member, and a footnote."""
        up = sum(1 for e in entries if e["up"])
        total = len(entries)
        down = [e["name"] for e in entries if not e["up"]]

        c.label(box.x, box.y, "Services")
        headline = str(up) if total else "--"
        c.text(box.x, box.y + 16, headline, size=40, bold=True)
        if total:
            # Suppressed rather than shown as "/ 0": a denominator of
            # zero is not a fact about the homelab, it is the absence of
            # one, and the footnote below says so in words.
            width = c.text_width(headline, size=40, bold=True)
            c.text(box.x + width + 8, box.y + 36, f"/ {total}", size=18,
                   bold=True)

        self._grid(c, Box(box.x, box.y + 68, box.w, 44), entries)

        # Naming the casualties beats counting them, but only while the
        # list is short enough to read: past two, the grid above is
        # already the better answer and a truncated list would be noise.
        if not total:
            note = "nothing is being scraped"
        elif not down:
            note = "every exporter and endpoint answering"
        elif len(down) <= 2:
            note = "down: " + ", ".join(down)
        else:
            note = f"{len(down)} down"
        c.text(box.x, box.bottom - 14, c.clip(note, box.w, size=13), size=13)

    def _grid(self, c: Canvas, box: Box, targets: list[dict]) -> None:
        """One cell per target: filled = up, hollow = down.

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

    def _backup_rows(self, c: Canvas, box: Box, rows: list[dict]) -> None:
        c.label(box.x, box.y, "Backups")
        c.text(box.right, box.y, "AGO", size=13, bold=True, anchor="ra",
               tracking=1)
        track = Box(box.x + 112, 0, 70, 14)
        for i, row in enumerate(rows):
            y = box.y + 26 + i * 28
            age = row["age"]
            known = age is not None and age < NEVER
            late = row["failed"] or not known or age > row["overdue"]
            c.text(box.x, y, row["title"], size=14, bold=late)
            # Full track = overdue. Solid once past it, so the late row
            # is both the longest bar and the darkest one in the band.
            fraction = 1.0 if late else age / row["overdue"]
            c.gauge(Box(track.x, y + 2, track.w, track.h), fraction,
                    shade="solid" if late else "dense")
            shown = "FAILED" if row["failed"] else _age(age)
            c.text(box.right, y, shown, size=14, bold=late, anchor="ra")

    def _hive(self, c: Canvas, box: Box, d: dict) -> None:
        """Uptime first: an unclean reboot is what hive's history warns of.

        The load sparkline is kept, smaller, because a spike in the last
        hour is the usual prelude to the hard resets this box has had.
        """
        c.label(box.x, box.y, "Up")
        c.text(box.x, box.y + 16, _uptime(d["uptime"]), size=30, bold=True)

        temps = d["temps"]
        parts = []
        if temps["cpu"] is not None:
            parts.append(f"CPU {temps['cpu']:.0f}°")
        if temps["drive"] is not None:
            parts.append(f"disk {temps['drive']:.0f}°")
        c.text(box.x, box.y + 56, " · ".join(parts) or "no temperatures",
               size=14)

        series = d["load_series"]
        c.sparkline(Box(box.x, box.y + 80, box.w, 30), series)
        load = d["load"]
        readings = [v for v in series if v is not None]
        note = "load " + ("--" if load is None else f"{load:.2f}")
        if readings:
            note += f" · peak {max(readings):.2f}"
        c.text(box.x, box.bottom - 14, note, size=13)

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
            c.text(MARGIN, box.y + 20, "NONE FIRING", size=26, bold=True,
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
            c.text(c.width - MARGIN, box.y + 28,
                   c.clip(quiet, 380, size=15), size=15, bold=bool(failed),
                   anchor="ra")
            return

        if len(alerts) > MAX_ALERT_ROWS:
            c.text(c.width - MARGIN, box.y,
                   f"+{len(alerts) - MAX_ALERT_ROWS} MORE", size=13, bold=True,
                   anchor="ra", tracking=1)

        for i, alert in enumerate(alerts[:MAX_ALERT_ROWS]):
            y = box.y + 20 + i * 24
            c.fill(Box(MARGIN, y + 3, 12, 12), shade="solid")
            name_x = MARGIN + 20
            c.text(name_x, y, alert["name"], size=17, bold=True)
            width = c.text_width(alert["name"], size=17, bold=True)
            if alert["about"]:
                c.text(name_x + width + 10, y + 3,
                       c.clip(alert["about"], 300, size=14), size=14)
            if alert["severity"]:
                c.text(c.width - MARGIN, y + 3, alert["severity"].upper(),
                       size=13, bold=True, anchor="ra", tracking=1)

    # -- bottom band ------------------------------------------------------

    def _storage(self, c: Canvas, box: Box, d: dict) -> None:
        c.label(box.x, box.y, "Storage")
        rows = d["filesystems"][:MAX_FS_ROWS]
        if not rows:
            c.text(box.x, box.y + 26, "no filesystem metrics", size=16)
            return
        c.text(box.right, box.y, "FREE", size=13, bold=True, anchor="ra",
               tracking=1)

        for i, row in enumerate(rows):
            y = box.y + 24 + i * 28
            fill = row["full_in"]
            tight = (row["free_fraction"] < FS_TIGHT
                     or (fill is not None and fill < FS_URGENT))
            c.text(box.x, y + 1, c.clip(row["mount"], 104, size=14), size=14,
                   bold=True)
            c.gauge(
                Box(box.x + 112, y, 150, 18),
                1 - row["free_fraction"],
                shade="solid" if tight else "dense",
            )
            c.text(
                box.right, y + 2,
                f"{row['free_fraction'] * 100:.0f}% · "
                f"{_si_bytes(row['free'])} · {_horizon(fill)}",
                size=13, bold=tight, anchor="ra",
            )

    def _next_up(self, c: Canvas, box: Box, d: dict) -> None:
        """Work in progress, read off the metrics so it updates itself.

        A hollow square is waiting, a solid one is in place. Items with
        no data at all are left out rather than drawn as dashes: an
        empty roadmap row is not news.
        """
        c.label(box.x, box.y, "Next up")
        items: list[tuple[bool, str, str]] = []

        storage = d["storage"]
        if storage["disks"] is not None:
            if storage["disks"] >= 2:
                errors = storage["errors"] or 0
                items.append((True, f"RAID1 · {storage['disks']} disks",
                              "no device errors" if not errors
                              else f"{errors:.0f} device errors"))
            else:
                items.append((False, "HDDs → RAID1",
                              "waiting · storage on the SSD"))

        house = d["house"]
        if house is not None:
            parts = []
            if house["open"] is not None:
                parts.append(f"{house['open']:.0f} matches open")
            if house["applied"] is not None:
                parts.append(f"{house['applied']:.0f} applied")
            items.append((False, "House hunt", " · ".join(parts)))

        if not items:
            c.text(box.x, box.y + 26, "nothing tracked", size=14)
            return
        for i, (done, title, detail) in enumerate(items[:2]):
            y = box.y + 24 + i * 44
            marker = Box(box.x, y + 3, 12, 12)
            if done:
                c.fill(marker, shade="solid")
            else:
                c.rect(marker, weight=2)
            c.text(box.x + 20, y,
                   c.clip(title, box.w - 20, size=15, bold=True),
                   size=15, bold=True)
            c.text(box.x + 20, y + 20, c.clip(detail, box.w - 20, size=13),
                   size=13)
