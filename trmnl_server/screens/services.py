"""Every service by name — the roll call the homelab grid only counts.

The homelab screen's grid answers "how many are down" at a distance; it
cannot say *which*, past the two names its footnote has room for. This
screen is the other half: one row per service, alphabetical, so a given
service is always in the same place and the eye learns where to look.

* A service is one row however many ways it is watched. `hivemind` is
  both an exporter (`up`) and a public site (`probe_success`); listing
  it twice would make a healthy panel look longer than the homelab is,
  and a half-down service look half-healthy. The row is up only when
  every check on it is.
* A down row is knocked out — white on solid black. In a column of
  hairline squares that is the only dark block, and it is legible from
  across the room without reading a word.
* Each row carries its probe time, because "up but taking two seconds"
  is the outage that does not page. Slow rows go bold.
* A certificate inside its renewal window replaces the timing: ACME
  renews at thirty days, so a cert closer than `CERT_WARN` to expiry
  means renewal is failing, and that is worth a row's attention weeks
  before the browser warning.
"""

from __future__ import annotations

from datetime import datetime
from statistics import median

from ..canvas import WHITE, Box, Canvas
from ..sources.prometheus import Probe, Sample
from .base import Context, Screen, register

MARGIN = 24
COLUMNS = 4
GUTTER = 16

# Probes slower than this are drawn bold. Every endpoint here is a
# Traefik → tunnel → localhost hop that answers in ~100 ms; a second is
# ten times normal and means something behind it is struggling.
SLOW = 1.0

# Days. ACME renews at 30 days left, so a cert inside 14 has missed two
# weeks of daily renewal attempts.
CERT_WARN = 14

Q_UP = "up"
Q_PROBES = 'probe_success{job="blackbox-http"}'
Q_LATENCY = 'probe_duration_seconds{job="blackbox-http"}'
Q_CERT_DAYS = (
    '(probe_ssl_earliest_cert_expiry{job="blackbox-http"} - time()) / 86400'
)

# Scrape jobs whose name is not the name a person uses for the thing.
# `blackbox-http` is absent on purpose: its `up` only says the probe
# ran, and the probe's own result is already the row for that site.
_JOB_NAMES = {
    "node": "hive",
    "node-vps": "vps",
    "blackbox-exporter": "blackbox",
    "maigret-runner": "maigret",
}


def _probe_name(sample: Sample) -> str:
    """The first DNS label: `https://karakeep.siem2l.nl/` → `karakeep`."""
    host = sample.label("instance").split("://")[-1].split("/")[0]
    labels = host.split(".")
    return labels[0] if labels else host


def _job_name(sample: Sample) -> str:
    job = sample.label("job") or "?"
    return _JOB_NAMES.get(job, job)


def merge_services(up: list[Sample], probes: list[Sample],
                   latency: list[Sample],
                   certs: list[Sample]) -> list[dict]:
    """One row per service name, sorted, from every check that names it.

    Public: the homelab screen counts its grid from this too, so the two
    screens can never disagree about how many services there are.
    """
    rows: dict[str, dict] = {}

    def row(name: str) -> dict:
        return rows.setdefault(
            name,
            {"name": name, "up": True, "latency": None, "cert_days": None},
        )

    for s in up:
        if s.label("job") == "blackbox-http":
            continue
        r = row(_job_name(s))
        r["up"] = r["up"] and s.value > 0
    for s in probes:
        r = row(_probe_name(s))
        r["up"] = r["up"] and s.value > 0
    for s in latency:
        r = row(_probe_name(s))
        r["latency"] = max(r["latency"] or 0.0, s.value)
    for s in certs:
        r = row(_probe_name(s))
        days = s.value
        r["cert_days"] = days if r["cert_days"] is None else min(
            r["cert_days"], days)
    return sorted(rows.values(), key=lambda r: r["name"])


def _summary(rows: list[dict]) -> tuple[str, bool]:
    down = [r["name"] for r in rows if not r["up"]]
    if not rows:
        return "No services reporting", False
    if down:
        return (f"{len(down)} of {len(rows)} down: {', '.join(down)}", True)
    timed = [r for r in rows if r["latency"] is not None]
    text = f"All {len(rows)} up"
    if timed:
        slowest = max(timed, key=lambda r: r["latency"])
        typical = median(r["latency"] for r in timed) * 1000
        text += (f" · median {typical:.0f}ms"
                 f" · slowest {slowest['name']}")
    certs = [r["cert_days"] for r in rows if r["cert_days"] is not None]
    if certs:
        text += f" · next cert {min(certs):.0f}d"
    return text, False


@register
class ServicesScreen(Screen):
    slug = "services"
    title = "Services"
    # Same cadence as the homelab screen: this is its detail view, and a
    # row that went dark should not wait longer to show here than the
    # hollow square that counted it did there.
    refresh_seconds = 300

    def fetch(self, ctx: Context) -> dict:
        probe = Probe(ctx.source("prometheus"))
        rows = merge_services(
            probe.vector(Q_UP),
            probe.vector(Q_PROBES),
            probe.vector(Q_LATENCY),
            probe.vector(Q_CERT_DAYS),
        )
        probe.check()
        summary, bad = _summary(rows)
        return {
            "generated_at": datetime.now(),
            "rows": rows,
            "summary": summary,
            "summary_bad": bad,
        }

    def render(self, c: Canvas, d: dict) -> None:
        c.text(MARGIN, 16, "SERVICES", size=30, bold=True, tracking=2)
        c.text(
            c.width - MARGIN, 24,
            f"UPDATED {d['generated_at'].strftime('%H:%M')}",
            size=13, bold=True, anchor="ra", tracking=1,
        )
        c.hline(MARGIN, 54, c.width - MARGIN, weight=3)

        x = MARGIN
        if d["summary_bad"]:
            c.fill(Box(MARGIN, 70, 14, 14), shade="solid")
            x += 24
        summary = c.clip(d["summary"], c.width - MARGIN - x, size=17,
                         bold=True)
        c.text(x, 66, summary, size=17, bold=True)
        c.hline(MARGIN, 96, c.width - MARGIN, weight=1)

        self._roll(c, Box(MARGIN, 106, c.width - 2 * MARGIN,
                          c.height - 106 - 8), d["rows"])

    def _roll(self, c: Canvas, box: Box, rows: list[dict]) -> None:
        if not rows:
            c.text(box.x, box.y + 10, "nothing is being scraped", size=16)
            return
        # Row height is chosen so every service fits, for the same
        # reason the homelab grid's cell size is: the count is a fact
        # about the homelab, and a new service must not fall off the
        # bottom of the panel.
        col_w = (box.w - GUTTER * (COLUMNS - 1)) // COLUMNS
        for pitch, size in ((26, 15), (23, 14), (20, 13), (17, 12)):
            per_col = box.h // pitch
            if per_col * COLUMNS >= len(rows):
                break
        for i, r in enumerate(rows[: per_col * COLUMNS]):
            col, line = divmod(i, per_col)
            cell = Box(box.x + col * (col_w + GUTTER), box.y + line * pitch,
                       col_w, pitch - 3)
            self._row(c, cell, r, size)
        for col in range(1, COLUMNS):
            vx = box.x + col * (col_w + GUTTER) - GUTTER // 2
            c.vline(vx, box.y, box.y + per_col * pitch - 4)

    def _row(self, c: Canvas, cell: Box, r: dict, size: int) -> None:
        ty = cell.y + (cell.h - size) // 2 - 1
        if not r["up"]:
            c.fill(cell, shade="solid")
            c.text(cell.x + 6, ty,
                   c.clip(r["name"], cell.w - 50, size=size, bold=True),
                   size=size, bold=True, ink=WHITE)
            c.text(cell.right - 6, ty, "DOWN", size=size - 3, bold=True,
                   anchor="ra", ink=WHITE)
            return

        mark = size - 5
        c.fill(Box(cell.x, cell.y + (cell.h - mark) // 2, mark, mark),
               shade="solid")
        cert = r["cert_days"]
        latency = r["latency"]
        if cert is not None and cert < CERT_WARN:
            note, loud = f"cert {max(cert, 0):.0f}d", True
        elif latency is not None:
            note, loud = (f"{latency * 1000:.0f}ms" if latency < 10
                          else f"{latency:.0f}s"), latency >= SLOW
        else:
            note, loud = "", False
        note_w = c.text_width(note, size=size - 3, bold=loud) if note else 0
        c.text(cell.x + mark + 7, ty,
               c.clip(r["name"], cell.w - mark - 7 - note_w - 6, size=size),
               size=size)
        if note:
            c.text(cell.right, ty + 2, note, size=size - 3, bold=loud,
                   anchor="ra")
