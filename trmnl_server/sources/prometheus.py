"""Read-only access to a Prometheus server over its HTTP API.

Three shapes of question cover every screen in this repo:

    instant(q)  -> one number, or None
    vector(q)   -> the labelled members of an instant vector
    series(q)   -> evenly-spaced points for a sparkline, gaps as None

No new dependency: `httpx` is already in the closure for `utils.py` and
the OIDC flow, and this file is deliberately written against it rather
than pulling in a Prometheus client library — the API is two GET
endpoints returning JSON, and the whole client fits in a page.

**"No data" is not an error, and this is the important part.** The
canonical homelab query `count(ALERTS{alertstate="firing"})` returns an
*empty result* whenever nothing is on fire, which is the state the
homelab is in almost all of the time. Prometheus reports that with
`status: success` and a zero-length result, exactly as it reports a
metric nobody exports. So an empty result is returned as `None` / `[]`
and never raised: the screens turn it into "no alerts", which is the
truth, rather than into a dash or a notice, which would read as a
broken panel on a perfectly healthy night.

`PrometheusError` is reserved for the cases where the server genuinely
could not answer: unreachable, timed out, a malformed query it refused,
a body that is not JSON.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from typing import Any

import httpx

# A range query answers with one sample per step per series, so a wide
# window at a fine step is a large body. Nothing here asks for one, but
# the panel renderer lives in the same process as `/api/display` and the
# server on the other end is a separate moving part: cap what is read
# rather than trusting every future query to stay small.
MAX_RESPONSE_BYTES = 2 * 1024 * 1024

# A homelab Prometheus on the same host answers in milliseconds. Waiting
# longer than this is worse than not waiting: the screen has a legible
# "unavailable" state, and a render thread parked on a hung socket does
# not.
HTTP_TIMEOUT = 5.0


class PrometheusError(RuntimeError):
    """Prometheus could not be reached, or refused the query.

    Never raised for a well-formed query that simply matched nothing —
    see the module docstring. This distinction is the whole contract:
    callers may treat this exception as "the monitoring is down" and
    an empty result as "the thing being monitored is quiet".
    """


@dataclass(frozen=True)
class Sample:
    """One member of an instant vector: its labels and its value."""

    labels: dict[str, str]
    value: float

    def label(self, name: str, default: str = "") -> str:
        return self.labels.get(name, default)


def _to_float(raw: Any) -> float | None:
    """Parse a Prometheus sample value, folding NaN and ±Inf into None.

    Values arrive as strings, and "NaN" is an ordinary answer — a
    division by zero, a rate over a series that has not moved. A single
    NaN poisons every min/max downstream, which makes a sparkline
    autoscale to NaN and vanish entirely. Treat it as the same "no
    reading" that a missing scrape produces, because that is what it
    means to a reader.
    """
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _read_capped(response: httpx.Response, url: str) -> bytes:
    """Read at most `MAX_RESPONSE_BYTES` of `response`.

    Content-Length is checked first because it is cheap and Prometheus
    sets it honestly, and the stream is capped anyway because that
    header is a claim rather than a fact.
    """
    declared = response.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise PrometheusError(
            f"{url} declares {int(declared)} bytes, over this server's "
            f"{MAX_RESPONSE_BYTES}-byte cap"
        )
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise PrometheusError(
                f"{url} exceeded this server's {MAX_RESPONSE_BYTES}-byte cap"
            )
        chunks.append(chunk)
    return b"".join(chunks)


class PrometheusSource:
    """The Prometheus half of `build_sources()`."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = HTTP_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.timeout = timeout
        # Test seam, the same shape as `oidc.HTTP_TRANSPORT`: the suite
        # points this at an in-process fake Prometheus so a screen can be
        # rendered end to end with no network. Production leaves it None
        # and httpx builds its own transport.
        self.transport = transport

    def available(self) -> bool:
        """False when `TRMNL_PROMETHEUS_URL` is unset, i.e. feature off."""
        return bool(self.base_url)

    # ---- queries --------------------------------------------------------

    def instant(self, query: str) -> float | None:
        """The value `query` evaluates to now, or None if it matched nothing.

        None is a real answer, not a failure. See the module docstring.
        When the expression matches several series the first is taken;
        aggregate in PromQL (`sum(...)`, `max(...)`) when that would be
        ambiguous, so the choice is visible in the screen rather than
        hidden here.
        """
        samples = self.vector(query)
        return samples[0].value if samples else None

    def vector(self, query: str) -> list[Sample]:
        """Every member of the instant vector `query` returns.

        Empty when nothing matched. Samples whose value is NaN are
        dropped rather than carried as a hole, because a labelled
        sample with no usable number is not something any caller here
        can draw.
        """
        data = self._get("/api/v1/query", {"query": query})
        out: list[Sample] = []
        result = data.get("result")

        # `scalar` (e.g. `time()`) and `string` answers carry no labels
        # and arrive as a bare [timestamp, "value"] pair rather than a
        # list of series.
        if data.get("resultType") in ("scalar", "string"):
            value = _to_float((result or [None, None])[1])
            return [] if value is None else [Sample({}, value)]

        for entry in result or []:
            value = _to_float((entry.get("value") or [None, None])[1])
            if value is None:
                continue
            labels = {
                str(k): str(v) for k, v in (entry.get("metric") or {}).items()
            }
            out.append(Sample(labels, value))
        return out

    def series(
        self, query: str, *, minutes: int = 60, points: int = 60
    ) -> list[float | None]:
        """`points` evenly-spaced samples covering the last `minutes`.

        Gaps come back as None rather than being dropped, because
        `Canvas.sparkline` breaks its line on None: a scrape that never
        happened has to read as a gap, not as a straight line drawn
        between the readings either side of it.
        """
        step = max(round(minutes * 60 / max(points - 1, 1)), 1)
        end = int(time.time())
        start = end - step * (points - 1)
        data = self._get(
            "/api/v1/query_range",
            {"query": query, "start": start, "end": end, "step": step},
        )
        out: list[float | None] = [None] * points
        result = data.get("result") or []
        if not result:
            return out
        # Only the first series, for the same reason `instant()` takes
        # the first sample: a query that can match more than one host
        # should say which one it wants, in PromQL, where the reader of
        # the screen can see it.
        for pair in result[0].get("values") or []:
            stamp = _to_float(pair[0])
            if stamp is None:
                continue
            index = round((stamp - start) / step)
            if 0 <= index < points:
                out[index] = _to_float(pair[1])
        return out

    # ---- transport ------------------------------------------------------

    def _get(self, path: str, params: dict) -> dict:
        if not self.base_url:
            raise PrometheusError(
                "TRMNL_PROMETHEUS_URL is not set, so there is no Prometheus "
                "to ask"
            )
        url = f"{self.base_url}{path}"
        try:
            with httpx.Client(
                timeout=self.timeout,
                # Never chase a redirect: a metrics endpoint that 302s is
                # misconfigured, and following it would send homelab
                # queries somewhere nobody configured.
                follow_redirects=False,
                transport=self.transport,
            ) as client:
                with client.stream("GET", url, params=params) as response:
                    status = response.status_code
                    body = _read_capped(response, url)
        except httpx.HTTPError as exc:
            raise PrometheusError(f"GET {url} failed: {exc}") from exc

        try:
            payload = json.loads(body)
        except ValueError:
            raise PrometheusError(
                f"{url} answered {status} with a body that is not JSON"
            ) from None
        if not isinstance(payload, dict):
            raise PrometheusError(f"{url} answered {status} with non-object JSON")
        # Prometheus reports query errors in the body with a non-200 as
        # well, so this one check covers both a refused query and a
        # server-side fault, and keeps the server's own wording.
        if payload.get("status") != "success":
            raise PrometheusError(
                f"{url} refused the query: {payload.get('error') or status}"
            )
        data = payload.get("data")
        return data if isinstance(data, dict) else {}


class Probe:
    """Runs one screen's queries, so a single bad query cannot blank the board.

    A status screen asks half a dozen independent questions. Any one of
    them can stop working on its own — an exporter renamed a metric, a
    recording rule was deleted, a label changed — and letting that
    exception out would replace five correct answers with a notice
    saying nothing useful.

    So a failed query is downgraded to a missing value, which every tile
    already knows how to draw: "Prometheus has no data for this" is a
    state that happens anyway, and it is a truthful description of a
    query that errored, from the reader's point of view.

    A *total* failure is a different fact. Every tile blank is not six
    honest empty states, it is one thing — the monitoring is down — and
    the panel must say so rather than showing a dashboard-shaped page of
    dashes that looks healthy from across the room. `check()` re-raises
    the first error when nothing at all succeeded.
    """

    def __init__(self, source: PrometheusSource) -> None:
        self.source = source
        self.asked = 0
        self.failed = 0
        self.error: PrometheusError | None = None

    def _record(self, exc: PrometheusError) -> None:
        self.failed += 1
        if self.error is None:
            self.error = exc

    def vector(self, query: str) -> list[Sample]:
        self.asked += 1
        try:
            return self.source.vector(query)
        except PrometheusError as exc:
            self._record(exc)
            return []

    def instant(self, query: str) -> float | None:
        self.asked += 1
        try:
            return self.source.instant(query)
        except PrometheusError as exc:
            self._record(exc)
            return None

    def series(self, query: str, **kwargs) -> list[float | None]:
        self.asked += 1
        try:
            return self.source.series(query, **kwargs)
        except PrometheusError as exc:
            self._record(exc)
            return [None] * int(kwargs.get("points", 60))

    def check(self) -> None:
        """Raise if every query failed. A no-op when even one succeeded."""
        if self.asked and self.failed == self.asked and self.error is not None:
            raise self.error
