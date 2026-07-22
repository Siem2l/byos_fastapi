"""The Prometheus source, and the two screens drawn from it.

**No network.** `PrometheusSource` takes its httpx transport as a
constructor argument for exactly this reason; `fake_prometheus` points
it at an `httpx.MockTransport` that forwards into a `TestClient`
wrapping a real FastAPI app, the same bridge `conftest.py` builds for
the fake IdP. So the query string, the URL-encoding, the status code and
the JSON envelope are all real round-trips, served inside the test
process.

The fake lives here rather than in `conftest.py` because only this
module uses it — unlike the IdP, which two test modules share.

What is asserted about the *rendering* is deliberately not "the text
says X", which a bitmap cannot be asked. It is the two things that can
be checked and that actually matter: nothing overflows the panel, and
the states the design encodes as shapes really do change the pixels.
"""

from __future__ import annotations

# See conftest.py for why these five pylint defaults are off in tests.
# pylint: disable=unused-argument,redefined-outer-name,protected-access
# pylint: disable=import-outside-toplevel,missing-function-docstring

import json
import time

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.testclient import TestClient

from trmnl_server.canvas import Canvas
from trmnl_server.config import Config
from trmnl_server.render import build_sources, render_screen
from trmnl_server.screens import Context, available, get
from trmnl_server.screens import homelab as homelab_screen
from trmnl_server.screens import stats as stats_screen
from trmnl_server.sources import prometheus as prom_module
from trmnl_server.sources.prometheus import (
    Probe,
    PrometheusError,
    PrometheusSource,
    Sample,
)
from trmnl_server.sources.synthetic import (
    SyntheticGarminSource,
    SyntheticPrometheusSource,
)

WIDTH, HEIGHT = 800, 480


# --- the fake Prometheus ---------------------------------------------------


class FakePrometheus:
    """A Prometheus HTTP API good enough to exercise the real client.

    `answers` maps a PromQL string to the `data` object the server would
    return for it. A query that is not in the table gets an *empty
    vector* — a successful response carrying no series — because that is
    what a real Prometheus answers for a metric nobody exports, and it
    is the case this client's contract is built around.
    """

    def __init__(self, answers: dict[str, dict] | None = None) -> None:
        self.answers = answers or {}
        self.queries: list[str] = []
        self.status = 200
        self.body: str | None = None
        self.app = self._build_app()

    def _build_app(self) -> FastAPI:
        app = FastAPI()
        fake = self

        @app.get("/api/v1/query")
        def query(request: Request) -> Response:
            return fake._answer(request.query_params.get("query", ""))

        @app.get("/api/v1/query_range")
        def query_range(request: Request) -> Response:
            return fake._answer(request.query_params.get("query", ""))

        return app

    def _answer(self, query: str) -> Response:
        self.queries.append(query)
        if self.body is not None:
            return Response(content=self.body, status_code=self.status,
                            media_type="application/json")
        if self.status != 200:
            return JSONResponse(
                {"status": "error", "errorType": "bad_data",
                 "error": "parse error: unexpected end of input"},
                status_code=self.status,
            )
        data = self.answers.get(query)
        if data is None:
            data = {"resultType": "vector", "result": []}
        return JSONResponse({"status": "success", "data": data})


def _transport(fake: FakePrometheus) -> httpx.MockTransport:
    """Bridge the source's *sync* httpx calls into the fake's ASGI app.

    `httpx.ASGITransport` is async-only and `PrometheusSource` is called
    from a sync render path, so the transport has to be a sync one.
    """
    inner = TestClient(fake.app, base_url="http://prometheus.test")

    def handler(request: httpx.Request) -> httpx.Response:
        upstream = inner.request(request.method, str(request.url))
        headers = {}
        if "content-type" in upstream.headers:
            headers["content-type"] = upstream.headers["content-type"]
        return httpx.Response(
            upstream.status_code, headers=headers, content=upstream.content
        )

    return httpx.MockTransport(handler)


def _vector(*samples: tuple[dict, str]) -> dict:
    return {
        "resultType": "vector",
        "result": [
            {"metric": labels, "value": [1_770_000_000, value]}
            for labels, value in samples
        ],
    }


def _matrix(pairs: list[tuple[float, str]]) -> dict:
    return {
        "resultType": "matrix",
        "result": [{"metric": {}, "values": [list(p) for p in pairs]}],
    }


@pytest.fixture()
def fake_prometheus():
    fake = FakePrometheus()
    fake.source = PrometheusSource(
        "http://prometheus.test", transport=_transport(fake)
    )
    return fake


# --- the client ------------------------------------------------------------


def test_instant_reads_a_scalar_out_of_a_vector(fake_prometheus):
    fake_prometheus.answers["sum(up)"] = _vector(({}, "48"))
    assert fake_prometheus.source.instant("sum(up)") == 48.0


def test_no_data_is_a_value_not_an_error(fake_prometheus):
    """The healthy homelab case, and the reason this client exists.

    `count(ALERTS{alertstate="firing"})` matches nothing whenever
    nothing is on fire. Prometheus answers `status: success` with a
    zero-length result, and turning that into an exception would put an
    error screen on the wall every night that nothing went wrong.
    """
    query = 'count(ALERTS{alertstate="firing"})'
    assert fake_prometheus.source.instant(query) is None
    assert fake_prometheus.source.vector(query) == []
    assert fake_prometheus.queries == [query, query]


def test_vector_carries_the_labels(fake_prometheus):
    fake_prometheus.answers["up"] = _vector(
        ({"job": "node", "instance": "127.0.0.1:9002"}, "1"),
        ({"job": "hivemind", "instance": "127.0.0.1:8830"}, "0"),
    )
    samples = fake_prometheus.source.vector("up")
    assert [s.value for s in samples] == [1.0, 0.0]
    assert samples[1].label("job") == "hivemind"
    assert samples[1].label("nonesuch", "fallback") == "fallback"


def test_a_scalar_result_type_is_understood(fake_prometheus):
    fake_prometheus.answers["time()"] = {
        "resultType": "scalar", "result": [1_770_000_000, "1770000000"]
    }
    assert fake_prometheus.source.instant("time()") == 1_770_000_000.0


def test_nan_is_folded_into_no_reading(fake_prometheus):
    """A NaN must not reach a chart: it poisons every min/max downstream."""
    fake_prometheus.answers["broken"] = _vector(({}, "NaN"))
    assert fake_prometheus.source.instant("broken") is None
    fake_prometheus.answers["inf"] = _vector(({}, "+Inf"))
    assert fake_prometheus.source.instant("inf") is None


def test_series_places_samples_on_their_own_step(fake_prometheus):
    now = int(time.time())
    step = 60
    start = now - step * 9
    fake_prometheus.answers["q"] = _matrix(
        [(start + step * i, str(i)) for i in range(10)]
    )
    values = fake_prometheus.source.series("q", minutes=9, points=10)
    assert values == [float(i) for i in range(10)]


def test_series_leaves_a_missing_scrape_as_a_gap(fake_prometheus):
    """None, not interpolation — `Canvas.sparkline` breaks its line on it."""
    now = int(time.time())
    step = 60
    start = now - step * 9
    fake_prometheus.answers["q"] = _matrix(
        [(start + step * i, "1") for i in range(10) if i != 4]
    )
    values = fake_prometheus.source.series("q", minutes=9, points=10)
    assert values[4] is None
    assert values.count(None) == 1


def test_series_with_no_data_is_all_gaps(fake_prometheus):
    assert fake_prometheus.source.series("q", points=12) == [None] * 12


def test_a_refused_query_raises(fake_prometheus):
    fake_prometheus.status = 400
    with pytest.raises(PrometheusError, match="refused the query"):
        fake_prometheus.source.instant("sum(")


def test_a_non_json_body_raises_rather_than_crashing(fake_prometheus):
    fake_prometheus.body = "<html>502 Bad Gateway</html>"
    with pytest.raises(PrometheusError, match="not JSON"):
        fake_prometheus.source.instant("up")


def test_an_unreachable_server_raises(fake_prometheus):
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    source = PrometheusSource(
        "http://prometheus.test", transport=httpx.MockTransport(refuse)
    )
    with pytest.raises(PrometheusError, match="failed"):
        source.instant("up")


def test_an_oversized_body_is_refused(fake_prometheus, monkeypatch):
    """The panel lives in this process; a huge answer must not be buffered."""
    monkeypatch.setattr(prom_module, "MAX_RESPONSE_BYTES", 16)
    fake_prometheus.answers["up"] = _vector(({}, "1"))
    with pytest.raises(PrometheusError, match="cap"):
        fake_prometheus.source.instant("up")


def test_no_configured_url_names_the_setting():
    source = PrometheusSource("")
    assert source.available() is False
    with pytest.raises(PrometheusError, match="TRMNL_PROMETHEUS_URL"):
        source.instant("up")


def test_a_configured_url_is_available():
    assert PrometheusSource("http://127.0.0.1:8001/").available() is True
    assert PrometheusSource("http://127.0.0.1:8001/").base_url.endswith("8001")


# --- Probe -----------------------------------------------------------------


class _PartlyBroken:
    """Answers one query and fails the rest."""

    def __init__(self, good: str) -> None:
        self.good = good

    def vector(self, query: str) -> list[Sample]:
        if query == self.good:
            return [Sample({}, 1.0)]
        raise PrometheusError("no such metric")

    def instant(self, query: str) -> float | None:
        samples = self.vector(query)
        return samples[0].value if samples else None

    def series(self, query: str, **kwargs) -> list[float | None]:
        raise PrometheusError("no such metric")


def test_one_broken_query_does_not_blank_the_board():
    probe = Probe(_PartlyBroken("good"))
    assert probe.instant("good") == 1.0
    assert probe.instant("bad") is None
    assert probe.vector("bad") == []
    assert probe.series("bad", points=5) == [None] * 5
    probe.check()  # one query worked, so this is not an outage


def test_every_query_failing_is_re_raised_as_an_outage():
    """Six blank tiles is one fact — the monitoring is down — not six."""
    probe = Probe(_PartlyBroken("nothing-asks-this"))
    probe.instant("a")
    probe.vector("b")
    with pytest.raises(PrometheusError):
        probe.check()


def test_check_on_an_unused_probe_is_a_no_op():
    Probe(_PartlyBroken("x")).check()


# --- the screens -----------------------------------------------------------


def _sources(**overrides) -> dict:
    sources = {
        "garmin": SyntheticGarminSource(),
        "prometheus": SyntheticPrometheusSource(),
    }
    sources.update(overrides)
    return sources


def _draw(slug: str, sources: dict) -> Canvas:
    screen = get(slug)
    canvas = Canvas(WIDTH, HEIGHT)
    screen.render(canvas, screen.fetch(Context(Config(), sources)))
    return canvas


def _ink(canvas: Canvas) -> float:
    """Fraction of the panel that is black. Bin 0 of a mode-"1" histogram."""
    return canvas.image.histogram()[0] / (WIDTH * HEIGHT)


def test_the_registry_lists_all_three_screens():
    assert available() == ["homelab", "readiness", "stats"]


@pytest.mark.parametrize("slug", ["homelab", "readiness", "stats"])
def test_every_screen_renders_a_1bit_panel(slug):
    canvas = _draw(slug, _sources())
    assert canvas.image.mode == "1"
    assert canvas.image.size == (WIDTH, HEIGHT)


@pytest.mark.parametrize("slug", ["homelab", "stats"])
def test_ink_coverage_suits_e_ink(slug):
    """Between 4% and 25%: a legible panel, not a solid black rectangle."""
    assert 0.04 < _ink(_draw(slug, _sources())) < 0.25


@pytest.mark.parametrize("slug", ["homelab", "stats"])
def test_synthetic_rendering_is_reproducible(slug):
    """Layout iteration depends on a diff meaning a code change, only."""
    first = _draw(slug, _sources()).image.tobytes()
    second = _draw(slug, _sources()).image.tobytes()
    assert first == second


@pytest.mark.parametrize("slug", ["homelab", "stats"])
def test_the_synthetic_source_answers_every_query_a_screen_asks(slug):
    """Anti-drift: a new PromQL string has to be taught to the stand-in.

    Without this, adding a query to a screen leaves a silently blank
    tile in every `--synthetic` preview, which is exactly the state the
    preview exists to rule out.
    """
    class Recorder:
        def __init__(self) -> None:
            self.asked: list[str] = []

        def vector(self, query):
            self.asked.append(query)
            return []

        def instant(self, query):
            self.asked.append(query)
            return None

        def series(self, query, *, minutes=60, points=60):
            self.asked.append(query)
            return [None] * points

    recorder = Recorder()
    get(slug).fetch(Context(Config(), _sources(prometheus=recorder)))

    synthetic = SyntheticPrometheusSource()
    unanswered = [
        query for query in recorder.asked
        if not synthetic.vector(query)
        and all(v is None for v in synthetic.series(query, points=4))
    ]
    assert not unanswered, unanswered


# --- the states the design encodes as shapes -------------------------------


def test_a_firing_alert_is_visible_without_reading_it():
    """The design rule, made executable.

    A firing alert draws a solid bar in the left margin beside the
    alerts band. Nothing else on any screen draws there, so this single
    pixel is the difference between "quiet" and "something is wrong" at
    arm's length — and a refactor that quietly drops the bar leaves the
    two states distinguishable only by reading the text.
    """
    firing = _draw("homelab", _sources(
        prometheus=SyntheticPrometheusSource(calm=False)))
    quiet = _draw("homelab", _sources(
        prometheus=SyntheticPrometheusSource(calm=True)))
    assert firing.image.getpixel((11, 270)) == 0
    assert quiet.image.getpixel((11, 270)) == 1


def test_a_down_target_changes_the_grid():
    firing = _draw("homelab", _sources(
        prometheus=SyntheticPrometheusSource(calm=False)))
    quiet = _draw("homelab", _sources(
        prometheus=SyntheticPrometheusSource(calm=True)))
    assert firing.image.tobytes() != quiet.image.tobytes()


def test_a_quiet_homelab_is_still_a_full_panel():
    """The calm state must not read as a half-drawn screen."""
    canvas = _draw("homelab", _sources(
        prometheus=SyntheticPrometheusSource(calm=True)))
    assert 0.04 < _ink(canvas) < 0.25


# --- no data, everywhere it can happen -------------------------------------


class _Empty:
    """A Prometheus that is up, healthy, and exports none of this."""

    def vector(self, query):
        return []

    def instant(self, query):
        return None

    def series(self, query, *, minutes=60, points=60):
        return [None] * points


@pytest.mark.parametrize("slug", ["homelab", "stats"])
def test_a_screen_with_no_data_at_all_still_draws(slug):
    """Every tile empty is a legible page, not an exception and not a blank.

    This is the shape of a homelab whose exporters have all been renamed,
    and of a brand-new install: Prometheus answers every query, correctly,
    with nothing.
    """
    canvas = _draw(slug, _sources(prometheus=_Empty()))
    assert canvas.image.mode == "1"
    assert _ink(canvas) > 0.005


def test_homelab_reports_no_alerts_rather_than_no_data():
    data = get("homelab").fetch(Context(Config(), _sources(prometheus=_Empty())))
    assert data["alerts"] == []
    assert data["failed_units"] == []
    assert data["targets"] == []


def test_stats_handles_a_window_with_no_active_block():
    """ccusage publishes the block series only while a block is open."""
    class NoBlock(SyntheticPrometheusSource):
        def vector(self, query):
            if query.startswith("claude_code_block_"):
                return []
            return super().vector(query)

    data = get("stats").fetch(Context(Config(), _sources(prometheus=NoBlock())))
    assert data["block"]["tokens"] is None
    canvas = _draw("stats", _sources(prometheus=NoBlock()))
    assert _ink(canvas) > 0.02


def test_stats_discloses_a_stale_exporter():
    """An hours-old number looks live unless the header says otherwise."""
    class Stale(SyntheticPrometheusSource):
        def vector(self, query):
            if query == stats_screen.Q_STALENESS:
                return [Sample({}, 9000.0)]
            return super().vector(query)

    fresh = _draw("stats", _sources())
    stale = _draw("stats", _sources(prometheus=Stale()))
    assert stale.image.tobytes() != fresh.image.tobytes()
    data = get("stats").fetch(Context(Config(), _sources(prometheus=Stale())))
    assert data["staleness"] > stats_screen.STALE_AFTER


def test_a_total_outage_reaches_the_caller_as_an_error():
    """So `routes/panel.py` puts a notice on the glass, not a page of dashes."""
    class Down:
        def vector(self, query):
            raise PrometheusError("connection refused")

        def instant(self, query):
            raise PrometheusError("connection refused")

        def series(self, query, **kwargs):
            raise PrometheusError("connection refused")

    for slug in ("homelab", "stats"):
        with pytest.raises(PrometheusError):
            get(slug).fetch(Context(Config(), _sources(prometheus=Down())))


def test_an_unconfigured_prometheus_names_the_setting():
    cfg = Config()
    cfg.synthetic = False
    cfg.prometheus_url = ""
    with pytest.raises(PrometheusError, match="TRMNL_PROMETHEUS_URL"):
        render_screen("homelab", cfg)


# --- wiring ----------------------------------------------------------------


def test_build_sources_offers_prometheus_in_both_modes():
    cfg = Config()
    cfg.synthetic = False
    cfg.prometheus_url = "http://127.0.0.1:8001"
    live = build_sources(cfg)
    assert isinstance(live["prometheus"], PrometheusSource)
    assert live["prometheus"].available()
    fake = build_sources(cfg, synthetic=True)
    assert isinstance(fake["prometheus"], SyntheticPrometheusSource)


def test_config_reads_the_prometheus_url(monkeypatch):
    monkeypatch.setenv("TRMNL_PROMETHEUS_URL", "http://127.0.0.1:8001/")
    assert Config().prometheus_url == "http://127.0.0.1:8001"
    monkeypatch.delenv("TRMNL_PROMETHEUS_URL")
    assert Config().prometheus_url == ""


def test_the_new_screens_have_their_own_refresh_cadence():
    """A status board that changes every scrape must not inherit Garmin's."""
    assert homelab_screen.HomelabScreen.refresh_seconds == 300
    assert stats_screen.StatsScreen.refresh_seconds == 600
    assert get("readiness").refresh_seconds == 1800


def test_each_screen_is_exposed_as_a_rotation_entry():
    """The UI has no concept of a screen; it only sees plugins."""
    from trmnl_server.plugins.garmin import SLUG_BY_PLUGIN

    assert set(SLUG_BY_PLUGIN.values()) == {"homelab", "readiness", "stats"}


@pytest.mark.parametrize("slug", ["homelab", "stats"])
def test_preview_route_renders_the_new_screens(client, slug):
    response = client.get(
        f"/preview/{slug}.png", headers={"Access-Token": "test-token"}
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"


def test_a_screen_renders_to_a_true_1bit_bmp(tmp_path):
    from PIL import Image

    from trmnl_server.render import render_to_file

    cfg = Config()
    cfg.synthetic = True
    path, refresh = render_to_file("homelab", cfg, tmp_path / "f.bmp")
    assert refresh == 300
    with Image.open(path) as opened:
        assert opened.mode == "1"
        assert opened.size == (WIDTH, HEIGHT)


def test_the_fake_prometheus_speaks_the_real_wire_format(fake_prometheus):
    """Guards the fake itself: a stub that drifts proves nothing."""
    fake_prometheus.answers["up"] = _vector(({"job": "node"}, "1"))
    inner = TestClient(fake_prometheus.app)
    payload = json.loads(inner.get("/api/v1/query", params={"query": "up"}).text)
    assert payload["status"] == "success"
    assert payload["data"]["resultType"] == "vector"
    assert payload["data"]["result"][0]["metric"] == {"job": "node"}
