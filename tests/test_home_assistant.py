"""The Home Assistant source and the `home` screen built on it."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from trmnl_server.canvas import Canvas
from trmnl_server.config import Config
from trmnl_server.screens import Context, get
from trmnl_server.screens.home import rooms
from trmnl_server.sources.home_assistant import (
    HomeAssistantError,
    HomeAssistantSource,
    State,
    SyntheticHomeAssistantSource,
    sample_steps,
)

TOKEN = "ha-test-token"


@pytest.fixture
def token_file(tmp_path):
    path = tmp_path / "ha-token"
    path.write_text(TOKEN + "\n")
    return str(path)


def _source(token_file, handler) -> HomeAssistantSource:
    return HomeAssistantSource("http://ha.test:8123/", token_file,
                               transport=httpx.MockTransport(handler))


def test_states_sends_the_token_and_keys_by_entity(token_file):
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["path"] = request.url.path
        return httpx.Response(200, json=[
            {"entity_id": "sensor.a", "state": "21.5",
             "attributes": {"friendly_name": "A"}},
            {"state": "orphan"},
        ])

    states = _source(token_file, handler).states()
    assert seen == {"auth": f"Bearer {TOKEN}", "path": "/api/states"}
    assert list(states) == ["sensor.a"]
    assert states["sensor.a"].number == 21.5


def test_a_refused_token_is_an_error_without_the_body(token_file):
    def handler(request):
        return httpx.Response(401, text=f"bad token {TOKEN}")

    with pytest.raises(HomeAssistantError) as err:
        _source(token_file, handler).states()
    assert TOKEN not in str(err.value)


def test_unconfigured_is_off_not_a_guess():
    source = HomeAssistantSource("", "")
    assert source.available() is False
    with pytest.raises(HomeAssistantError):
        source.states()


def test_todo_items_reads_the_service_response(token_file):
    def handler(request):
        assert request.method == "POST"
        assert json.loads(request.content)["entity_id"] == "todo.list"
        return httpx.Response(200, json={"service_response": {"todo.list": {
            "items": [{"summary": "melk"}, {"summary": ""}, {"summary": "brood"}]
        }}})

    assert _source(token_file, handler).todo_items("todo.list") == [
        "melk", "brood"]


def test_unavailable_is_no_reading():
    assert State("sensor.x", "unavailable").number is None
    assert State("sensor.x", "nan").number is None


def test_history_is_resampled_as_a_step_function():
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    changes = [(start + timedelta(hours=1), 100.0),
               (start + timedelta(hours=3), 300.0)]
    points = sample_steps(changes, start, start + timedelta(hours=4), 5)
    # Nothing known before the first change; then each value holds.
    assert points == [None, 100.0, 100.0, 300.0, 300.0]


def test_rooms_skip_a_valves_own_temperature_sensor():
    states = {
        "climate.slaapkamer_siem": State(
            "climate.slaapkamer_siem", "heat",
            {"friendly_name": "Slaapkamer siem", "current_temperature": 18.6,
             "temperature": 19.5, "hvac_action": "heating"}),
        "sensor.slaapkamer_siem_local_temperature": State(
            "sensor.slaapkamer_siem_local_temperature", "18.6",
            {"device_class": "temperature"}),
        "sensor.keuken_temperature": State(
            "sensor.keuken_temperature", "19.9",
            {"device_class": "temperature",
             "friendly_name": "Keuken Temperature"}),
    }
    found = rooms(states)
    assert [r["name"] for r in found] == ["Keuken", "Slaapkamer siem"]
    assert found[1]["heating"] is True


class _NoExtras(SyntheticHomeAssistantSource):
    def forecast(self, entity_id):
        raise HomeAssistantError("forecast down")

    def history(self, entity_id, **kwargs):
        raise HomeAssistantError("recorder down")

    def todo_items(self, entity_id):
        raise HomeAssistantError("todo down")


def test_a_failing_extra_does_not_blank_the_screen():
    screen = get("home")
    data = screen.fetch(Context(Config(), {"home_assistant": _NoExtras()}))
    assert data["forecast"] is None and data["power_history"] is None
    canvas = Canvas(800, 480)
    screen.render(canvas, data)
    assert canvas.image.mode == "1"


def test_a_home_without_weather_says_how_to_add_it():
    class NoWeather(SyntheticHomeAssistantSource):
        def states(self):
            return {k: v for k, v in super().states().items()
                    if not k.startswith("weather.")}

    screen = get("home")
    data = screen.fetch(Context(Config(), {"home_assistant": NoWeather()}))
    assert data["weather"] is None
    screen.render(Canvas(800, 480), data)
