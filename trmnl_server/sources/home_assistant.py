"""Read-only access to Home Assistant over its REST API.

Three questions cover the `home` screen:

    states()           -> every entity, by entity_id
    history(id, ...)   -> evenly-spaced points for a sparkline, gaps as None
    todo_items(id)     -> the open items on a to-do list

Authentication is a long-lived access token, read from a file per request
so a rotation needs no restart, and sent only to the configured URL. The
token is a Home Assistant user's full API access, so this client only
ever issues GETs plus the one read-only service call `todo.get_items`.

An entity that does not exist, or reports `unavailable`/`unknown`, is
not an error: a radiator valve with a flat battery is a normal state of
a home, and the screen draws it as a dash. `HomeAssistantError` means
Home Assistant itself could not answer.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

# `/api/states` on a home with a few hundred entities is ~200 KB; a cap
# well above that still stops a misbehaving server from filling memory
# in the same process that answers the panel.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
# Home Assistant is on the same host. A render that waits longer than this
# is worse than a notice on the glass.
HTTP_TIMEOUT = 5.0

MISSING = {"unavailable", "unknown", "none", ""}


class HomeAssistantError(RuntimeError):
    """Home Assistant could not be reached or refused the request."""


@dataclass(frozen=True)
class State:
    entity_id: str
    state: str
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return str(self.attributes.get("friendly_name") or self.entity_id)

    @property
    def number(self) -> float | None:
        return to_float(self.state)

    def attr_number(self, key: str) -> float | None:
        return to_float(self.attributes.get(key))


def to_float(raw: Any) -> float | None:
    if raw is None or str(raw).strip().lower() in MISSING:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _parse_time(raw: Any) -> datetime | None:
    try:
        stamp = datetime.fromisoformat(str(raw))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def sample_steps(changes: list[tuple[datetime, float | None]],
                 start: datetime, end: datetime,
                 points: int) -> list[float | None]:
    """Resample state changes into `points` evenly-spaced readings.

    Home Assistant records a value when it changes, not on a clock, so
    each point takes the last value recorded at or before it. Points
    before the first change are gaps rather than a guess.
    """
    out: list[float | None] = [None] * points
    if points < 2 or not changes:
        return out
    step = (end - start) / (points - 1)
    i, current = 0, None
    for p in range(points):
        at = start + step * p
        while i < len(changes) and changes[i][0] <= at:
            current = changes[i][1]
            i += 1
        out[p] = current if i else None
    return out


class HomeAssistantSource:
    """The Home Assistant half of `build_sources()`."""

    def __init__(self, base_url: str, token_file: str, *,
                 timeout: float = HTTP_TIMEOUT,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.base_url = (base_url or "").rstrip("/")
        self.token_file = token_file or ""
        self.timeout = timeout
        # Test seam, as in PrometheusSource.
        self.transport = transport

    def available(self) -> bool:
        """False when no URL or token is configured, i.e. feature off."""
        return bool(self.base_url and self.token_file)

    def states(self) -> dict[str, State]:
        payload = self._request("GET", "/api/states")
        if not isinstance(payload, list):
            raise HomeAssistantError("/api/states did not answer a list")
        out: dict[str, State] = {}
        for raw in payload:
            if isinstance(raw, dict) and isinstance(raw.get("entity_id"), str):
                out[raw["entity_id"]] = State(
                    raw["entity_id"], str(raw.get("state", "")),
                    raw.get("attributes") or {},
                )
        return out

    def history(self, entity_id: str, *, hours: int = 24,
                points: int = 96) -> list[float | None]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
        payload = self._request(
            "GET", f"/api/history/period/{start.isoformat()}",
            params={"filter_entity_id": entity_id,
                    "end_time": end.isoformat(),
                    "minimal_response": "", "no_attributes": ""},
        )
        rows = payload[0] if isinstance(payload, list) and payload else []
        changes = []
        for row in rows if isinstance(rows, list) else []:
            stamp = _parse_time(row.get("last_changed")
                                or row.get("last_updated"))
            if stamp is not None:
                changes.append((stamp, to_float(row.get("state"))))
        changes.sort(key=lambda c: c[0])
        return sample_steps(changes, start, end, points)

    def todo_items(self, entity_id: str) -> list[str]:
        payload = self._request(
            "POST", "/api/services/todo/get_items",
            params={"return_response": ""},
            body={"entity_id": entity_id, "status": "needs_action"},
        )
        response = (payload or {}).get("service_response") or {}
        items = (response.get(entity_id) or {}).get("items") or []
        return [str(i.get("summary", "")).strip() for i in items
                if isinstance(i, dict) and i.get("summary")]

    def forecast(self, entity_id: str) -> list[dict]:
        """Daily forecast: dicts with datetime, temperature, templow, condition."""
        payload = self._request(
            "POST", "/api/services/weather/get_forecasts",
            params={"return_response": ""},
            body={"entity_id": entity_id, "type": "daily"},
        )
        response = (payload or {}).get("service_response") or {}
        days = (response.get(entity_id) or {}).get("forecast") or []
        return [d for d in days if isinstance(d, dict)]

    # ---- transport ------------------------------------------------------

    def _token(self) -> str:
        try:
            with open(self.token_file, encoding="utf-8") as fh:
                token = fh.read().strip()
        except OSError as exc:
            raise HomeAssistantError(
                f"TRMNL_HOME_ASSISTANT_TOKEN_FILE could not be read: {exc}"
            ) from exc
        if not token:
            raise HomeAssistantError("TRMNL_HOME_ASSISTANT_TOKEN_FILE is empty")
        return token

    def _request(self, method: str, path: str, *, params: dict | None = None,
                 body: dict | None = None) -> Any:
        if not self.available():
            raise HomeAssistantError(
                "TRMNL_HOME_ASSISTANT_URL and TRMNL_HOME_ASSISTANT_TOKEN_FILE "
                "are not both set, so there is no Home Assistant to ask"
            )
        url = f"{self.base_url}{path}"
        headers = {"Authorization": f"Bearer {self._token()}"}
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False,
                              transport=self.transport) as client:
                with client.stream(method, url, params=params, json=body,
                                   headers=headers) as response:
                    status = response.status_code
                    data = self._read_capped(response, path)
        except httpx.HTTPError as exc:
            raise HomeAssistantError(f"{method} {path} failed: {exc}") from exc
        if status != 200:
            # Never echo the body: on a 401 it can quote the request.
            raise HomeAssistantError(f"{method} {path} answered {status}")
        try:
            return json.loads(data)
        except ValueError:
            raise HomeAssistantError(f"{path} did not answer JSON") from None

    @staticmethod
    def _read_capped(response: httpx.Response, path: str) -> bytes:
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise HomeAssistantError(
                    f"{path} exceeded the {MAX_RESPONSE_BYTES}-byte cap")
            chunks.append(chunk)
        return b"".join(chunks)


class SyntheticHomeAssistantSource:
    """A plausible home, shaped like the real one, for previews and tests.

    Uses the same entity IDs the `home` screen asks for, so a preview
    exercises the real lookups. Seeded, so two renders are identical.
    """

    def available(self) -> bool:
        return True

    def states(self) -> dict[str, State]:
        from ..screens import home as hs

        def s(entity_id: str, state: Any, **attrs: Any) -> State:
            return State(entity_id, str(state), attrs)

        rows = [
            s("weather.buienradar", "rainy", friendly_name="Buienradar",
              temperature=7.4, humidity=86, wind_speed=21.6,
              temperature_unit="°C"),
            s("climate.slaapkamer_siem", "heat",
              friendly_name="Slaapkamer siem", current_temperature=18.6,
              temperature=19.5, hvac_action="heating"),
            s("climate.woonkamer", "heat", friendly_name="Woonkamer",
              current_temperature=20.8, temperature=20.5,
              hvac_action="idle"),
            s("sensor.slaapkamer_siem_local_temperature", 18.6,
              device_class="temperature", unit_of_measurement="°C",
              friendly_name="Slaapkamer siem Temperature"),
            s("sensor.keuken_temperature", 19.9, device_class="temperature",
              unit_of_measurement="°C", friendly_name="Keuken Temperature"),
            s(hs.POWER, 412, unit_of_measurement="W"),
            s(hs.COST_TODAY, 1.84, unit_of_measurement="EUR"),
            s(hs.COST_MONTH, 38.2, unit_of_measurement="EUR"),
            s(hs.WASHER_POWER, 1840, unit_of_measurement="W"),
            s(hs.WASHER_COST_TODAY, 0.42, unit_of_measurement="EUR"),
            s(hs.SHOPPING_LIST, 5, friendly_name="Shopping list"),
        ]
        return {r.entity_id: r for r in rows}

    def history(self, entity_id: str, *, hours: int = 24,
                points: int = 96) -> list[float | None]:
        import random

        rng = random.Random(f"home:{entity_id}")
        level, out = 300.0, []
        for p in range(points):
            # A base load with a cooking peak and an evening rise.
            level = max(80.0, level + rng.uniform(-60, 60))
            peak = 1500.0 if points * 0.70 < p < points * 0.74 else 0.0
            out.append(round(level + peak))
        return out

    def todo_items(self, entity_id: str) -> list[str]:
        return ["havermelk", "brood", "koffiebonen", "tomaten", "vaatwastabs"]

    def forecast(self, entity_id: str) -> list[dict]:
        days = [("2026-11-24", 9, 4, "rainy", 70), ("2026-11-25", 8, 2, "cloudy", 20),
                ("2026-11-26", 6, 0, "partlycloudy", 10),
                ("2026-11-27", 5, -1, "sunny", 0), ("2026-11-28", 7, 3, "pouring", 90)]
        return [{"datetime": f"{d}T12:00:00+00:00", "temperature": hi,
                 "templow": lo, "condition": c, "precipitation_probability": p}
                for d, hi, lo, c, p in days]
