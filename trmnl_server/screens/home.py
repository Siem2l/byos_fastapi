"""The house at a glance: weather, rooms, electricity, washing, shopping.

Everything comes from Home Assistant (`sources/home_assistant.py`).

* Rooms are discovered, not listed: every `climate` entity, plus every
  temperature sensor that is not the same device's own reading of a
  climate entity already shown. A new radiator valve or Zigbee sensor
  appears without touching this file.
* A room that is heating is knocked out — white on black — because that
  is the one state worth noticing from across the room.
* Electricity, the washing machine and the shopping list are fixed
  entity IDs below: they are particular devices, and guessing which
  power sensor is "the house" would pick the wrong one.
* Only `states()` failing blanks the screen. The forecast, the power
  history and the shopping list are extras; if one of them fails, its
  corner says so and the rest still draws.
"""

from __future__ import annotations

from datetime import datetime

from ..canvas import WHITE, Box, Canvas
from ..sources.home_assistant import HomeAssistantError, State, to_float
from .base import Context, Screen, register

MARGIN = 24
COL_GAP = 24

# Preferred weather entity; any other `weather.*` is used when it is absent.
WEATHER = "weather.buienradar"
POWER = "sensor.p1_meter_power"
COST_TODAY = "sensor.stroomkosten_vandaag"
COST_MONTH = "sensor.stroomkosten_deze_maand"
WASHER_POWER = "sensor.badkamer_wasmachine_power"
WASHER_COST_TODAY = "sensor.wasmachine_kosten_vandaag"
SHOPPING_LIST = "todo.shopping_list"

# Watts. A washing machine on standby draws one or two; a wash, hundreds.
WASHER_RUNNING = 5.0

CONDITIONS = {
    "clear-night": "Clear",
    "cloudy": "Cloudy",
    "exceptional": "Exceptional",
    "fog": "Fog",
    "hail": "Hail",
    "lightning": "Thunder",
    "lightning-rainy": "Thunderstorm",
    "partlycloudy": "Partly cloudy",
    "pouring": "Pouring",
    "rainy": "Rain",
    "snowy": "Snow",
    "snowy-rainy": "Sleet",
    "sunny": "Sunny",
    "windy": "Windy",
    "windy-variant": "Windy",
}
SHORT = {
    "partlycloudy": "Clouds", "lightning-rainy": "Storm",
    "snowy-rainy": "Sleet", "windy-variant": "Windy", "clear-night": "Clear",
}


def _optional(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except HomeAssistantError:
        return None


def _object_id(entity_id: str) -> str:
    return entity_id.split(".", 1)[-1]


def rooms(states: dict[str, State]) -> list[dict]:
    out = []
    climates = [s for s in states.values() if s.entity_id.startswith("climate.")]
    for c in climates:
        out.append({
            "name": c.name,
            "current": c.attr_number("current_temperature"),
            "target": c.attr_number("temperature"),
            "heating": c.attributes.get("hvac_action") == "heating",
        })
    covered = [_object_id(c.entity_id) for c in climates]
    for s in states.values():
        if (not s.entity_id.startswith("sensor.")
                or s.attributes.get("device_class") != "temperature"
                or any(_object_id(s.entity_id).startswith(c) for c in covered)):
            continue
        name = s.name
        for suffix in (" Temperature", " temperature", " Temperatuur"):
            name = name.removesuffix(suffix)
        out.append({"name": name, "current": s.number, "target": None,
                    "heating": False})
    return sorted(out, key=lambda r: r["name"].lower())


def _weather(states: dict[str, State]) -> State | None:
    if WEATHER in states:
        return states[WEATHER]
    others = sorted(k for k in states if k.startswith("weather."))
    return states[others[0]] if others else None


def _num(states: dict[str, State], entity_id: str) -> float | None:
    state = states.get(entity_id)
    return state.number if state else None


@register
class HomeScreen(Screen):
    slug = "home"
    title = "Home"
    refresh_seconds = 300

    def fetch(self, ctx: Context) -> dict:
        ha = ctx.source("home_assistant")
        states = ha.states()
        weather = _weather(states)
        shopping = states.get(SHOPPING_LIST)
        return {
            "generated_at": datetime.now(),
            "weather": weather and {
                "temperature": weather.attr_number("temperature"),
                "condition": weather.state,
                "humidity": weather.attr_number("humidity"),
                "wind": weather.attr_number("wind_speed"),
            },
            "forecast": weather and _optional(ha.forecast, weather.entity_id),
            "rooms": rooms(states),
            "power": _num(states, POWER),
            "power_history": _optional(ha.history, POWER, hours=24,
                                       points=96),
            "cost_today": _num(states, COST_TODAY),
            "cost_month": _num(states, COST_MONTH),
            "washer_power": _num(states, WASHER_POWER),
            "washer_cost": _num(states, WASHER_COST_TODAY),
            "shopping": (_optional(ha.todo_items, SHOPPING_LIST)
                         if shopping else None),
        }

    def render(self, c: Canvas, d: dict) -> None:
        c.text(MARGIN, 16, "HOME", size=30, bold=True, tracking=2)
        c.text(c.width - MARGIN, 24,
               d["generated_at"].strftime("%a %d %b · %H:%M").upper(),
               size=13, bold=True, anchor="ra", tracking=1)
        c.hline(MARGIN, 54, c.width - MARGIN, weight=3)

        half = (c.width - 2 * MARGIN - COL_GAP) // 2
        left = Box(MARGIN, 66, half, 0)
        right = Box(MARGIN + half + COL_GAP, 66, half, 0)
        c.vline(MARGIN + half + COL_GAP // 2, 66, c.height - 12)

        self._weather(c, left, d["weather"], d["forecast"])
        self._rooms(c, right, d["rooms"])
        c.hline(MARGIN, 258, left.right, weight=1)
        c.hline(right.x, 258, c.width - MARGIN, weight=1)
        self._electricity(c, Box(left.x, 270, half, 200), d)
        self._washer(c, Box(right.x, 270, half, 64), d)
        self._shopping(c, Box(right.x, 344, half, 126), d["shopping"])

    # ---- blocks ---------------------------------------------------------

    def _weather(self, c: Canvas, box: Box, now: dict | None,
                 forecast: list[dict] | None) -> None:
        c.label(box.x, box.y, "weather", size=11)
        if not now:
            c.text(box.x, box.y + 24, "No weather in Home Assistant", size=16,
                   bold=True)
            c.text(box.x, box.y + 48, "Add the Buienradar integration.",
                   size=13)
            return
        temp = now["temperature"]
        c.text(box.x, box.y + 16, "–" if temp is None else f"{temp:.0f}°",
               size=60, bold=True)
        cond = CONDITIONS.get(now["condition"], now["condition"].title())
        c.text(box.x + 130, box.y + 26, c.clip(cond, box.w - 130, size=20,
                                               bold=True), size=20, bold=True)
        details = []
        if now["humidity"] is not None:
            details.append(f"{now['humidity']:.0f}% humidity")
        if now["wind"] is not None:
            details.append(f"wind {now['wind']:.0f} km/h")
        c.text(box.x + 130, box.y + 56, " · ".join(details), size=13)

        if not forecast:
            return
        days = forecast[:5]
        cols = Box(box.x, box.y + 100, box.w, 84).split_h(len(days), gap=6)
        for col, day in zip(cols, days):
            when = _when(day.get("datetime"))
            c.label(col.x, col.y, when.strftime("%a") if when else "?",
                    size=11)
            hi, lo = to_float(day.get("temperature")), to_float(
                day.get("templow"))
            temps = "/".join("–" if t is None else f"{t:.0f}°" for t in (hi, lo))
            c.text(col.x, col.y + 18, temps, size=16, bold=True)
            cond = str(day.get("condition") or "")
            short = SHORT.get(cond, CONDITIONS.get(cond, cond.title()))
            c.text(col.x, col.y + 42, c.clip(short, col.w, size=12), size=12)
            rain = to_float(day.get("precipitation_probability"))
            if rain is not None:
                c.text(col.x, col.y + 60, f"rain {rain:.0f}%", size=12)

    def _rooms(self, c: Canvas, box: Box, rows: list[dict]) -> None:
        c.label(box.x, box.y, "rooms", size=11)
        if not rows:
            c.text(box.x, box.y + 24, "No temperature sensors", size=16)
            return
        pitch = 42 if len(rows) <= 4 else 34
        for i, r in enumerate(rows[: (258 - 12 - box.y - 18) // pitch]):
            cell = Box(box.x, box.y + 20 + i * pitch, box.w, pitch - 6)
            ink = 0
            if r["heating"]:
                c.fill(cell, shade="solid")
                ink = WHITE
            temp = "–" if r["current"] is None else f"{r['current']:.1f}°"
            temp_w = c.text_width(temp, size=24, bold=True)
            note = ""
            if r["target"] is not None:
                note = f"→ {r['target']:.1f}°"
            if r["heating"]:
                note = f"heating {note}".strip()
            mid = cell.y + (cell.h - 24) // 2 - 2
            c.text(cell.right - 6, mid, temp, size=24, bold=True, anchor="ra",
                   ink=ink)
            name_w = cell.w - temp_w - 24
            c.text(cell.x + 6, cell.y + 2,
                   c.clip(r["name"], name_w, size=16, bold=True), size=16,
                   bold=True, ink=ink)
            if note:
                c.text(cell.x + 6, cell.y + 20, note, size=12, ink=ink)

    def _electricity(self, c: Canvas, box: Box, d: dict) -> None:
        c.label(box.x, box.y, "electricity", size=11)
        power = d["power"]
        c.text(box.x, box.y + 16,
               "–" if power is None else f"{power:,.0f} W",
               size=40, bold=True)
        costs = []
        if d["cost_today"] is not None:
            costs.append(f"today €{d['cost_today']:.2f}")
        if d["cost_month"] is not None:
            costs.append(f"month €{d['cost_month']:.2f}")
        for i, line in enumerate(costs):
            c.text(box.right, box.y + 20 + i * 22, line, size=15,
                   anchor="ra")
        history = d["power_history"]
        if history and sum(v is not None for v in history) > 1:
            c.label(box.x, box.y + 74, "last 24 hours", size=11)
            c.sparkline(Box(box.x, box.y + 92, box.w, box.bottom - box.y - 104),
                        history, weight=2)
        else:
            c.text(box.x, box.y + 80, "no power history", size=13)

    def _washer(self, c: Canvas, box: Box, d: dict) -> None:
        c.label(box.x, box.y, "washing machine", size=11)
        power = d["washer_power"]
        if power is None:
            state = "–"
        elif power >= WASHER_RUNNING:
            state = f"running · {power:,.0f} W"
        else:
            state = "idle"
        c.text(box.x, box.y + 18, state, size=20, bold=True)
        if d["washer_cost"] is not None:
            c.text(box.right, box.y + 22, f"today €{d['washer_cost']:.2f}",
                   size=13, anchor="ra")

    def _shopping(self, c: Canvas, box: Box, items: list[str] | None) -> None:
        if items is None:
            c.label(box.x, box.y, "shopping list", size=11)
            c.text(box.x, box.y + 20, "–", size=14)
            return
        c.label(box.x, box.y, f"shopping list · {len(items)}", size=11)
        if not items:
            c.text(box.x, box.y + 20, "nothing to buy", size=14)
            return
        cols = box.split_h(2, gap=12)
        per_col = (box.h - 20) // 20
        for i, item in enumerate(items[: per_col * 2]):
            col = cols[i // per_col]
            y = box.y + 20 + (i % per_col) * 20
            c.text(col.x, y, "· " + c.clip(item, col.w - 12, size=14),
                   size=14)


def _when(raw) -> datetime | None:
    try:
        return datetime.fromisoformat(str(raw))
    except ValueError:
        return None
