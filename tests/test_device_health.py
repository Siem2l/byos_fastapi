"""The wifi-percent guard on the device payload.

`get_wifi_signal_strength` maps an RSSI dBm to 0-100, but it treats any value
>= -50 as full bars — so 0 or None (no reading) would render as 100%. The
gauge must show "no signal" as unknown, not as excellent, so the payload nulls
those out before they reach the meter.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,protected-access

from trmnl_server.routes import api as api_module


def test_wifi_percent_is_none_without_a_reading():
    assert api_module._wifi_percent(None) is None
    assert api_module._wifi_percent(0) is None      # no reading, not full bars
    assert api_module._wifi_percent(42) is None      # positive is not a real RSSI


def test_wifi_percent_maps_a_real_rssi():
    assert api_module._wifi_percent(-100) == 0
    assert api_module._wifi_percent(-50) == 100
    # -75 dBm -> 2 * (-75 + 100) = 50
    assert api_module._wifi_percent(-75) == 50
