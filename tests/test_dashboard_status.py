"""The dashboard's two derived fields on /status.

`next_refresh_at` is advisory: it is last-contact plus the refresh interval,
and the panel is free to wake late. The contract that matters is that it is
absent rather than invented when the device has never checked in — the UI
renders a live countdown from it, and a countdown from a fabricated deadline
would be worse than no countdown at all.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,protected-access

from trmnl_server.routes import api as api_module


def test_next_refresh_is_none_before_the_device_has_ever_polled():
    assert api_module._next_refresh_at(None, 900) is None
    assert api_module._next_refresh_at(0, 900) is None


def test_next_refresh_is_none_without_a_usable_interval():
    assert api_module._next_refresh_at(1_700_000_000, None) is None
    assert api_module._next_refresh_at(1_700_000_000, 0) is None


def test_next_refresh_is_last_contact_plus_interval():
    result = api_module._next_refresh_at(1_700_000_000, 900)

    assert result is not None
    # Same encoding the rest of /status uses, so the client parses one format.
    from trmnl_server import utils

    assert result == utils.to_iso_timestamp(1_700_000_900)


def test_next_refresh_still_reports_a_passed_deadline():
    """Overdue is the UI's problem to phrase, not a reason to drop the field.

    The server keeps reporting when the poll was due; the client renders that
    as "due now". Suppressing it here would make a late panel look identical
    to one that has never checked in.
    """
    assert api_module._next_refresh_at(1, 1) is not None


def test_screen_title_is_none_for_an_unknown_or_missing_plugin():
    assert api_module._screen_title_for_plugin(None) is None
    assert api_module._screen_title_for_plugin('') is None
    assert api_module._screen_title_for_plugin('NoSuchPlugin') is None
