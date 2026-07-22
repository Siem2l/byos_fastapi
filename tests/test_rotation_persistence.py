"""The saved rotation must survive a restart.

These are regression tests for a bug that silently changed what the panel
displayed. `_prune_missing_selected_ids` drops selected IDs that no longer
appear in `meta`, which is right on a settled rotation and wrong while one is
being built: at startup `initialize_rotation_playlists_from_storage()` loads
the saved selection and *then* the plugins render. Each append pruned the
selection against a `meta` that was still filling, so every saved ID looked
missing, the selection was emptied, and `persist_default_playlist([])` wrote
that emptiness back to the database.

The consequence was not an empty panel — it was the opposite. With a stored
row present but empty, `_selected_ids_for_device` falls through to "every
entry in meta", so the panel rotated screens the deployed configuration had
deliberately excluded, and `TRMNL_PLAYLIST` never applied because the
fallback in `Renderer.playlist_for` only fires on *zero* resolved slugs.

Guarding just the first append is not a fix, and the second test here is the
one that says so: `refresh_plugin_assets` gathers the plugins concurrently, so
appends after the first still see a partial `meta`. That turns a reproducible
wipe into an order-dependent one, which is strictly worse — it would pass a
single restart check and then drop a screen later.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,protected-access,redefined-outer-name

import pytest

from trmnl_server.services import state as state_module


def _master(selected, meta_ids):
    return {
        'selected_ids': list(selected),
        'meta': [{'id': entry_id, 'plugin': entry_id} for entry_id in meta_ids],
    }


@pytest.fixture(autouse=True)
def _clear_population_guard():
    """Never let a failed test leak the guard into the next one."""
    yield
    state_module._rotation_populating = 0


def test_prune_drops_ids_absent_from_a_settled_rotation():
    """The pruning behaviour itself is still wanted — this is the control."""
    master = _master(['a', 'b'], ['a'])

    assert state_module._prune_missing_selected_ids(master) is True
    assert master['selected_ids'] == ['a']


def test_prune_is_suppressed_while_the_rotation_is_populating():
    master = _master(['a', 'b'], [])

    with state_module.rotation_population():
        assert state_module._prune_missing_selected_ids(master) is False

    assert master['selected_ids'] == ['a', 'b'], "saved selection was destroyed"


def test_prune_is_suppressed_against_a_partially_filled_rotation():
    """The case a first-append-only guard would miss.

    `meta` holds one of the two screens because that plugin finished first.
    Pruning here would silently drop 'b' — the screen that is merely slower.
    """
    master = _master(['a', 'b'], ['a'])

    with state_module.rotation_population():
        assert state_module._prune_missing_selected_ids(master) is False

    assert master['selected_ids'] == ['a', 'b']


def test_guard_is_reentrant_and_only_clears_at_the_outermost_exit():
    master = _master(['a'], [])

    with state_module.rotation_population():
        with state_module.rotation_population():
            assert state_module.rotation_is_populating() is True
        # Still inside the outer window: the guard must not have lifted.
        assert state_module.rotation_is_populating() is True
        assert state_module._prune_missing_selected_ids(master) is False

    assert state_module.rotation_is_populating() is False


def test_guard_lifts_even_when_population_raises():
    with pytest.raises(RuntimeError):
        with state_module.rotation_population():
            raise RuntimeError("a plugin blew up mid-render")

    assert state_module.rotation_is_populating() is False
    master = _master(['a', 'b'], ['a'])
    assert state_module._prune_missing_selected_ids(master) is True
