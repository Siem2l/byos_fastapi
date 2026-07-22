"""The rotation across a real startup cycle.

`test_rotation_persistence.py` pins the unit that was wrong. This pins the
behaviour anyone actually cares about: boot the app twice against one database
and check the panel is still told to show the same screens.

Against the unfixed code both tests here fail, and they fail the way the live
deployment did — the second boot returns *every* registered screen, including
the one the deployed configuration deliberately excluded, because a
stored-but-emptied row makes `_selected_ids_for_device` fall through to "all
entries" and `Renderer.playlist_for` only falls back to TRMNL_PLAYLIST on zero.
"""

from __future__ import annotations

# pylint: disable=missing-function-docstring,protected-access,redefined-outer-name
# pylint: disable=import-outside-toplevel,unused-argument

import sys

import pytest
from fastapi.testclient import TestClient

from trmnl_server import config as config_module


def _boot(db_path, frames_dir, playlist):
    """Run one full startup cycle; return the default playlist's plugin names.

    Purges the package's modules first so each call starts from the same clean
    module-global state a fresh process would have.
    """
    for name in [m for m in list(sys.modules) if m.startswith("trmnl_server")]:
        del sys.modules[name]

    from trmnl_server import config as cfg_module
    from trmnl_server import models
    from trmnl_server.config import Config
    from trmnl_server.main import create_app
    from trmnl_server.services import state

    cfg_module.pin_database_path(str(db_path))
    models.init_db()

    cfg = Config()
    cfg.state_dir = str(frames_dir)
    cfg.base_url = "https://trmnl.example"
    cfg.synthetic = True
    cfg.playlist = list(playlist)

    with TestClient(create_app(cfg), base_url="https://trmnl.example"):
        snapshot = state.build_rotation_snapshot()

    plugins = [entry.split(":")[0] for entry in snapshot["playlists"]["default"]]
    return plugins, state


@pytest.fixture()
def boot(tmp_path):
    db_path = tmp_path / "trmnl.db"
    frames = tmp_path / "frames"
    original_db = config_module.DATABASE_PATH

    def _run(playlist=("readiness", "homelab")):
        return _boot(db_path, frames, playlist)

    yield _run

    config_module.pin_database_path(original_db)


def test_the_configured_playlist_survives_a_restart(boot):
    first, _ = boot()
    assert sorted(first) == ["HomelabScreenPlugin", "ReadinessScreenPlugin"], (
        "first boot should seed the rotation from TRMNL_PLAYLIST"
    )

    second, _ = boot()

    assert second == first, (
        "restart changed the rotation; an excluded screen coming back is the "
        "exact failure this guards"
    )
    assert "StatsScreenPlugin" not in second


def test_a_ui_edit_survives_a_restart(boot):
    _, state = boot()
    selected = state.build_rotation_snapshot()["playlists"]["default"][:1]
    state.set_default_playlist(list(selected))

    after, _ = boot()

    assert len(after) == 1, f"UI edit was discarded on restart (got {after})"
