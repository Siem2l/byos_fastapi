"""FastAPI routers for the TRMNL BYOS panel server.

Include order matters: `panel_router` first. It, `api_router` and
`image_router` all live at the app root, and FastAPI resolves the first
registration that matches with no warning on collision. The panel router
owns every path the firmware touches (`/api/*`, `/image/*`,
`/preview/<slug>.png`), and those are the paths where the MAC allowlist,
the Access-Token check and the frame nonces live.
"""

from .panel import router as panel_router
from .api import router as api_router
from .auth import router as auth_router
from .images import router as image_router
from .pages import router as page_router

__all__ = [
    'panel_router', 'api_router', 'auth_router', 'image_router', 'page_router',
]
