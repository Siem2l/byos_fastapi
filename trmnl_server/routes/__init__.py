"""FastAPI routers for the TRMNL BYOS panel server."""

from .panel import router as panel_router

__all__ = ['panel_router']
