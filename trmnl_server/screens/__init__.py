"""Screen registry. Importing a screen module is what registers it."""

from .base import REGISTRY, Context, Screen, available, get, register  # noqa: F401
from . import readiness  # noqa: F401  (import for side-effect: registration)
from . import homelab  # noqa: F401  (ditto)
from . import stats  # noqa: F401  (ditto)

__all__ = ["REGISTRY", "Context", "Screen", "available", "get", "register"]
