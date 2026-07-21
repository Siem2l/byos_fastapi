"""Data sources. Each is duck-typed against what its screens ask for."""

from .garmin import GarminSource  # noqa: F401
from .synthetic import SyntheticGarminSource  # noqa: F401

__all__ = ["GarminSource", "SyntheticGarminSource"]
