"""Data sources. Each is duck-typed against what its screens ask for."""

from .garmin import GarminSource  # noqa: F401
from .home_assistant import (  # noqa: F401
    HomeAssistantError,
    HomeAssistantSource,
    SyntheticHomeAssistantSource,
)
from .life import LifeSource, SyntheticLifeSource  # noqa: F401
from .prometheus import (  # noqa: F401
    Probe,
    PrometheusError,
    PrometheusSource,
    Sample,
)
from .synthetic import (  # noqa: F401
    SyntheticGarminSource,
    SyntheticPrometheusSource,
)

__all__ = [
    "GarminSource",
    "HomeAssistantError",
    "HomeAssistantSource",
    "LifeSource",
    "Probe",
    "PrometheusError",
    "PrometheusSource",
    "Sample",
    "SyntheticGarminSource",
    "SyntheticHomeAssistantSource",
    "SyntheticLifeSource",
    "SyntheticPrometheusSource",
]
