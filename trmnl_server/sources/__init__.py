"""Data sources. Each is duck-typed against what its screens ask for."""

from .garmin import GarminSource  # noqa: F401
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
    "Probe",
    "PrometheusError",
    "PrometheusSource",
    "Sample",
    "SyntheticGarminSource",
    "SyntheticPrometheusSource",
]
