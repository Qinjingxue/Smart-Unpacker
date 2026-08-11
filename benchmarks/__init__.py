"""SunPack opt-in performance and profiling scenarios.

The package is intentionally outside ``tests``: scenarios report measurements,
while pytest tests assert product behaviour.
"""

from .registry import SCENARIOS

__all__ = ["SCENARIOS"]
