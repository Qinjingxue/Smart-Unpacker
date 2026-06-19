"""Archive detection pipeline.

This package keeps fact collection, fact processing, and rule evaluation
together because those layers cooperate to decide whether a file is an archive.
"""

from sunpack.detection.scheduler import DetectionResult, DetectionScheduler
from sunpack.detection.validation import validate_detection_contracts

__all__ = [
    "DetectionResult",
    "DetectionScheduler",
    "validate_detection_contracts",
]
