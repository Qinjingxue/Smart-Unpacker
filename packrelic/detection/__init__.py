"""Archive detection pipeline.

This package keeps fact collection, fact processing, and rule evaluation
together because those layers cooperate to decide whether a file is an archive.
"""

from packrelic.detection.scheduler import DetectionResult, DetectionScheduler
from packrelic.detection.nested_scan_policy import NestedOutputScanPolicy
from packrelic.detection.task_provider import ArchiveTaskProvider
from packrelic.detection.validation import validate_detection_contracts

__all__ = [
    "ArchiveTaskProvider",
    "DetectionResult",
    "DetectionScheduler",
    "NestedOutputScanPolicy",
    "validate_detection_contracts",
]
