from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectionOptions:
    deep_scan: bool = False
