from typing import Any

from packrelic.filesystem.filters.base import ScanCandidate, ScanDecision, keep, reject


class SizeMinimumScanFilter:
    name = "size_minimum"
    stage = "size"

    def __init__(self, min_inspection_size_bytes: int | None = None):
        self.min_inspection_size_bytes = min_inspection_size_bytes

    @classmethod
    def from_config(cls, config: dict[str, Any]):
        return cls(config.get("min_inspection_size_bytes"))

    def evaluate(self, candidate: ScanCandidate) -> ScanDecision:
        if candidate.kind != "file":
            return keep()
        if self.min_inspection_size_bytes is None:
            return keep()
        if candidate.size is None or candidate.size < 0:
            return keep()
        if candidate.size < int(self.min_inspection_size_bytes):
            return reject(f"File size below minimum threshold: {candidate.size} < {self.min_inspection_size_bytes}")
        return keep()
