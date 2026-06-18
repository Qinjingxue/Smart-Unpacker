from dataclasses import dataclass, field
from typing import List

from sunpack.contracts.failures import FailureInfo

@dataclass
class RunSummary:
    success_count: int
    failed_tasks: List[str]
    processed_keys: List[str]
    partial_success_count: int = 0
    recovered_outputs: List[dict] = field(default_factory=list)
    failures: List[FailureInfo] = field(default_factory=list)
