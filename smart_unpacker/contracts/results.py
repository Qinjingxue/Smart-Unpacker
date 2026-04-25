from dataclasses import dataclass
from typing import List

@dataclass
class RunSummary:
    success_count: int
    failed_tasks: List[str]
    processed_keys: List[str]
