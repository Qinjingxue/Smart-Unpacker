from typing import List, Dict, Any
from dataclasses import dataclass

from packrelic.contracts.run_context import RunContext
from packrelic.coordinator.task_scan import ArchiveTaskScanner

@dataclass
class ScanResult:
    logical_name: str
    main_path: str
    all_parts: List[str]
    should_extract: bool
    score: int
    stop_reason: str
    matched_rules: List[str]
    detected_ext: str
    fact_bag: object
    decision: str

class ScanOrchestrator:
    def __init__(self, config: Dict[str, Any]):
        self.task_scanner = ArchiveTaskScanner(config, RunContext())

    def scan(self, root_dir: str) -> List[ScanResult]:
        return self.scan_targets([root_dir])

    def scan_targets(self, target_paths: List[str]) -> List[ScanResult]:
        return [
            ScanResult(
                logical_name=task.logical_name,
                main_path=task.main_path,
                all_parts=list(task.all_parts),
                should_extract=True,
                score=task.score,
                stop_reason=task.stop_reason,
                matched_rules=list(task.matched_rules),
                detected_ext=task.detected_ext,
                fact_bag=task.fact_bag,
                decision=task.decision,
            )
            for task in self.task_scanner.scan_targets(target_paths)
        ]
