import threading
from typing import List, Set


class RunContext:
    def __init__(self):
        self.lock = threading.Lock()
        self.success_count: int = 0
        self.failed_tasks: List[str] = []
        self.processed_keys: Set[str] = set()
        self.unpacked_archives: List[List[str]] = []
        self.flatten_candidates: Set[str] = set()
