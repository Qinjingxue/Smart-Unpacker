from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class WatchLogStore:
    def __init__(self, path: str):
        self.path = Path(path)

    def write(self, event: str, **payload: Any) -> None:
        record = {
            "ts": time.time(),
            "event": event,
            **payload,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        except Exception:
            return
