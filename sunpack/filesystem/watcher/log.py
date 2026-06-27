from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class WatchLogStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self._throttle_lock = threading.Lock()
        self._last_throttled_write: dict[tuple[str, str], float] = {}

    def write(self, event: str, **payload: Any) -> None:
        record = {
            "ts": time.time(),
            "time": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **payload,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        except Exception:
            return

    def write_throttled(
        self,
        event: str,
        *,
        throttle_key: str,
        interval_seconds: float,
        **payload: Any,
    ) -> None:
        now = time.monotonic()
        token = (event, str(throttle_key))
        with self._throttle_lock:
            previous = self._last_throttled_write.get(token)
            if previous is not None and now - previous < max(0.0, interval_seconds):
                return
            self._last_throttled_write[token] = now
            if len(self._last_throttled_write) > 2048:
                oldest = min(self._last_throttled_write, key=self._last_throttled_write.get)
                self._last_throttled_write.pop(oldest, None)
        self.write(event, **payload)
