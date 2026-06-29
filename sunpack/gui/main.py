from __future__ import annotations

import json
import traceback
from datetime import datetime, timezone

from sunpack.support.resources import get_resource_path


def main() -> int:
    try:
        return _run_watch_service()
    except Exception as exc:
        _write_bootstrap_error(exc)
        return 1


def _run_watch_service() -> int:
    from sunpack.coordinator.watch_runtime import run_watch_service

    return run_watch_service(tray_enabled=True)


def _write_bootstrap_error(exc: BaseException) -> None:
    try:
        state_dir = get_resource_path(".sunpack_watch")
        state_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "gui_bootstrap_error",
            "error_type": type(exc).__name__,
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }
        with (state_dir / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
    except Exception:
        pass
