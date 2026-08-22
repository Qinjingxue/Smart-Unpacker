from __future__ import annotations

import argparse
import asyncio
import os
import sys
import traceback
from datetime import datetime, timezone

from sunpack.filesystem.watcher.log import append_jsonl_record
from sunpack.support.resources import get_resource_path
from sunpack.support.runtime_cwd import runtime_working_directory


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parse_args(argv)
        if _request_watch_elevation(args):
            return 0
        os.chdir(runtime_working_directory())
        from sunpack.platform.windows.process_qos import enter_background_processing

        enter_background_processing()
        return _run_watch_service(
            once=args.once,
            no_tray=args.no_tray,
            initial_scan=args.initial_scan,
        )
    except Exception as exc:
        _write_bootstrap_error(exc)
        return 1


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--no-tray", action="store_true")
    parser.add_argument("--initial-scan", action="store_true")
    return parser.parse_args(sys.argv[1:] if argv is None else argv)


def _run_watch_service(*, once: bool, no_tray: bool, initial_scan: bool = False) -> int:
    from sunpack.coordinator.watch_runtime import run_watch_service

    return asyncio.run(
        run_watch_service(
            tray_enabled=not no_tray,
            once=once,
            initial_scan=initial_scan,
        )
    )


def _request_watch_elevation(args: argparse.Namespace) -> bool:
    from sunpack.gui.launcher import watch_launch_argv
    from sunpack.platform.windows.elevation import relaunch_elevated

    return relaunch_elevated(
        watch_launch_argv(
            once=bool(args.once),
            no_tray=bool(args.no_tray),
            initial_scan=bool(args.initial_scan),
            prefer_windowed_python=True,
        ),
        cwd=runtime_working_directory(),
    )


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
        append_jsonl_record(state_dir / "events.jsonl", payload)
    except Exception:
        pass
