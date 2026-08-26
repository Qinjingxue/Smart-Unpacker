from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from sunpack.platform.windows.process_launch import launch_unelevated


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a command with the interactive shell's normal user token.")
    parser.add_argument("--cwd", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cwd = str(Path(args.cwd).resolve())
    process = launch_unelevated(args.command, cwd=cwd)
    try:
        try:
            exit_code = process.wait(timeout=max(0.1, args.timeout_seconds))
        except subprocess.TimeoutExpired:
            exit_code = None
        if exit_code is None:
            process.terminate()
            process.wait(timeout=5.0)
            print(f"Unelevated process timed out after {args.timeout_seconds:.1f}s", file=sys.stderr)
            return 124
        return int(exit_code)
    finally:
        close = getattr(process, "close", None)
        if callable(close):
            close()


if __name__ == "__main__":
    raise SystemExit(main())
