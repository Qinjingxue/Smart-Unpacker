from __future__ import annotations

import argparse
import os
import subprocess
import sys

from .registry import SCENARIOS

# A scenario that makes a stale API call must fail loudly instead of hanging the
# whole benchmark run.  Every scenario therefore runs in a child process under
# a hard wall-clock deadline; on expiry the child is killed and the run reports
# exit code 124 (the conventional "timeout" status).
DEFAULT_TIMEOUT_SECONDS = float(os.environ.get("SUNPACK_BENCH_TIMEOUT", "3600"))
TIMEOUT_EXIT_CODE = 124


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SunPack performance benchmark runner")
    parser.add_argument("--list", action="store_true", help="List available scenarios.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=(
            "Hard wall-clock limit in seconds for the whole scenario "
            f"(default: {DEFAULT_TIMEOUT_SECONDS:g}; env SUNPACK_BENCH_TIMEOUT). "
            "On expiry the scenario process is killed and the run exits with "
            f"{TIMEOUT_EXIT_CODE}."
        ),
    )
    parser.add_argument("group", nargs="?", choices=sorted({key[0] for key in SCENARIOS}))
    parser.add_argument("scenario", nargs="?")
    parser.add_argument("scenario_args", nargs=argparse.REMAINDER)
    return parser


def _run_scenario_in_subprocess(module: str, scenario_args: list[str], timeout: float) -> int:
    """Run one scenario module in a child process with a hard timeout.

    The child inherits stdout/stderr so real-time progress stays visible, and
    its exit code becomes the benchmark's exit code.  A stale scenario that
    blocks forever is killed by ``subprocess.run``'s timeout and reported as
    ``TIMEOUT_EXIT_CODE`` instead of hanging the parent.
    """
    command = [sys.executable, "-m", module, *scenario_args]
    try:
        completed = subprocess.run(command, cwd=os.getcwd(), timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        print(
            f"benchmark timed out after {timeout:g}s and was killed: {' '.join(command)}",
            file=sys.stderr,
            flush=True,
        )
        return TIMEOUT_EXIT_CODE
    return int(completed.returncode)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.list:
        for scenario in SCENARIOS.values():
            print(f"{scenario.group:10} {scenario.name:24} {scenario.description}")
        return 0
    if not args.group or not args.scenario:
        _parser().error("group and scenario are required unless --list is used")
    selected = SCENARIOS.get((args.group, args.scenario))
    if selected is None:
        names = ", ".join(name for group, name in SCENARIOS if group == args.group)
        _parser().error(f"unknown {args.group} scenario {args.scenario!r}; choose one of: {names}")
    if args.timeout <= 0:
        _parser().error("--timeout must be positive")
    return _run_scenario_in_subprocess(selected.module, list(args.scenario_args), args.timeout)
