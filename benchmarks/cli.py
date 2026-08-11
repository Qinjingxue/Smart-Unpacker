from __future__ import annotations

import argparse
import runpy
import sys

from .registry import SCENARIOS


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SunPack performance benchmark runner")
    parser.add_argument("--list", action="store_true", help="List available scenarios.")
    parser.add_argument("group", nargs="?", choices=sorted({key[0] for key in SCENARIOS}))
    parser.add_argument("scenario", nargs="?")
    parser.add_argument("scenario_args", nargs=argparse.REMAINDER)
    return parser


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
    old_argv = sys.argv
    try:
        sys.argv = [selected.module, *args.scenario_args]
        runpy.run_module(selected.module, run_name="__main__")
    finally:
        sys.argv = old_argv
    return 0
