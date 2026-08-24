"""Process-local entry mode for the shared packaged runtime."""

from __future__ import annotations


RUNTIME_MODE_ARGUMENT_PREFIX = "--_sunpack-mode="
RUNTIME_MODE_CLI = "cli"
RUNTIME_MODE_WATCH = "watch"
RUNTIME_MODES = frozenset({RUNTIME_MODE_CLI, RUNTIME_MODE_WATCH})


def consume_runtime_mode(argv: list[str]) -> tuple[str, list[str]]:
    """Remove and validate the private runtime mode argument from *argv*.

    The mode is intentionally returned instead of stored globally. Each
    runtime process selects one entry path at startup, while separate runtime
    processes can independently serve CLI requests and watch the filesystem.
    """

    mode = RUNTIME_MODE_CLI
    found = False
    public_argv: list[str] = []
    for item in argv:
        if not item.startswith(RUNTIME_MODE_ARGUMENT_PREFIX):
            public_argv.append(item)
            continue
        if found:
            raise ValueError("duplicate SunPack runtime mode")
        found = True
        mode = item[len(RUNTIME_MODE_ARGUMENT_PREFIX) :]
        if mode not in RUNTIME_MODES:
            raise ValueError(f"invalid SunPack runtime mode: {mode!r}")
    return mode, public_argv


def runtime_mode_argument(mode: str) -> str:
    if mode not in RUNTIME_MODES:
        raise ValueError(f"invalid SunPack runtime mode: {mode!r}")
    return RUNTIME_MODE_ARGUMENT_PREFIX + mode
