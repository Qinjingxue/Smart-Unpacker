import os
import sys


def main() -> int:
    from sunpack.support.runtime_identity import consume_runtime_id

    try:
        public_argv = consume_runtime_id(sys.argv[1:])
    except ValueError as exc:
        print(f"SunPack startup failed: {exc}", file=sys.stderr, flush=True)
        return 2
    # Existing CLI and GUI entry points read sys.argv directly.  Remove the
    # native launcher's private identity argument before either is entered.
    sys.argv[:] = [sys.argv[0], *public_argv]

    if _is_watch_executable():
        from sunpack.gui.main import main as watch_main

        return watch_main()

    from sunpack.cli.persistent_process import handle_early_argv

    early_result = handle_early_argv(sys.argv[1:])
    if early_result is not None:
        return early_result
    from sunpack.cli.cli import main as cli_main

    return cli_main()


def _is_watch_executable() -> bool:
    executable_names = (sys.executable, sys.argv[0] if sys.argv else "")
    return any(os.path.basename(path).lower() == "sunpack-watch.exe" for path in executable_names)
