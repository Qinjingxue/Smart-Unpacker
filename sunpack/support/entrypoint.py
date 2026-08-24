import sys


def main() -> int:
    from sunpack.support.runtime_identity import consume_runtime_id
    from sunpack.support.runtime_mode import RUNTIME_MODE_WATCH, consume_runtime_mode

    try:
        public_argv = consume_runtime_id(sys.argv[1:])
        runtime_mode, public_argv = consume_runtime_mode(public_argv)
    except ValueError as exc:
        print(f"SunPack startup failed: {exc}", file=sys.stderr, flush=True)
        return 2
    # Existing CLI and GUI entry points read sys.argv directly. Remove the
    # process-local private bootstrap arguments before either is entered.
    sys.argv[:] = [sys.argv[0], *public_argv]

    if runtime_mode == RUNTIME_MODE_WATCH:
        from sunpack.gui.main import main as watch_main

        return watch_main()

    from sunpack.cli.persistent_process import handle_early_argv

    early_result = handle_early_argv(sys.argv[1:])
    if early_result is not None:
        return early_result
    from sunpack.cli.cli import main as cli_main

    return cli_main()
