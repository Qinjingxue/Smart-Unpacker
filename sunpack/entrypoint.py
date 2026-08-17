import os
import sys


def main() -> int:
    is_compiled = getattr(sys, "frozen", False) or "__compiled__" in globals()
    if is_compiled and os.path.basename(sys.executable).lower() == "sunpack-watch.exe":
        from sunpack.gui.main import main as watch_main

        return watch_main()

    from sunpack.cli.persistent_process import handle_early_argv

    early_result = handle_early_argv(sys.argv[1:])
    if early_result is not None:
        return early_result
    from sunpack.cli.cli import main as cli_main

    return cli_main()
