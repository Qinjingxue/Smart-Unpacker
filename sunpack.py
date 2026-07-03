import os
import sys

# Ensure import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def _main():
    if getattr(sys, "frozen", False) and os.path.basename(sys.executable).lower() == "sunpack-watch.exe":
        from sunpack.gui.main import main
    else:
        from sunpack.cli.persistent_process import handle_early_argv

        early_result = handle_early_argv(sys.argv[1:])
        if early_result is not None:
            return early_result
        from sunpack.cli.cli import main
    return main()

if __name__ == "__main__":
    sys.exit(_main())
