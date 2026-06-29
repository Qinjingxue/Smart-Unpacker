import os
import sys
from pathlib import Path

# Ensure import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def _main():
    if getattr(sys, "frozen", False) and Path(sys.executable).name.lower() == "sunpack-watch.exe":
        from sunpack.gui.main import main
    else:
        from sunpack.cli.cli import main
    return main()

if __name__ == "__main__":
    sys.exit(_main())
