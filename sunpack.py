import os
import sys

# Ensure import path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sunpack.support.entrypoint import main

if __name__ == "__main__":
    raise SystemExit(main())
