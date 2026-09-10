"""PyInstaller entry point for the bundled backend executable.

The desktop app spawns this as `CBOMScan-Backend.exe serve --port N`, so it is
just the normal CLI with a frozen-executable guard for multiprocessing.
"""

import multiprocessing
import sys

from cbomscan.__main__ import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
