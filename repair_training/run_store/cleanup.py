from __future__ import annotations

import os
import subprocess
from pathlib import Path


def remove_tree_fast(path: str | Path, *, root: str | Path) -> bool:
    target = Path(path).resolve()
    allowed_root = Path(root).resolve()
    if target == allowed_root or allowed_root not in target.parents:
        raise ValueError(f"refusing to remove path outside allowed root: {target}")
    if not target.exists():
        return False
    command = "& { param($p) Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue }"
    for candidate in (str(target), "\\\\?\\" + str(target)):
        subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
                candidate,
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not target.exists():
            return True
    return not target.exists()
