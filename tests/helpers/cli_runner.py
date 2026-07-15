import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def run_cli(repo_root: Path, args: list[str], timeout: int = 20) -> dict[str, Any]:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(repo_root), existing_pythonpath) if part
    )
    result = subprocess.run(
        [sys.executable, "-B", "sunpack.py", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=timeout,
    )
    payload: dict[str, Any] = {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
    if result.stdout.strip().startswith("{"):
        payload["json"] = json.loads(result.stdout)
    return payload

