import os
import subprocess


def detect_max_workers() -> int:
    cpu_count = os.cpu_count() or 4
    if os.name == "nt":
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-PhysicalDisk | Select-Object -Property MediaType"],
                capture_output=True,
                text=True,
                stdin=subprocess.DEVNULL,
            )
            if "SSD" in result.stdout.upper():
                return max(2, cpu_count)
        except Exception:
            pass
    return 2


def resolve_max_workers() -> int:
    return max(1, detect_max_workers())
