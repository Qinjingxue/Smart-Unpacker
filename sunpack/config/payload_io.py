from pathlib import Path

from sunpack.config.loader import load_effective_config_payload
def read_config_payload(request_cwd: str | Path | None = None) -> tuple[Path, dict]:
    return load_effective_config_payload(request_cwd)
