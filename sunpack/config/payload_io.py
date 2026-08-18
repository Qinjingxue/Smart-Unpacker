from pathlib import Path

from sunpack.config.loader import load_effective_config_payload
from sunpack.support.json_format import write_json_file


def read_config_payload(request_cwd: str | Path | None = None) -> tuple[Path, dict]:
    return load_effective_config_payload(request_cwd)


def write_config_payload(config_path: Path, payload: dict):
    write_json_file(config_path, payload)
