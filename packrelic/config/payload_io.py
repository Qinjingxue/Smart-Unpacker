from pathlib import Path

from packrelic.config.loader import load_config
from packrelic.config.paths import get_config_path
from packrelic.support.json_format import load_json_file, write_json_file


def read_config_payload() -> tuple[Path, dict]:
    config_path = get_config_path()
    if not config_path.exists():
        return config_path, load_config()
    return config_path, load_json_file(config_path)


def write_config_payload(config_path: Path, payload: dict):
    write_json_file(config_path, payload)
