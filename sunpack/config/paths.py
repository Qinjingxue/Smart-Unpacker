from pathlib import Path

from sunpack.support.resources import find_resource_path


CONFIG_FILENAME = "sunpack_config.json"


def get_config_path() -> Path:
    return find_resource_path(CONFIG_FILENAME) or Path(__file__).resolve().parents[2] / CONFIG_FILENAME
