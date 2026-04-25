from pathlib import Path

from smart_unpacker.support.resources import find_resource_path


CONFIG_FILENAME = "smart_unpacker_config.json"


def get_config_path() -> Path:
    return find_resource_path(CONFIG_FILENAME) or Path(__file__).resolve().parents[2] / CONFIG_FILENAME
