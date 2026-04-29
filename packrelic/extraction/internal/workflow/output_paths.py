import os

from packrelic.contracts.tasks import ArchiveTask
from packrelic.support.path_keys import normalized_path


def default_output_dir_for_task(task: ArchiveTask, output_config: dict | None = None) -> str:
    output_config = output_config if isinstance(output_config, dict) else {}
    path = task.main_path
    out_name = task.logical_name or os.path.splitext(os.path.basename(path))[0]
    if output_config.get("root"):
        output_root = os.path.abspath(os.path.normpath(str(output_config.get("root"))))
        common_root = output_config.get("common_root")
        relative_parent = _relative_parent(path, common_root)
        out_dir = os.path.join(output_root, relative_parent, os.path.basename(out_name))
    else:
        out_dir = os.path.join(os.path.dirname(path), os.path.basename(out_name))
    if normalized_path(out_dir) == normalized_path(path):
        out_dir += "_extracted"
    return _non_existing_output_dir(out_dir)


def _relative_parent(path: str, common_root: str | None) -> str:
    parent = os.path.dirname(os.path.abspath(os.path.normpath(path)))
    if not common_root:
        return ""
    root = os.path.abspath(os.path.normpath(str(common_root)))
    try:
        relative = os.path.relpath(parent, root)
    except ValueError:
        return _safe_path_component(parent)
    if relative in {"", "."}:
        return ""
    if relative.startswith("..") and (relative == ".." or relative.startswith(".." + os.sep)):
        return _safe_path_component(parent)
    return relative


def _safe_path_component(value: str) -> str:
    drive, tail = os.path.splitdrive(os.path.abspath(value))
    text = (drive.rstrip(":") + "_" + tail.strip(os.sep)).strip("_")
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in text) or "input"


def _non_existing_output_dir(path: str) -> str:
    if not os.path.exists(path):
        return path

    base = f"{path}_extracted"
    if not os.path.exists(base):
        return base

    index = 2
    while True:
        candidate = f"{base}_{index}"
        if not os.path.exists(candidate):
            return candidate
        index += 1
