import os

from smart_unpacker.contracts.tasks import ArchiveTask


def default_output_dir_for_task(task: ArchiveTask) -> str:
    path = task.main_path
    out_name = task.logical_name or os.path.splitext(os.path.basename(path))[0]
    out_dir = os.path.join(os.path.dirname(path), os.path.basename(out_name))
    if os.path.normpath(out_dir) == os.path.normpath(path):
        out_dir += "_extracted"
    if os.path.isfile(out_dir):
        out_dir += "_extracted"
    return out_dir
