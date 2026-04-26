import os
from dataclasses import dataclass


@dataclass(frozen=True)
class OutputStats:
    exists: bool
    is_dir: bool
    file_count: int = 0
    dir_count: int = 0
    total_size: int = 0
    transient_file_count: int = 0
    unreadable_count: int = 0
    relative_paths: tuple[str, ...] = ()


TRANSIENT_SUFFIXES = (
    ".tmp",
    ".temp",
    ".part",
    ".partial",
    ".crdownload",
)


def collect_output_stats(output_dir: str) -> OutputStats:
    if not output_dir or not os.path.exists(output_dir):
        return OutputStats(exists=False, is_dir=False)
    if not os.path.isdir(output_dir):
        return OutputStats(exists=True, is_dir=False)

    file_count = 0
    dir_count = 0
    total_size = 0
    transient_file_count = 0
    unreadable_count = 0
    relative_paths = []

    for root, dirs, files in os.walk(output_dir):
        dir_count += len(dirs)
        for name in files:
            file_count += 1
            if name.lower().endswith(TRANSIENT_SUFFIXES):
                transient_file_count += 1
            path = os.path.join(root, name)
            relative_paths.append(os.path.relpath(path, output_dir))
            try:
                total_size += os.path.getsize(path)
            except OSError:
                unreadable_count += 1

    return OutputStats(
        exists=True,
        is_dir=True,
        file_count=file_count,
        dir_count=dir_count,
        total_size=total_size,
        transient_file_count=transient_file_count,
        unreadable_count=unreadable_count,
        relative_paths=tuple(relative_paths),
    )
