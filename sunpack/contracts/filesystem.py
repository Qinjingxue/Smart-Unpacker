from dataclasses import dataclass
from pathlib import Path
from typing import Any, List

@dataclass
class FileEntry:
    path: Path
    is_dir: bool
    size: int | None = None
    mtime_ns: int | None = None
    metadata: dict[str, Any] | None = None

@dataclass
class DirectorySnapshot:
    root_path: Path
    entries: List[FileEntry]
