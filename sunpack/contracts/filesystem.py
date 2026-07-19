from dataclasses import dataclass
from collections.abc import Iterator
from pathlib import Path
from typing import Any

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
    _native_snapshot: Any

    @classmethod
    def from_native(cls, root_path: Path, native_snapshot: Any) -> "DirectorySnapshot":
        return cls(root_path=root_path, _native_snapshot=native_snapshot)

    @classmethod
    def from_entries(
        cls, root_path: Path, entries: list[FileEntry]
    ) -> "DirectorySnapshot":
        from sunpack_native import directory_snapshot_from_columns

        native_snapshot = directory_snapshot_from_columns(
            [str(entry.path) for entry in entries],
            [bool(entry.is_dir) for entry in entries],
            [entry.size for entry in entries],
            [entry.mtime_ns for entry in entries],
        )
        return cls.from_native(root_path, native_snapshot)

    def __len__(self) -> int:
        return len(self._native_snapshot)

    def __bool__(self) -> bool:
        return len(self) > 0

    @property
    def native_snapshot(self) -> Any:
        return self._native_snapshot

    @property
    def has_files(self) -> bool:
        return bool(self._native_snapshot.has_files())

    def iter_columns(
        self,
    ) -> Iterator[tuple[str, bool, int | None, int | None]]:
        paths, is_dirs, sizes, mtimes_ns = self._native_snapshot.materialize_columns()
        return iter(zip(paths, is_dirs, sizes, mtimes_ns))

    def iter_file_columns(self) -> Iterator[tuple[str, int | None, int | None]]:
        paths, sizes, mtimes_ns = self._native_snapshot.file_columns()
        return iter(zip(paths, sizes, mtimes_ns))

    def file_entries_for_directories(self, directories: set[str]) -> list[FileEntry]:
        if not directories:
            return []
        paths, sizes, mtimes_ns = (
            self._native_snapshot.file_columns_for_directories(list(directories))
        )
        return [
            FileEntry(path=Path(path), is_dir=False, size=size, mtime_ns=mtime_ns)
            for path, size, mtime_ns in zip(paths, sizes, mtimes_ns)
        ]

    def identity_rows(self) -> list[tuple[str, bool, int, int]]:
        return list(self._native_snapshot.identity_rows())
