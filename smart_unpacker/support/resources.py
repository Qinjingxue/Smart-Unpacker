import sys
from pathlib import Path


def dedupe_paths(paths: list[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path.resolve()).lower()
        if key not in seen:
            seen.add(key)
            deduped.append(path)
    return deduped


def first_existing_path(paths: list[Path]) -> Path | None:
    for path in dedupe_paths(paths):
        if path.exists():
            return path
    return None


def candidate_resource_roots() -> list[Path]:
    roots: list[Path] = []

    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(Path(meipass).resolve())

    module_root = Path(__file__).resolve().parents[2]
    roots.extend([
        module_root,
        Path.cwd().resolve(),
        Path.cwd().resolve() / "smart_unpacker-2",
    ])

    return dedupe_paths(roots)


def candidate_resource_paths(filename: str) -> list[Path]:
    return [root / filename for root in candidate_resource_roots()]


def find_resource_path(filename: str) -> Path | None:
    return first_existing_path(candidate_resource_paths(filename))


def get_resource_path(filename: str) -> Path:
    return candidate_resource_roots()[0] / filename


def get_7z_path() -> str:
    if sys.platform == "win32":
        for root in candidate_resource_roots():
            for relative in (Path("tools") / "7z.exe", Path("7z.exe")):
                seven_z = root / relative
                if seven_z.exists():
                    return str(seven_z)
    return "7z"
