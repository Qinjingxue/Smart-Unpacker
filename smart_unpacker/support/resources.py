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
    if sys.platform != "win32":
        raise RuntimeError("Bundled 7z.exe is only supported on Windows in this test build.")
    for root in candidate_resource_roots():
        for relative in (Path("tools") / "7z.exe", Path("7z.exe")):
            seven_z = root / relative
            if seven_z.exists():
                return str(seven_z)
    raise FileNotFoundError("Required bundled 7z.exe was not found under tools\\ or the application root.")


def get_sevenzip_worker_path() -> str:
    if sys.platform != "win32":
        raise RuntimeError("sevenzip_worker.exe is only supported on Windows in this test build.")
    relatives = (
        Path("tools") / "sevenzip_worker.exe",
        Path("sevenzip_worker.exe"),
        Path("native") / "sevenzip_password_tester" / "build" / "Release" / "sevenzip_worker.exe",
        Path("native") / "sevenzip_password_tester" / "build" / "Debug" / "sevenzip_worker.exe",
    )
    for root in candidate_resource_roots():
        for relative in relatives:
            worker = root / relative
            if worker.exists():
                return str(worker)
    raise FileNotFoundError("Required sevenzip_worker.exe was not found under tools\\ or native\\sevenzip_password_tester\\build.")


def get_7z_dll_path() -> str:
    if sys.platform != "win32":
        raise RuntimeError("Bundled 7z.dll is only supported on Windows in this test build.")
    for root in candidate_resource_roots():
        for relative in (Path("tools") / "7z.dll", Path("7z.dll")):
            seven_z = root / relative
            if seven_z.exists():
                return str(seven_z)
    raise FileNotFoundError("Required bundled 7z.dll was not found under tools\\ or the application root.")
