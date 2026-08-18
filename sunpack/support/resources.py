import platform
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


def candidate_resource_roots(request_cwd: str | Path | None = None) -> list[Path]:
    roots: list[Path] = []

    if getattr(sys, "frozen", False) or "__compiled__" in globals():
        roots.append(Path(sys.executable).resolve().parent)
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            roots.append(Path(meipass).resolve())

    module_root = Path(__file__).resolve().parents[2]
    invocation_root = Path(request_cwd).resolve() if request_cwd is not None else Path.cwd().resolve()
    roots.extend([
        module_root,
        invocation_root,
        invocation_root / "sunpack-2",
    ])

    return dedupe_paths(roots)


def candidate_resource_paths(filename: str, request_cwd: str | Path | None = None) -> list[Path]:
    return [root / filename for root in candidate_resource_roots(request_cwd)]


def tool_dir_candidates() -> tuple[Path, ...]:
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        return (Path("tools-arm64"), Path("tools"))
    return (Path("tools"), Path("tools-x64"))


def find_resource_path(filename: str) -> Path | None:
    return first_existing_path(candidate_resource_paths(filename))


def get_resource_path(filename: str) -> Path:
    return candidate_resource_roots()[0] / filename


def get_7z_path() -> str:
    for root in candidate_resource_roots():
        for relative in tuple(tool_dir / "7z.exe" for tool_dir in tool_dir_candidates()) + (Path("7z.exe"),):
            seven_z = root / relative
            if seven_z.exists():
                return str(seven_z)
    raise FileNotFoundError("Required bundled 7z.exe was not found under tools\\ or the application root.")


def get_sevenzip_bridge_worker_path() -> str:
    relatives = (
        Path("native") / "sevenzip_bridge" / "build-x64" / "Release" / "sunpack_sevenzip_worker.exe",
        Path("native") / "sevenzip_bridge" / "build-arm64" / "Release" / "sunpack_sevenzip_worker.exe",
        Path("native") / "sevenzip_bridge" / "build" / "Release" / "sunpack_sevenzip_worker.exe",
        Path("native") / "sevenzip_bridge" / "build" / "Debug" / "sunpack_sevenzip_worker.exe",
        *tuple(tool_dir / "sunpack_sevenzip_worker.exe" for tool_dir in tool_dir_candidates()),
        Path("sunpack_sevenzip_worker.exe"),
    )
    for root in candidate_resource_roots():
        for relative in relatives:
            worker = root / relative
            if worker.exists():
                return str(worker)
    raise FileNotFoundError("Required sunpack_sevenzip_worker.exe was not found under tools\\ or native\\sevenzip_bridge\\build.")


def get_7z_dll_path() -> str:
    for root in candidate_resource_roots():
        for relative in tuple(tool_dir / "7z.dll" for tool_dir in tool_dir_candidates()) + (Path("7z.dll"),):
            seven_z = root / relative
            if seven_z.exists():
                return str(seven_z)
    raise FileNotFoundError("Required bundled 7z.dll was not found under tools\\ or the application root.")
