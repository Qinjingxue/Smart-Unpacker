from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
NATIVE_SRC = REPO_ROOT / "native" / "sunpack_native" / "src"

LEGACY_WHITELIST: set[str] = set()
REMOVED_NATIVE_SHIMS = {
    "analysis.rs",
    "format_structure.rs",
    "binary_profile.rs",
    "archive_deep_repair.rs",
    "compression_stream_repair.rs",
    "zip_deep_repair.rs",
    "archive_state_ops.rs",
    "carrier.rs",
    "directory_scan.rs",
    "file_crc.rs",
    "magic.rs",
    "password_7z.rs",
    "password_input.rs",
    "password_rar.rs",
    "password_zip.rs",
    "pe_overlay.rs",
    "postprocess_ops.rs",
    "relations.rs",
    "repair_io.rs",
    "scene_semantics.rs",
    "util.rs",
    "zip_names.rs",
}


def test_native_rust_files_do_not_grow_new_giants() -> None:
    offenders: list[str] = []
    for path in NATIVE_SRC.rglob("*.rs"):
        if "target" in path.parts:
            continue
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        rel = path.relative_to(NATIVE_SRC).as_posix()
        if path.name in LEGACY_WHITELIST:
            continue
        if line_count > 1000:
            offenders.append(f"{rel}: {line_count} lines")
    assert not offenders, "Rust files over 1000 lines:\n" + "\n".join(offenders)


def test_native_legacy_shims_are_removed() -> None:
    offenders = [name for name in sorted(REMOVED_NATIVE_SHIMS) if (NATIVE_SRC / name).exists()]
    assert not offenders, "Legacy native shim files still present:\n" + "\n".join(offenders)


def test_native_root_only_contains_module_entrypoint() -> None:
    offenders = sorted(
        path.name
        for path in NATIVE_SRC.glob("*.rs")
        if path.name != "lib.rs"
    )
    assert not offenders, "Native root still has flat implementation files:\n" + "\n".join(offenders)


def test_seven_zip_refactor_files_stay_bounded() -> None:
    seven_zip_root = NATIVE_SRC / "formats" / "seven_zip"
    offenders = [
        f"{path.relative_to(NATIVE_SRC).as_posix()}: {len(path.read_text(encoding='utf-8').splitlines())} lines"
        for path in seven_zip_root.rglob("*.rs")
        if len(path.read_text(encoding="utf-8").splitlines()) > 1000
    ]
    assert not offenders, "7z refactor files over 1000 lines:\n" + "\n".join(offenders)


def test_zip_refactor_files_stay_bounded() -> None:
    zip_root = NATIVE_SRC / "formats" / "zip"
    offenders = [
        f"{path.relative_to(NATIVE_SRC).as_posix()}: {len(path.read_text(encoding='utf-8').splitlines())} lines"
        for path in zip_root.rglob("*.rs")
        if len(path.read_text(encoding="utf-8").splitlines()) > 1000
    ]
    assert not offenders, "ZIP refactor files over 1000 lines:\n" + "\n".join(offenders)


def test_phase_three_refactor_files_stay_bounded() -> None:
    roots = [
        NATIVE_SRC / "formats" / "stream",
        NATIVE_SRC / "formats" / "tar",
        NATIVE_SRC / "formats" / "carrier",
        NATIVE_SRC / "formats" / "rar",
        NATIVE_SRC / "formats" / "nested",
    ]
    offenders = [
        f"{path.relative_to(NATIVE_SRC).as_posix()}: {len(path.read_text(encoding='utf-8').splitlines())} lines"
        for root in roots
        for path in root.rglob("*.rs")
        if len(path.read_text(encoding="utf-8").splitlines()) > 1000
    ]
    assert not offenders, "Phase-3 refactor files over 1000 lines:\n" + "\n".join(offenders)


def test_analysis_native_refactor_files_stay_bounded() -> None:
    analysis_root = NATIVE_SRC / "analysis_native"
    offenders = [
        f"{path.relative_to(NATIVE_SRC).as_posix()}: {len(path.read_text(encoding='utf-8').splitlines())} lines"
        for path in analysis_root.rglob("*.rs")
        if len(path.read_text(encoding="utf-8").splitlines()) > 1000
    ]
    assert not offenders, "Analysis native refactor files over 1000 lines:\n" + "\n".join(offenders)
