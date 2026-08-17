"""Embed and verify a Windows application manifest without SDK tooling."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import sys


RT_MANIFEST = 24
MANIFEST_RESOURCE_ID = 1
LANG_NEUTRAL = 0
LOAD_LIBRARY_AS_DATAFILE = 0x00000002


class ManifestResourceError(RuntimeError):
    """Raised when a PE manifest resource cannot be updated or read."""


def _raise_last_error(action: str) -> None:
    raise ManifestResourceError(f"{action} failed: {ctypes.WinError(ctypes.get_last_error())}")


def _windows_api():
    if sys.platform != "win32":
        raise ManifestResourceError("Windows manifest resources can only be modified on Windows.")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.BeginUpdateResourceW.argtypes = (wintypes.LPCWSTR, wintypes.BOOL)
    kernel32.BeginUpdateResourceW.restype = wintypes.HANDLE
    kernel32.UpdateResourceW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.WORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    kernel32.UpdateResourceW.restype = wintypes.BOOL
    kernel32.EndUpdateResourceW.argtypes = (wintypes.HANDLE, wintypes.BOOL)
    kernel32.EndUpdateResourceW.restype = wintypes.BOOL
    kernel32.LoadLibraryExW.argtypes = (wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD)
    kernel32.LoadLibraryExW.restype = wintypes.HMODULE
    kernel32.FreeLibrary.argtypes = (wintypes.HMODULE,)
    kernel32.FreeLibrary.restype = wintypes.BOOL
    kernel32.FindResourceExW.argtypes = (wintypes.HMODULE, wintypes.LPVOID, wintypes.LPVOID, wintypes.WORD)
    kernel32.FindResourceExW.restype = wintypes.HRSRC
    kernel32.LoadResource.argtypes = (wintypes.HMODULE, wintypes.HRSRC)
    kernel32.LoadResource.restype = wintypes.HGLOBAL
    kernel32.SizeofResource.argtypes = (wintypes.HMODULE, wintypes.HRSRC)
    kernel32.SizeofResource.restype = wintypes.DWORD
    kernel32.LockResource.argtypes = (wintypes.HGLOBAL,)
    kernel32.LockResource.restype = wintypes.LPVOID
    kernel32.EnumResourceLanguagesW.restype = wintypes.BOOL
    return kernel32


def _integer_resource(resource_id: int) -> wintypes.LPVOID:
    return wintypes.LPVOID(resource_id)


def _manifest_languages(kernel32, executable: Path) -> list[int]:
    module = kernel32.LoadLibraryExW(str(executable), None, LOAD_LIBRARY_AS_DATAFILE)
    if not module:
        _raise_last_error(f"Loading {executable} as a resource module")

    languages: list[int] = []
    callback_type = ctypes.WINFUNCTYPE(
        wintypes.BOOL,
        wintypes.HMODULE,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.WORD,
        wintypes.LPARAM,
    )
    kernel32.EnumResourceLanguagesW.argtypes = (
        wintypes.HMODULE,
        wintypes.LPVOID,
        wintypes.LPVOID,
        callback_type,
        wintypes.LPARAM,
    )

    @callback_type
    def collect_language(_module, _resource_type, _resource_name, language, _parameter):
        languages.append(int(language))
        return True

    try:
        ctypes.set_last_error(0)
        found = kernel32.EnumResourceLanguagesW(
            module,
            _integer_resource(RT_MANIFEST),
            _integer_resource(MANIFEST_RESOURCE_ID),
            collect_language,
            0,
        )
        if not found and ctypes.get_last_error() != 0:
            _raise_last_error(f"Enumerating manifest resources in {executable}")
        return languages
    finally:
        kernel32.FreeLibrary(module)


def embed_manifest(executable: Path, manifest: bytes) -> None:
    kernel32 = _windows_api()
    if not executable.is_file():
        raise ManifestResourceError(f"Executable not found: {executable}")

    update = kernel32.BeginUpdateResourceW(str(executable), False)
    if not update:
        _raise_last_error(f"Opening {executable} for resource update")

    committed = False
    try:
        for language in _manifest_languages(kernel32, executable):
            if not kernel32.UpdateResourceW(
                update,
                _integer_resource(RT_MANIFEST),
                _integer_resource(MANIFEST_RESOURCE_ID),
                language,
                None,
                0,
            ):
                _raise_last_error(f"Removing the existing manifest from {executable}")

        buffer = ctypes.create_string_buffer(manifest)
        if not kernel32.UpdateResourceW(
            update,
            _integer_resource(RT_MANIFEST),
            _integer_resource(MANIFEST_RESOURCE_ID),
            LANG_NEUTRAL,
            ctypes.cast(buffer, wintypes.LPVOID),
            len(manifest),
        ):
            _raise_last_error(f"Embedding the manifest into {executable}")
        if not kernel32.EndUpdateResourceW(update, False):
            _raise_last_error(f"Committing the manifest resource in {executable}")
        committed = True
    finally:
        if not committed:
            kernel32.EndUpdateResourceW(update, True)


def read_manifest(executable: Path) -> bytes:
    kernel32 = _windows_api()
    module = kernel32.LoadLibraryExW(str(executable), None, LOAD_LIBRARY_AS_DATAFILE)
    if not module:
        _raise_last_error(f"Loading {executable} as a resource module")
    try:
        resource = kernel32.FindResourceExW(
            module,
            _integer_resource(RT_MANIFEST),
            _integer_resource(MANIFEST_RESOURCE_ID),
            LANG_NEUTRAL,
        )
        if not resource:
            _raise_last_error(f"Finding the embedded manifest in {executable}")
        size = kernel32.SizeofResource(module, resource)
        data = kernel32.LockResource(kernel32.LoadResource(module, resource))
        if not data or not size:
            _raise_last_error(f"Reading the embedded manifest from {executable}")
        return ctypes.string_at(data, size)
    finally:
        kernel32.FreeLibrary(module)


def verify_per_monitor_v2(executable: Path) -> None:
    content = read_manifest(executable).decode("utf-8-sig")
    for required_value in ("<dpiAwareness", "PerMonitorV2"):
        if required_value not in content:
            raise ManifestResourceError(
                f"Embedded application manifest does not contain {required_value!r}: {executable}"
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True, action="append")
    args = parser.parse_args()

    manifest = args.manifest.read_bytes()
    if not manifest:
        raise ManifestResourceError(f"Manifest is empty: {args.manifest}")
    for executable in args.executable:
        embed_manifest(executable, manifest)
        verify_per_monitor_v2(executable)
        print(f"Embedded PerMonitorV2 manifest: {executable}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ManifestResourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
