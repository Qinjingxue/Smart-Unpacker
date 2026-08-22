# sevenzip_bridge

Windows C++ bridge around the bundled `7z.dll`.

It provides SunPack's in-process archive inspection ABI and the out-of-process extraction worker. Product code calls the bridge through `sunpack.support.sevenzip_bridge`; extraction jobs are executed by `sunpack_sevenzip_worker.exe`.

## Responsibilities

- archive probe and test
- password array attempts
- open-only archive probing and resource analysis
- archive CRC/state manifest collection
- extraction from files, volume sets, file ranges, concatenated ranges and patch-plan inputs

Business decisions remain in Python. The bridge reports structured facts and operation results.

## Requirements

- Windows
- CMake 3.25 or newer
- Visual Studio Build Tools 2022 or another C++17 MSVC-compatible toolchain
- repository `tools\7z.dll`

## Build

```powershell
cmake -S native\sevenzip_bridge -B native\sevenzip_bridge\build-x64 -A x64
cmake --build native\sevenzip_bridge\build-x64 --config Release
ctest --test-dir native\sevenzip_bridge\build-x64 -C Release --output-on-failure
```

Release outputs:

```text
native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip.dll
native\sevenzip_bridge\build-x64\Release\sunpack_sevenzip_worker.exe
```

Development and release scripts copy them to:

```text
tools\sunpack_sevenzip.dll
tools\sunpack_sevenzip_worker.exe
```

## C API

The DLL exports a narrow C ABI including:

- `sup7z_try_passwords`
- `sup7z_test_archive`
- `sup7z_run_operation` (open probe, test, and password attempts)
- `sup7z_analyze_archive_resources`
- archive manifest and operation entry points

The Python binding owns library loading, typed result conversion and caches. The worker owns process isolation, JSON job handling and progress output.

## Runtime Contract

`sunpack_sevenzip.dll`, `sunpack_sevenzip_worker.exe` and the architecture-matching `7z.dll` must be available in the same SunPack tool directory. Do not add a `7z.exe x` fallback to the product extraction path; failures must remain explicit and structured.
