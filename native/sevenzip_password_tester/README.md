# sevenzip_password_tester

Windows C++ wrapper around the bundled `7z.dll`.

This component provides the in-process 7-Zip backend used by SunPack for
archive probing, archive testing, and password attempts. It avoids spawning
`7z.exe` for high-volume detection/password checks. The final extraction step
still uses `7z.exe x`.

## Build Requirements

- Windows
- CMake 3.25 or newer
- A C++17 compiler toolchain, such as Visual Studio Build Tools 2022
- Repository `tools\7z.dll`

The project build scripts install Python build dependencies, including CMake,
but they do not install the Visual Studio C++ compiler.

## Build

```powershell
cmake -S native\sevenzip_password_tester -B native\sevenzip_password_tester\build
cmake --build native\sevenzip_password_tester\build --config Release
ctest --test-dir native\sevenzip_password_tester\build -C Release --output-on-failure
```

The runtime DLL is:

```text
native\sevenzip_password_tester\build\Release\sevenzip_password_tester_capi.dll
```

Development and release scripts copy it to:

```text
tools\sevenzip_password_tester_capi.dll
```

That path is preferred by Python at runtime.

## C API

The wrapper exports a narrow C ABI:

- `sup7z_try_passwords`
- `sup7z_test_archive`
- `sup7z_probe_archive`
- `sup7z_check_archive_health`
- `sup7z_analyze_archive_resources`

Python calls these through `sunpack.support.sevenzip_native`.

## Runtime Responsibility

Use this wrapper for:

- password attempts over a supplied password array
- `7z t`-style archive testing
- `7z l`-style archive probing fields currently consumed by the detection pipeline
- pre-extraction health checks that classify damaged or incomplete archives
- aggregate resource analysis, such as unpacked size, packed size, item counts,
  dominant compression method, solid archive flag, and dictionary size

Keep final extraction on `7z.exe` unless the extraction scheduler is explicitly
redesigned around the 7-Zip COM interfaces.
