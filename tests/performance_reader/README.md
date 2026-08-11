# Reader performance benchmarks

These benchmarks exercise the two performance-sensitive Reader workflows with
the native extension built in release mode.

Build/install the optimized extension first:

```powershell
$env:VIRTUAL_ENV='C:\Users\29402\Desktop\sunpack\.venv'
.venv\Scripts\maturin.exe develop --release --manifest-path native\sunpack_native\Cargo.toml
```

Run the password benchmark. It creates temporary ZIP AES-256, encrypted-header
7z, and RAR5 `-hp` archives. Each run places the correct password after 100
wrong passwords and asserts that native verification reports index 100.

```powershell
$env:PYTHONPATH='C:\Users\29402\Desktop\sunpack\.venv\Lib\site-packages;C:\Users\29402\Desktop\sunpack'
.venv\Scripts\python.exe tests\performance_reader\password_fast_path.py
```

To check whether wrong-password probe cost grows with archive size, run the
size-scaling benchmark. It tests 1, 16, and 64 MiB payloads by default and
reports both raw measurements and the largest/smallest latency ratio:

```powershell
.venv\Scripts\python.exe -m tests.performance_reader.password_size_scaling
```

Use `--payload-mib 1 8 32 128` to select a different size matrix.

The staged 7z password-optimization benchmark measures isolated wrong/correct
candidate cost, candidate-position latency, CPU time, and reuse across 100 and
1000 independent archive sessions:

```powershell
.venv\Scripts\python.exe -m tests.performance_reader.seven_zip_password_optimization `
  --label baseline
```

For a same-binary comparison against the legacy 7z `Archive::read`-per-password
path, add `--disable-seven-zip-probe`. Run it in a separate process so the
password worker pool and archive-session state start cleanly.

Run the complete CLI scan and three native embedded-scan rounds for the fixed
large sample:

```powershell
$env:PYTHONPATH='C:\Users\29402\Desktop\sunpack\.venv\Lib\site-packages;C:\Users\29402\Desktop\sunpack'
.venv\Scripts\python.exe tests\performance_reader\embedded_scan.py
```

Both programs print machine-readable JSON. Use `--help` for paths, round count,
payload size, or a different embedded sample.
