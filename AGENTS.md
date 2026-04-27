# AGENTS.md

## Environment & Setup

- **Windows-only.** Every script enforces `$env:OS -ne "Windows_NT"` → abort.
- Prerequisites: Python 3.10+, Rust (`cargo`), VS Build Tools 2022 (C++17), CMake 3.25+, PowerShell 5+.
- Dev setup: `.\scripts\setup_windows_dev.ps1` (creates `.venv`, builds Rust + C++ natives, bootstraps `tools/`).
- Build deps: `.\scripts\setup_windows_dev.ps1 -IncludeBuildDeps`

## Must-Run-Before-Tests

The `tools/` directory is **gitignored but required at runtime**. These must exist before any test run:

```
tools/7z.exe
tools/7z.dll
tools/sevenzip_password_tester_capi.dll   (C++ 7z.dll wrapper)
tools/sevenzip_worker.exe                  (extraction backend)
```

Verify both natives are available:
```powershell
python -c "import smart_unpacker_native as n; assert n.native_available()"
python -c "from smart_unpacker.support.sevenzip_native import NativePasswordTester; assert NativePasswordTester().available()"
```

## Entrypoint

- Dev CLI: `python sunpack_cli.py` (not a package entrypoint).
- Requires `PYTHONPATH` set to repo root (scripts set it automatically).
- Frozen build: `sunpack.exe` (built via `.\scripts\build_windows.ps1`).

## Architecture (non-obvious from filenames)

**Three-language hybrid:**
- **Python** (`smart_unpacker/`): orchestrator, CLI, config, rules, scheduling.
- **Rust** (`native/smart_unpacker_native/`, PyO3 via maturin): hot paths — directory scanning, binary I/O, signature prepass, carrier scan, ZIP EOCD, PE overlay, repair I/O.
- **C++** (`native/sevenzip_password_tester/`, CMake): 7z.dll wrapper for probe/test/password brute-force + `sevenzip_worker.exe` for streaming extract.

**Domain boundaries (strict — violations cause subtle bugs):**
- Never import from another domain's `internal` module: `from smart_unpacker.X.internal import ...` is forbidden.
- Never access private fields across modules: `bag._facts` is forbidden; use `FactBag.to_dict()`.
- `contracts/` holds shared data structures only (no logic, only stdlib deps).
- `support/` holds infrastructure only (no detection/password/extraction policy).
- `app/` is CLI adaption only (no business logic).
- `coordinator/` is orchestration only (no domain algorithms).
- Config aliases (`"*"`, `"-"`, `"d/r/k"`) are user-facing; code consumes normalized internal values.

**Approved dependency direction:** `app → coordinator → (detection | analysis | extraction | repair | verification | postprocess) → contracts`. See `docs/development_boundaries.md` for the full map.

## Testing

```powershell
pytest                                    # default suite (unit + functional + integration)
pytest tests/unit -q                      # unit only
pytest tests/functional -q                # functional only
pytest tests/runners -q                   # data-driven JSON cases only
pytest tests/cli -q                       # CLI contract tests only
.\run_acceptance_tests.ps1                # full acceptance suite
.\scripts\run_ci_tests.ps1                # CI checks (native smoke + pytest + CLI smoke)
```

**Opt-in markers (skipped by default):**
```powershell
pytest --run-slow-real-archives                              # full real-archive matrix
pytest --run-large-archive-performance -s                    # multi-GB perf tests
pytest --run-large-archive-performance -s --large-archive-count 5 --large-archive-size-mb 100
```

**Test conventions:**
- Prefer JSON data-driven cases (`tests/cases/`) over new Python test files.
- Tests use public APIs only — do not import `*/internal/*` or private methods.
- `test_tools.json` controls test tool configurations.
- Expensive real-archive tests go under `integration/` or behind `slow_real_archive` marker.

## Commands Reference

```powershell
python sunpack_cli.py scan <dir>              # scan only, no extraction
python sunpack_cli.py extract <dir>           # full extract pipeline
python sunpack_cli.py inspect <dir> -v        # detailed detection report
python sunpack_cli.py config validate         # validate config + rule plugins
python sunpack_cli.py passwords --json        # list password candidates
python sunpack_cli.py watch <dir>             # watchdog-based auto-extract
```

## Rebuilding Natives (manual)

Only needed after changing Rust or C++ code:

```powershell
# Rust:
python -m maturin build --manifest-path native\smart_unpacker_native\Cargo.toml --release --out build\native-wheels-dev
$wheel = Get-ChildItem build\native-wheels-dev\smart_unpacker_native-*.whl | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
python -m pip install --force-reinstall $wheel

# C++:
cmake -S native\sevenzip_password_tester -B native\sevenzip_password_tester\build
cmake --build native\sevenzip_password_tester\build --config Release
ctest --test-dir native\sevenzip_password_tester\build -C Release --output-on-failure
Copy-Item native\sevenzip_password_tester\build\Release\sevenzip_password_tester_capi.dll tools\ -Force
Copy-Item native\sevenzip_password_tester\build\Release\sevenzip_worker.exe tools\ -Force
```

## Boundary Compliance Check

After refactoring, run:
```powershell
rg "from smart_unpacker\.[^.]+\.internal" smart_unpacker tests
rg "\._facts|FactBag\._facts" smart_unpacker tests
```

## Key Non-Obvious Details

- The 7z backend is **not** `7z.exe x` — extraction runs through `sevenzip_worker.exe` calling `7z.dll` directly.
- `builtin_passwords.txt` and `smart_unpacker_config.json` are external files alongside the exe, not bundled in PyInstaller internals.
- Config `--json` flag outputs machine-readable JSON for all commands.
- `GEMINI.md` is gitignored (not tracked in repo).
- No `.github/workflows/` CI exists — CI is local only via `.\scripts\run_ci_tests.ps1`.
