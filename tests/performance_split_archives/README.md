# Archive Pressure Scenarios

This directory contains an opt-in pressure script for real archive edge cases.

Run it from the repository root:

```powershell
python tests\performance_split_archives\split_archive_pressure.py
```

It dynamically creates temporary archives with 7-Zip, so it requires `tools/7z.exe`
or `SMART_UNPACKER_TEST_7Z`. SFX cases also require `tools/7zCon.sfx` or
`SMART_UNPACKER_TEST_7Z_SFX`. RAR cases require `rar.exe`, configured with
`SMART_UNPACKER_TEST_RAR` or `tests/test_tools.json` as `rar_exe`; without it, the
RAR matrix is reported as skipped.

The script covers:

- formats: `7z`, `zip`, and `rar`
- plain single-file archives
- split archives, including normal split, missing split member, and corrupt split member
- SFX single-file archives
- SFX split archives
- JPG carrier archives, where the real archive payload is appended after JPEG bytes
- wrong-suffix archives, where a valid archive is renamed to an unrelated extension
- corrupt single archives with header and tail damage
- password matrices for each encrypted family: no password, wrong passwords only, and
  a correct password after intentionally wrong passwords

By default the script is report-oriented and exits with 0 even if a scenario exposes
an unexpected observed result. Use `--strict` when you want expectation mismatches to
return a non-zero exit code.

Limit the generated matrix when you only need a subset:

```powershell
python tests\performance_split_archives\split_archive_pressure.py --formats 7z,zip
python tests\performance_split_archives\split_archive_pressure.py --formats rar --strict
```
