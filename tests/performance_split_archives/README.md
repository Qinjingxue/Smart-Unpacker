# Split Archive Pressure Scenarios

This directory contains an opt-in pressure script for real split archive edge cases.

Run it from the repository root:

```powershell
python tests\performance_split_archives\split_archive_pressure.py
```

It dynamically creates temporary archives with 7-Zip, so it requires `tools/7z.exe` or
`SMART_UNPACKER_TEST_7Z`. SFX cases also require `tools/7zCon.sfx` or
`SMART_UNPACKER_TEST_7Z_SFX`.

The script covers:

- normal split archive: `archive.7z.001/.002`
- missing split member: only `.001`
- corrupt split member: `.002` overwritten
- encrypted split archive with no password, wrong password, and correct password
- split SFX archive: `.exe + .001/.002`
- misnamed split member: first part plus mismatched successor name

By default the script is report-oriented and exits with 0 even if a scenario exposes
an unexpected observed result. Use `--strict` when you want expectation mismatches to
return a non-zero exit code.
