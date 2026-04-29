# sunpack_native

Rust/PyO3 extension module for narrow native helpers used by SunPack.

This crate should stay focused on cross-platform filesystem and byte-structure
hot paths. Python remains responsible for configuration, rule decisions,
task orchestration, and error reporting. 7-Zip archive probing/password testing
lives in the separate C++ `native/sevenzip_password_tester` wrapper because it
is Windows/COM/7z.dll-specific.

## Build

```powershell
python -m pip install -r requirements-build.txt
python -m maturin build --manifest-path native\sunpack_native\Cargo.toml --release
```

Install the generated wheel:

```powershell
$wheel = Get-ChildItem native\sunpack_native\target\wheels\sunpack_native-*.whl | Select-Object -First 1 -ExpandProperty FullName
python -m pip install --force-reinstall $wheel
```

Smoke test:

```powershell
python -c "import sunpack_native; print(sunpack_native.native_available(), sunpack_native.scanner_version())"
```

## API

`native_available()` returns `True` from the native module and is used by smoke
tests to confirm the extension was imported.

`scanner_version()` returns the crate package version.

`scan_directory_entries(root_path, max_depth, patterns, prune_dirs, blocked_extensions, min_size)`
walks a directory tree and returns basic entry metadata after applying the
built-in filesystem scan filters. Python still owns `DirectorySnapshot` /
`FileEntry` construction. Custom filters must be expressible through native
scan parameters or the caller should fail explicitly.

Return value:

```python
[{"path": "C:/data/archive.zip", "is_dir": False, "size": 123, "mtime_ns": 123456789}]
```

`scene_semantics_payloads(root_path, entries, rules, prune_dir_globs)` evaluates
filesystem scene semantics from an already-scanned entry list. It does not
touch the filesystem; Python supplies the rule payload and attaches returned
metadata to `FileEntry` objects. `prune_dir_globs` skips matching inside
directory-name globs such as `node_modules` or `.venv`.

`list_regular_files_in_directory(directory)` lists regular files directly under
one directory and returns path/size/mtime metadata. This is intentionally a thin
filesystem helper used by relation grouping; Python still owns split-volume
semantics and grouping decisions.

`scan_carrier_archive(path, carrier_ext, archive_magics, file_size, tail_window, prefix_window, full_scan_max, deep_scan)`
searches for archive magic bytes appended to supported carrier formats: JPEG,
PNG, PDF, GIF, and WebP. It applies the same tail/prefix/full-scan window
strategy used by Python for marker-based carriers, and parses GIF/WebP container
boundaries directly.

Return value:

```python
{"detected_ext": ".7z", "offset": 123, "scan_scope": "tail"}
```

or `None` when no embedded archive is found.

`scan_after_markers(path, markers, archive_magics, tail_start, file_size, allow_full_scan)`
searches for archive magic bytes after carrier markers.

- `markers`: list of carrier marker bytes, such as JPEG EOF bytes.
- `archive_magics`: list of `(magic_bytes, detected_ext)` pairs.
- `tail_start` and `file_size`: define the tail scan range.
- `allow_full_scan`: when true, scan before the tail range if the tail scan misses.

Return value:

```python
{"detected_ext": ".7z", "offset": 123, "scan_scope": "tail"}
```

or `None` when no marker/magic pair is found.

`scan_magics_anywhere(path, archive_magics, min_offset, max_hits, end_offset=None)`
streams through a file and collects archive magic hits.

- `archive_magics`: list of `(magic_bytes, detected_ext)` pairs.
- `min_offset`: first byte offset to scan.
- `max_hits`: maximum number of hits to return.
- `end_offset`: optional exclusive end offset.

Return value:

```python
[{"detected_ext": ".zip", "offset": 123, "scan_scope": ""}]
```

`scan_zip_central_directory_names(path, max_samples, max_filename_bytes)`
reads ZIP central-directory metadata and returns raw filename samples for
encoding detection. ZIP64 central directory parsing is intentionally not handled
here; Python reports the unsupported status instead of reparsing it.

Return value:

```python
{
    "status": "ok",
    "raw_names": [b"name.txt"],
    "utf8_marked": 1,
    "truncated": False,
}
```

The module also exposes lightweight structure inspectors used by the detection
pipeline:

- `inspect_zip_local_header`
- `inspect_zip_eocd_structure`
- `inspect_seven_zip_structure`
- `inspect_rar_structure`
- `inspect_tar_header_structure`
- `inspect_compression_stream_structure`
- `inspect_archive_container_structure`
- `inspect_pe_overlay_structure`

These functions preserve the Python result shapes. During the current test
phase the application treats this native extension as required; missing native
functions or native errors should fail fast instead of falling back to Python
parsers.
