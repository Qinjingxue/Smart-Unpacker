# Smart Unpacker

[中文](./README.md) | [English](./README.en.md) | [日本語](./README.ja.md)

Smart Unpacker is a Windows-oriented Python command-line extraction tool developed with AI assistance.

It is designed for batch processing disguised archives, nested archives, split archives, password-protected archives, and self-extracting files. It tries to complete detection, validation, extraction, and cleanup through one consistent workflow.

The recommended usage is to register it as a Windows Explorer context-menu entry. After registration, you can launch it by right-clicking a folder or an empty area inside a directory, enter multiple passwords, and let the tool try them automatically. After successful processing, the original archives are moved to the Recycle Bin, and extraction results with only one child directory are automatically flattened.

## Use Cases

- Batch extract mixed archive files in a folder.
- Detect archives with disguised or missing extensions.
- Handle split archives, nested archives, and self-extracting files.
- Automatically try command-line passwords, password files, and built-in common passwords.
- Clean up original archives after extraction and simplify one-level directory structures.

## Quick Start

Using the prebuilt package from Releases is recommended.

1. Download the Release archive and extract it to a fixed directory.
2. Register the context-menu entry:

```powershell
.\scripts\register_context_menu.ps1
```

3. In File Explorer, right-click a folder or an empty area inside a directory, then choose `Smart Unpacker`.
4. To remove the context-menu entry, run:

```powershell
.\scripts\unregister_context_menu.ps1
```

`builtin_passwords.txt` is the built-in password list. If you do not want to manually enter common passwords every time, add them to this file, one password per line, and they will be tried automatically during extraction.

## Configuration

The main configuration file is `smart_unpacker_config.json`.

Common settings:

- `basic.min_inspection_size_bytes`: Minimum file size to inspect. Files smaller than this value are ignored. The default is `1048576`, or `1 MB`. Increase it to reduce the performance cost of scanning many small files; decrease it to detect smaller disguised archives.
- `basic.scheduler_profile`: Concurrency strategy. `auto` is usually enough; `aggressive` favors performance; `conservative` is safer when the tool creates too many processes or affects other tasks.
- `advanced.scheduler`: Detailed concurrency controls. All values default to `0`, which means they follow `scheduler_profile`. Setting a concrete value overrides the corresponding profile behavior.

## Commands

- `inspect`: Recursively inspect files or directories and output each file's detection result, matching reasons, and whether extraction is recommended.
- `scan`: Summarize processable archives by task so you can review scan results before extracting.
- `extract`: Run scanning, password attempts, archive validation, extraction, and post-processing, while dynamically adjusting concurrency based on system load.
- `passwords`: Show the final password list that may be tried, including command-line input, password files, and built-in common passwords.

Common options:

- `--json`: Output results as JSON.
- `--quiet`: Reduce terminal output.
- `--verbose`: Print more detailed information.
- `--pause-on-exit`: Wait for a key press before exiting, useful for context-menu usage.

Password options:

- `-p, --password`: Provide an extraction password. Can be passed multiple times.
- `--password-file`: Read passwords from a file, one password per line.
- `--prompt-passwords`: Enter passwords interactively in the terminal.
- `--no-builtin-passwords`: Disable built-in common passwords.

## Run Locally

1. Install Python 3.
2. Initialize the local development environment:

```powershell
.\scripts\setup_windows_dev.ps1
```

This script will:

- Create `.venv`.
- Install runtime dependencies from `requirements.txt`.
- Restore missing 7-Zip runtime components in the `tools` directory.

3. Run the CLI:

```powershell
python smart-unpacker.py <command> [options] [paths...]
```

Examples:

```powershell
python smart-unpacker.py inspect .\fixtures
python smart-unpacker.py scan .\archives
python smart-unpacker.py extract -p "secret" .\archives\sample.zip
python smart-unpacker.py extract --prompt-passwords .\archives
python smart-unpacker.py passwords
```

## Testing

Full logic acceptance test:

```powershell
.\run_acceptance_tests.ps1
```

CI test entry used by GitHub Actions:

```powershell
.\scripts\run_ci_tests.ps1
```

Local test paths and tool lookup rules are configured in:

```text
tests/test_config.json
```

The current synthetic samples cover these directory-semantic families: RPG Maker, Ren'Py, Godot, NW.js, and Electron.

RAR samples in the full test suite require `Rar.exe`. If it is missing, the RAR-dependent sample generation steps are skipped automatically. The `Rar.exe` path can be configured in `tests/test_config.json`.

## Dependencies And Build

Dependency files:

- Runtime dependencies: `requirements.txt`
- Build dependencies: `requirements-build.txt`
- 7-Zip runtime components: automatically downloaded by the local setup script and build script when missing.

Build the Windows release package:

```powershell
.\scripts\build_windows.ps1
```

The build process runs tests automatically to help prevent project changes from accidentally deleting ordinary files.

Optional parameters:

- `-SkipTests`: Skip tests and only validate the packaging pipeline.
- `-Clean`: Rebuild after additionally cleaning the build virtual environment.
- `-Version <string>`: Override the default version string used in release naming.

After the build finishes, it generates:

- `dist/SmartUnpacker/`: Runnable release directory.
- `release/*.zip`: Distributable zip package.

## Disclaimer

Although this software has been tested under complex scenarios, it cannot guarantee that files will never be deleted by mistake. Use it only when your data is recoverable or backed up. Any file loss caused by usage is the user's responsibility.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
