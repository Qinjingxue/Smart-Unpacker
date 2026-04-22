# Smart Unpacker

[中文](./README.md) | [English](./README.en.md) | [日本語](./README.ja.md)

Smart Unpacker is a Windows-oriented Python command-line extraction tool developed with AI assistance.
It is mainly designed for batch processing of disguised archives, nested archives, split archives, password-protected archives, and self-extracting files, while trying to complete detection, validation, extraction, and cleanup through one unified workflow.
It can also be registered as a Windows Explorer context-menu entry. The menu appears for folders or folder backgrounds. You can launch it from the right-click menu, enter multiple passwords, let it try them automatically, move successfully processed original archives to the Recycle Bin, and flatten single-child directories after extraction.

# Usage

Using the Windows context menu is the recommended way to launch the program.
You can download the prebuilt package from the Releases page, build it yourself from source by following the instructions, or run it directly from source.
After downloading a release package, extract it to a fixed location. Run `scripts/register_context_menu.ps1` to register the context menu, and run `scripts/unregister_context_menu.ps1` to remove it.
`builtin_passwords.txt` contains the built-in password list. If you do not want to enter passwords every time, you can add commonly used passwords there and let the program try them automatically.

## Configuration

`smart_unpacker_config.json` is the main configuration file.

`min_inspection_size_bytes` is the minimum archive size the program will inspect. Files smaller than this will not be recognized or processed. Increase it to reduce the performance cost of many noisy small files; decrease it if you want to detect smaller disguised archives. The default is `1 MB`.

Everything under `basic` is intended for normal users.

`scheduler_profile` controls the concurrency strategy. `auto` is usually fine. Set it to `aggressive` if you want a more performance-oriented strategy. Set it to `conservative` if the program creates too many worker processes or affects other tasks on your machine.

Everything under `advanced.scheduler` is for detailed concurrency tuning. By default, all values are `0`, which means they are overridden by the selected `scheduler_profile`. Once you fill in a concrete value there, it overrides the corresponding profile behavior.

## Feature Overview

- `inspect`: Recursively inspect files or directories and output each file's detection result, matching reasons, and whether extraction is recommended.
- `scan`: Summarize extractable archives at the task level so you can review scan results before deciding to extract.
- `extract`: Perform scanning, password attempts, archive validation, extraction, and post-processing, while dynamically adjusting concurrency based on system load.
- `passwords`: Show the final list of passwords that may be tried, including command-line input and built-in common passwords.
- Windows integration: Register an Explorer context-menu entry through PowerShell scripts.
- Windows build: The build script automatically fills in missing 7-Zip runtime components and produces a distributable directory and zip package.

## Run Locally

1. Install Python 3.
2. Initialize the local development environment:

```powershell
.\scripts\setup_windows_dev.ps1
```

This script will:

- create `.venv`
- install the runtime dependencies listed in `requirements.txt`
- automatically download and restore missing 7-Zip components in the `tools` directory

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

### Dependencies

- Runtime dependencies: `requirements.txt`
- Build dependencies: `requirements-build.txt`
- 7-Zip runtime components: automatically downloaded by the build script and local setup script when missing

### Build

```powershell
.\scripts\build_windows.ps1
```

The build process automatically runs tests to help ensure that project changes do not accidentally delete ordinary files.

Optional parameters:

- `-SkipTests`: Skip tests and only validate the packaging pipeline.
- `-Clean`: Rebuild after additionally cleaning the build virtual environment.
- `-Version <string>`: Override the default version string used in release naming.

After the build finishes, it generates:

- `dist/SmartUnpacker/`: runnable release directory
- `release/*.zip`: distributable zip package

### Disclaimer

Although this software has been tested under complex scenarios, it does not guarantee that files will never be deleted by mistake. Use it at your own risk. The developer is not responsible for file loss.
