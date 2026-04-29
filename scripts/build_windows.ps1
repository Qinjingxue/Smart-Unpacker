[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Clean,
    [string]$Version,
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$promptForAcceptanceTests = ($PSBoundParameters.Count -eq 0)

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-PythonCommand {
    foreach ($candidate in @("python", "py")) {
        try {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {
        }
    }
    throw "Python interpreter not found in PATH."
}

function Remove-IfExists {
    param([string]$LiteralPath)
    if (Test-Path -LiteralPath $LiteralPath) {
        Remove-Item -LiteralPath $LiteralPath -Recurse -Force
    }
}

function ConvertTo-NormalizedFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return ([System.IO.Path]::GetFullPath($Path).TrimEnd('\', '/') -replace '/', '\').ToLowerInvariant()
}

function Reset-StaleCMakeBuildDir {
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDir,
        [Parameter(Mandatory = $true)]
        [string]$BuildDir
    )

    $cachePath = Join-Path $BuildDir "CMakeCache.txt"
    if (-not (Test-Path -LiteralPath $cachePath)) {
        return
    }

    $expectedSource = ConvertTo-NormalizedFullPath -Path $SourceDir
    $actualSource = ""
    foreach ($line in Get-Content -LiteralPath $cachePath) {
        if ($line -like "CMAKE_HOME_DIRECTORY:INTERNAL=*") {
            $actualSource = ConvertTo-NormalizedFullPath -Path ($line.Substring("CMAKE_HOME_DIRECTORY:INTERNAL=".Length))
            break
        }
    }

    if ($actualSource -and $actualSource -ne $expectedSource) {
        Write-Host "CMake build cache points at a different source tree; recreating $BuildDir" -ForegroundColor Yellow
        Remove-IfExists -LiteralPath $BuildDir
    }
}

function Assert-PathExists {
    param(
        [string]$LiteralPath,
        [string]$Description
    )
    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        throw "$Description not found: $LiteralPath"
    }
}

function Assert-PathMissing {
    param(
        [string]$LiteralPath,
        [string]$Description
    )
    if (Test-Path -LiteralPath $LiteralPath) {
        throw "$Description should not exist: $LiteralPath"
    }
}

function Assert-CommandExists {
    param(
        [string]$Command,
        [string]$Description
    )
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        throw "$Description not found in PATH: $Command"
    }
}

function Get-ProcessBuildArch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
    switch ($arch) {
        "x64" { return "x64" }
        "arm64" { return "arm64" }
        default { return $arch }
    }
}

function Get-CMakePlatform {
    param([string]$BuildArch)
    switch ($BuildArch) {
        "x64" { return "x64" }
        "arm64" { return "ARM64" }
    }
    throw "Unsupported build architecture: $BuildArch"
}

function Get-RustTarget {
    param([string]$BuildArch)
    switch ($BuildArch) {
        "x64" { return "x86_64-pc-windows-msvc" }
        "arm64" { return "aarch64-pc-windows-msvc" }
    }
    throw "Unsupported build architecture: $BuildArch"
}

function Get-ExpectedPeMachine {
    param([string]$BuildArch)
    switch ($BuildArch) {
        "x64" { return 0x8664 }
        "arm64" { return 0xAA64 }
    }
    throw "Unsupported build architecture: $BuildArch"
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $stream = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        if ($stream.Length -lt 0x40) {
            throw "File is too small to be a PE image: $LiteralPath"
        }
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) {
                throw "Missing MZ signature: $LiteralPath"
            }
            $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
            $peOffset = $reader.ReadUInt32()
            if ($peOffset + 6 -gt $stream.Length) {
                throw "Invalid PE header offset: $LiteralPath"
            }
            $stream.Seek([int64]$peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
            if ($reader.ReadUInt32() -ne 0x00004550) {
                throw "Missing PE signature: $LiteralPath"
            }
            return [int]$reader.ReadUInt16()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Get-PeMachineName {
    param([int]$Machine)
    switch ($Machine) {
        0x014C { return "x86" }
        0x8664 { return "x64" }
        0xAA64 { return "arm64" }
        default { return ("0x{0:X4}" -f $Machine) }
    }
}

function Assert-PeMachine {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$BuildArch,
        [string]$Description = "PE image"
    )

    Assert-PathExists -LiteralPath $LiteralPath -Description $Description
    $expected = Get-ExpectedPeMachine -BuildArch $BuildArch
    $actual = Get-PeMachine -LiteralPath $LiteralPath
    if ($actual -ne $expected) {
        throw ("{0} architecture mismatch: expected {1}, got {2}: {3}" -f $Description, $BuildArch, (Get-PeMachineName -Machine $actual), $LiteralPath)
    }
    Write-Host ("{0} architecture: {1} ({2})" -f $Description, $BuildArch, $LiteralPath) -ForegroundColor Green
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        $joined = ($Arguments | ForEach-Object { $_ }) -join " "
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $joined"
    }
}

function Get-LatestWheel {
    param([string]$WheelRoot)
    $wheel = Get-ChildItem -LiteralPath $WheelRoot -Filter "*.whl" -File |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $wheel) {
        throw "Native wheel was not produced under: $WheelRoot"
    }
    return $wheel.FullName
}

function Get-MaturinCommand {
    param([string]$VenvScripts)

    $venvMaturin = Join-Path $VenvScripts "maturin.exe"
    if (Test-Path -LiteralPath $venvMaturin) {
        return $venvMaturin
    }

    $globalMaturin = Get-Command "maturin" -ErrorAction SilentlyContinue
    if ($globalMaturin) {
        return $globalMaturin.Source
    }

    throw "maturin executable not found. Install requirements-build.txt or make maturin available in PATH."
}

function Get-CMakeCommand {
    param([string]$VenvScripts)

    $venvCMake = Join-Path $VenvScripts "cmake.exe"
    if (Test-Path -LiteralPath $venvCMake) {
        return $venvCMake
    }

    $globalCMake = Get-Command "cmake" -ErrorAction SilentlyContinue
    if ($globalCMake) {
        return $globalCMake.Source
    }

    throw "cmake executable not found. Install requirements-build.txt or make CMake available in PATH."
}

function Test-NativeImport {
    param([string]$PythonPath)

    $code = @"
import packrelic_native as n
required = [
    'native_available', 'scanner_version',
    'scan_directory_entries', 'list_regular_files_in_directory',
    'scan_carrier_archive', 'scan_magics_anywhere',
    'scan_zip_central_directory_names', 'inspect_zip_eocd_structure',
    'inspect_pe_overlay_structure',
    'repair_read_file_range', 'repair_concat_ranges_to_bytes',
    'repair_write_candidate', 'repair_copy_range_to_file',
    'repair_concat_ranges_to_file', 'repair_patch_file',
    'archive_state_to_bytes_native', 'archive_state_size_native',
    'archive_state_write_to_file_native', 'archive_state_zip_manifest_native',
    'zip_deep_partial_recovery', 'zip_rebuild_from_local_headers',
    'zip_directory_field_repair', 'zip_conflict_resolver_rebuild',
    'gzip_footer_fix_repair', 'gzip_deflate_member_resync_repair',
    'zstd_frame_salvage_repair', 'tar_boundary_repair',
    'tar_sparse_pax_longname_repair', 'compression_stream_partial_recovery',
    'compression_stream_trailing_junk_trim', 'tar_compressed_partial_recovery',
    'tar_metadata_downgrade_recovery', 'archive_carrier_crop_recovery',
    'seven_zip_precise_boundary_repair', 'seven_zip_crc_field_repair',
    'seven_zip_next_header_field_repair', 'seven_zip_solid_block_partial_salvage',
    'rar_file_quarantine_rebuild', 'archive_nested_payload_salvage',
    'rar_block_chain_trim_recovery', 'rar_end_block_repair',
]
assert n.native_available()
missing = [name for name in required if not callable(getattr(n, name, None))]
assert not missing, missing
"@
    Invoke-Native -FilePath $PythonPath -Arguments @(
        "-c",
        $code
    )
}

function Test-SevenZipWrapper {
    param([string]$PythonPath)

    Invoke-Native -FilePath $PythonPath -Arguments @(
        "-c",
        "from packrelic.support.sevenzip_native import NativePasswordTester; tester = NativePasswordTester(); assert tester.available(), (tester.wrapper_path, tester.seven_zip_dll_path)"
    )
}

function Test-SevenZipWorker {
    param([string]$PythonPath)

    Invoke-Native -FilePath $PythonPath -Arguments @(
        "-c",
        "from packrelic.support.resources import get_7z_dll_path, get_sevenzip_worker_path; import os; assert os.path.exists(get_sevenzip_worker_path()); assert os.path.exists(get_7z_dll_path())"
    )
}

function Build-SevenZipWrapper {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CMakeCommand,
        [Parameter(Mandatory = $true)]
        [string]$WrapperRoot,
        [Parameter(Mandatory = $true)]
        [string]$BuildDir,
        [Parameter(Mandatory = $true)]
        [string]$ToolsRoot,
        [Parameter(Mandatory = $true)]
        [string]$SevenZipDllPath,
        [Parameter(Mandatory = $true)]
        [string]$BuildArch
    )

    Write-Step "Building 7z.dll C++ wrapper"
    Assert-PathExists -LiteralPath (Join-Path $WrapperRoot "CMakeLists.txt") -Description "7z wrapper CMake project"
    Assert-PathExists -LiteralPath $SevenZipDllPath -Description "Bundled 7z.dll"
    $cmakePlatform = Get-CMakePlatform -BuildArch $BuildArch
    Reset-StaleCMakeBuildDir -SourceDir $WrapperRoot -BuildDir $BuildDir
    Invoke-Native -FilePath $CMakeCommand -Arguments @("-S", $WrapperRoot, "-B", $BuildDir, "-A", $cmakePlatform, "-DCMAKE_BUILD_TYPE=Release")
    Invoke-Native -FilePath $CMakeCommand -Arguments @("--build", $BuildDir, "--config", "Release")
    if ((Get-ProcessBuildArch) -eq $BuildArch) {
        Invoke-Native -FilePath "ctest" -Arguments @("--test-dir", $BuildDir, "-C", "Release", "--output-on-failure")
    } else {
        Write-Host "Skipping C++ smoke test because $BuildArch binaries cannot run in the current process architecture." -ForegroundColor Yellow
    }

    $wrapperDll = Join-Path $BuildDir "Release\sevenzip_password_tester_capi.dll"
    $workerExe = Join-Path $BuildDir "Release\sevenzip_worker.exe"
    Assert-PathExists -LiteralPath $wrapperDll -Description "Built 7z wrapper DLL"
    Assert-PathExists -LiteralPath $workerExe -Description "Built 7z worker executable"
    Assert-PeMachine -LiteralPath $wrapperDll -BuildArch $BuildArch -Description "Built 7z wrapper DLL"
    Assert-PeMachine -LiteralPath $workerExe -BuildArch $BuildArch -Description "Built 7z worker executable"
    Copy-Item -LiteralPath $wrapperDll -Destination (Join-Path $ToolsRoot "sevenzip_password_tester_capi.dll") -Force
    Copy-Item -LiteralPath $workerExe -Destination (Join-Path $ToolsRoot "sevenzip_worker.exe") -Force
}

function Assert-PackagedNativeExtension {
    param(
        [string]$PackageRoot,
        [string]$BuildArch
    )

    $nativeExtension = Get-ChildItem -LiteralPath $PackageRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -like "packrelic_native*.pyd" -or
            $_.Name -like "packrelic_native*.dll"
        } |
        Select-Object -First 1

    if ($null -eq $nativeExtension) {
        throw "Packaged packrelic_native extension not found under: $PackageRoot"
    }

    Write-Host ("Packaged native extension: {0}" -f $nativeExtension.FullName) -ForegroundColor Green
    Assert-PeMachine -LiteralPath $nativeExtension.FullName -BuildArch $BuildArch -Description "Packaged packrelic_native extension"
}

function Test-PythonImports {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string[]]$Modules
    )

    $importList = ($Modules | ForEach-Object { "'$_'" }) -join ", "
    & $PythonPath -c "import importlib.util, sys; modules = [$importList]; missing = [name for name in modules if importlib.util.find_spec(name) is None]; sys.exit(0 if not missing else 1)"
    return ($LASTEXITCODE -eq 0)
}

function Install-RequirementsOrValidate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string]$RequirementsFile,
        [Parameter(Mandatory = $true)]
        [string[]]$RequiredModules,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    try {
        Invoke-Native -FilePath $PythonPath -Arguments @("-m", "pip", "install", "-r", $RequirementsFile)
        return
    } catch {
        Write-Warning "$Label install failed from $RequirementsFile. Falling back to already-available modules."
        if (Test-PythonImports -PythonPath $PythonPath -Modules $RequiredModules) {
            Write-Host "$Label modules are already importable in the build environment." -ForegroundColor Yellow
            return
        }
        throw
    }
}

function Invoke-WithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [string]$Description = "operation",
        [int]$MaxAttempts = 5,
        [int]$DelaySeconds = 2
    )

    $attempt = 0
    while ($true) {
        $attempt += 1
        try {
            & $ScriptBlock
            return
        } catch {
            if ($attempt -ge $MaxAttempts) {
                throw
            }
            Write-Warning ("{0} failed on attempt {1}/{2}: {3}" -f $Description, $attempt, $MaxAttempts, $_.Exception.Message)
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Get-ReleaseVersion {
    param(
        [string]$ExplicitVersion,
        [string]$RepoRoot
    )

    if ($ExplicitVersion) {
        return $ExplicitVersion
    }

    try {
        $gitOutput = & git -C $RepoRoot describe --tags --always 2>$null
        $gitVersion = (($gitOutput | Out-String).Trim())
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($gitVersion)) {
            return $gitVersion
        }
    } catch {
    }

    return (Get-Date -Format "yyyyMMdd-HHmmss")
}

function Get-GitCommit {
    param([string]$RepoRoot)
    try {
        $gitOutput = & git -C $RepoRoot rev-parse --short HEAD 2>$null
        $commit = (($gitOutput | Out-String).Trim())
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($commit)) {
            return $commit
        }
    } catch {
    }
    return "unknown"
}

function Confirm-AcceptanceTests {
    while ($true) {
        $rawAnswer = Read-Host "Run acceptance tests before building? [Y/n]"
        $answer = if ($null -eq $rawAnswer) { "" } else { $rawAnswer.Trim() }
        if ($answer -eq "" -or $answer -match "^(?i:y|yes)$") {
            return $true
        }
        if ($answer -match "^(?i:n|no)$") {
            return $false
        }
        Write-Host "Please answer Y or N." -ForegroundColor Yellow
    }
}

function Copy-IfExists {
    param(
        [string]$Source,
        [string]$Destination
    )
    if (Test-Path -LiteralPath $Source) {
        Copy-Item -LiteralPath $Source -Destination $Destination -Force
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot
$buildArch = $Arch.ToLowerInvariant()
$processArch = Get-ProcessBuildArch
$rustTarget = Get-RustTarget -BuildArch $buildArch

Write-Step "Environment preflight"
if ($env:OS -ne "Windows_NT") {
    throw "This build script only supports Windows."
}
Write-Host "Requested architecture: $buildArch"
Write-Host "Build Python/process architecture: $processArch"
if ($processArch -ne $buildArch) {
    throw "Windows PyInstaller/PyO3 final executable builds must run under a target-architecture Python. This machine/process is '$processArch', so it cannot produce a real '$buildArch' sunpack.exe. Use an ARM64 Windows Python environment for -Arch arm64; use static PE validation on the resulting package."
}

$pythonCommand = Get-PythonCommand
$venvPath = Join-Path $repoRoot ".venv-build"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvScripts = Join-Path $venvPath "Scripts"
$specPath = Join-Path $repoRoot "PackRelic.spec"
$requirementsPath = Join-Path $repoRoot "requirements.txt"
$buildRequirementsPath = Join-Path $repoRoot "requirements-build.txt"
$iconPath = Join-Path $repoRoot "packrelic.ico"
$nativeCrateRoot = Join-Path $repoRoot "native\packrelic_native"
$nativeCargoToml = Join-Path $nativeCrateRoot "Cargo.toml"
$sevenZipWrapperRoot = Join-Path $repoRoot "native\sevenzip_password_tester"
$sevenZipWrapperBuildDir = Join-Path $sevenZipWrapperRoot ("build-" + $buildArch)
$toolsRoot = if ($buildArch -eq "x64") { Join-Path $repoRoot "tools" } else { Join-Path $repoRoot ("tools-" + $buildArch) }
$sevenZipPath = Join-Path $toolsRoot "7z.exe"
$sevenZipDllPath = Join-Path $toolsRoot "7z.dll"
$sevenZipWrapperDllPath = Join-Path $toolsRoot "sevenzip_password_tester_capi.dll"
$sevenZipWorkerPath = Join-Path $toolsRoot "sevenzip_worker.exe"
$sevenZipLicensePath = Join-Path $repoRoot "licenses\7zip-license.txt"
$distRoot = Join-Path $repoRoot "dist"
$buildRoot = Join-Path $repoRoot "build"
$nativeWheelRoot = Join-Path $buildRoot ("native-wheels-" + $buildArch)
$releaseRoot = Join-Path $repoRoot "release"
$distFolderName = if ($buildArch -eq "x64") { "packrelic" } else { "packrelic-" + $buildArch }
$appExeName = "sunpack.exe"
$distAppRoot = Join-Path $distRoot $distFolderName
$distExePath = Join-Path $distAppRoot $appExeName
$distInternalRoot = Join-Path $distAppRoot "_internal"
$distToolsRoot = Join-Path $distAppRoot "tools"
$distLicensesRoot = Join-Path $distAppRoot "licenses"
$versionValue = Get-ReleaseVersion -ExplicitVersion $Version -RepoRoot $repoRoot
$releaseZipName = "packrelic-windows-{0}-{1}.zip" -f $buildArch, $versionValue
$releaseZipPath = Join-Path $releaseRoot $releaseZipName
$runAcceptanceTests = -not $SkipTests

if ($promptForAcceptanceTests) {
    $runAcceptanceTests = Confirm-AcceptanceTests
}

Assert-PathExists -LiteralPath $requirementsPath -Description "requirements.txt"
Assert-PathExists -LiteralPath $buildRequirementsPath -Description "requirements-build.txt"
Assert-PathExists -LiteralPath $specPath -Description "PyInstaller spec"
Assert-PathExists -LiteralPath $iconPath -Description "PackRelic icon"
Assert-PathExists -LiteralPath $nativeCargoToml -Description "packrelic_native Cargo manifest"
Assert-PathExists -LiteralPath (Join-Path $sevenZipWrapperRoot "CMakeLists.txt") -Description "7z wrapper CMake project"
Assert-PathExists -LiteralPath $sevenZipPath -Description "Bundled 7-Zip executable"
Assert-PathExists -LiteralPath $sevenZipDllPath -Description "Bundled 7-Zip runtime DLL"
Assert-PathExists -LiteralPath $sevenZipLicensePath -Description "7-Zip license file"
Assert-CommandExists -Command "cargo" -Description "Rust toolchain"
Assert-PeMachine -LiteralPath $sevenZipPath -BuildArch $buildArch -Description "Bundled 7-Zip executable"
Assert-PeMachine -LiteralPath $sevenZipDllPath -BuildArch $buildArch -Description "Bundled 7-Zip runtime DLL"

if ($Clean) {
    Write-Step "Cleaning build virtual environment"
    Remove-IfExists -LiteralPath $venvPath
}

Write-Step "Preparing build virtual environment"
if (-not (Test-Path -LiteralPath $venvPython)) {
    Invoke-Native -FilePath $pythonCommand -Arguments @("-m", "venv", "--system-site-packages", $venvPath)
}

Invoke-Native -FilePath $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip")
Install-RequirementsOrValidate -PythonPath $venvPython -RequirementsFile $requirementsPath -RequiredModules @("psutil", "send2trash", "watchdog", "zstandard") -Label "Runtime dependency"
Install-RequirementsOrValidate -PythonPath $venvPython -RequirementsFile $buildRequirementsPath -RequiredModules @("PyInstaller", "maturin", "cmake") -Label "Build dependency"
$maturinCommand = Get-MaturinCommand -VenvScripts $venvScripts
$cmakeCommand = Get-CMakeCommand -VenvScripts $venvScripts

$env:Path = "$venvScripts;$env:Path"
$env:PYTHONPATH = $repoRoot

Write-Step "Cleaning previous build outputs"
Remove-IfExists -LiteralPath $buildRoot
Remove-IfExists -LiteralPath $distRoot
Remove-IfExists -LiteralPath $releaseRoot
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null

Write-Step "Building and installing Rust native extension"
New-Item -ItemType Directory -Path $nativeWheelRoot -Force | Out-Null
Invoke-Native -FilePath "cargo" -Arguments @("--version")
Invoke-Native -FilePath $maturinCommand -Arguments @(
    "build",
    "--manifest-path", $nativeCargoToml,
    "--release",
    "--target", $rustTarget,
    "--out", $nativeWheelRoot
)
$nativeWheelPath = Get-LatestWheel -WheelRoot $nativeWheelRoot
Invoke-Native -FilePath $venvPython -Arguments @("-m", "pip", "install", "--force-reinstall", $nativeWheelPath)
Test-NativeImport -PythonPath $venvPython

Build-SevenZipWrapper -CMakeCommand $cmakeCommand -WrapperRoot $sevenZipWrapperRoot -BuildDir $sevenZipWrapperBuildDir -ToolsRoot $toolsRoot -SevenZipDllPath $sevenZipDllPath -BuildArch $buildArch
Assert-PathExists -LiteralPath $sevenZipWrapperDllPath -Description "Bundled 7z wrapper DLL"
Assert-PathExists -LiteralPath $sevenZipWorkerPath -Description "Bundled 7z worker executable"
Test-SevenZipWrapper -PythonPath $venvPython
Test-SevenZipWorker -PythonPath $venvPython

if ($runAcceptanceTests) {
    Write-Step "Running acceptance tests"
    Invoke-Native -FilePath "powershell" -Arguments @(
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $repoRoot "run_acceptance_tests.ps1"),
        "-NoWait"
    )
} else {
    Write-Host "Skipping acceptance tests by request." -ForegroundColor Yellow
}

Write-Step "Building Windows release with PyInstaller"
$env:PACKRELIC_DIST_NAME = $distFolderName
$env:PACKRELIC_EXE_NAME = [System.IO.Path]::GetFileNameWithoutExtension($appExeName)
Invoke-Native -FilePath $venvPython -Arguments @("-m", "PyInstaller", "--noconfirm", $specPath)

Write-Step "Validating packaged outputs"
Assert-PathExists -LiteralPath $distExePath -Description "Packaged sunpack executable"
Assert-PeMachine -LiteralPath $distExePath -BuildArch $buildArch -Description "Packaged sunpack executable"
Assert-PathExists -LiteralPath $distInternalRoot -Description "PyInstaller internal resource directory"
Assert-PackagedNativeExtension -PackageRoot $distAppRoot -BuildArch $buildArch
Assert-PathMissing -LiteralPath (Join-Path $distInternalRoot "builtin_passwords.txt") -Description "Duplicate internal password file"
Assert-PathMissing -LiteralPath (Join-Path $distInternalRoot "packrelic_config.json") -Description "Duplicate internal config file"

Write-Step "Adding release metadata and helper scripts"
$distPasswordPath = Join-Path $distAppRoot "builtin_passwords.txt"
$distConfigPath = Join-Path $distAppRoot "packrelic_config.json"
$distAdvancedConfigPath = Join-Path $distAppRoot "packrelic_advanced_config.json"
$distIconPath = Join-Path $distAppRoot "packrelic.ico"
Copy-Item -LiteralPath (Join-Path $repoRoot "builtin_passwords.txt") -Destination $distPasswordPath -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "packrelic_config.json") -Destination $distConfigPath -Force
Copy-Item -LiteralPath $iconPath -Destination $distIconPath -Force
Copy-IfExists -Source (Join-Path $repoRoot "packrelic_advanced_config.json") -Destination $distAdvancedConfigPath
Copy-Item -LiteralPath $toolsRoot -Destination $distToolsRoot -Recurse -Force

New-Item -ItemType Directory -Path $distLicensesRoot -Force | Out-Null
Copy-Item -LiteralPath $sevenZipLicensePath -Destination (Join-Path $distLicensesRoot "7zip-license.txt") -Force

$distScriptsRoot = Join-Path $distAppRoot "scripts"
New-Item -ItemType Directory -Path $distScriptsRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\register_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "register_context_menu.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\unregister_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "unregister_context_menu.ps1") -Force

Assert-PathExists -LiteralPath $distPasswordPath -Description "External password file"
Assert-PathExists -LiteralPath $distConfigPath -Description "External config file"
Assert-PathExists -LiteralPath $distIconPath -Description "External icon file"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7z.exe") -Description "External tools/7z.exe"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7z.dll") -Description "External tools/7z.dll"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "sevenzip_password_tester_capi.dll") -Description "External tools/sevenzip_password_tester_capi.dll"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "sevenzip_worker.exe") -Description "External tools/sevenzip_worker.exe"
Assert-PathExists -LiteralPath (Join-Path $distLicensesRoot "7zip-license.txt") -Description "External 7-Zip license file"
Assert-PeMachine -LiteralPath (Join-Path $distToolsRoot "7z.exe") -BuildArch $buildArch -Description "Packaged tools/7z.exe"
Assert-PeMachine -LiteralPath (Join-Path $distToolsRoot "7z.dll") -BuildArch $buildArch -Description "Packaged tools/7z.dll"
Assert-PeMachine -LiteralPath (Join-Path $distToolsRoot "sevenzip_password_tester_capi.dll") -BuildArch $buildArch -Description "Packaged tools/sevenzip_password_tester_capi.dll"
Assert-PeMachine -LiteralPath (Join-Path $distToolsRoot "sevenzip_worker.exe") -BuildArch $buildArch -Description "Packaged tools/sevenzip_worker.exe"

$versionFilePath = Join-Path $distAppRoot "VERSION.txt"
$gitCommit = Get-GitCommit -RepoRoot $repoRoot
$pythonVersion = (& $venvPython --version).Trim()
$metadata = @(
    "product=PackRelic"
    "version=$versionValue"
    "arch=$buildArch"
    "git_commit=$gitCommit"
    "python=$pythonVersion"
    "built_at_utc=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
)
[System.IO.File]::WriteAllLines($versionFilePath, $metadata)

if ($processArch -eq $buildArch) {
    Write-Step "Running packaged smoke tests"
    Invoke-Native -FilePath $distExePath -Arguments @("--help")
    Invoke-Native -FilePath $distExePath -Arguments @("passwords", "--json")
    Invoke-Native -FilePath $distExePath -Arguments @("inspect", (Join-Path $repoRoot "tests"), "--json")
    Invoke-Native -FilePath $distExePath -Arguments @("config", "validate", "--json")
} else {
    Write-Step "Skipping packaged smoke tests"
    Write-Host "Packaged executable is $buildArch and cannot run under the current $processArch process." -ForegroundColor Yellow
}

Write-Step "Creating distributable zip archive"
if (Test-Path -LiteralPath $releaseZipPath) {
    Remove-Item -LiteralPath $releaseZipPath -Force
}
Invoke-WithRetry -Description "Compress-Archive release packaging" -ScriptBlock {
    Compress-Archive -Path $distAppRoot -DestinationPath $releaseZipPath -Force
}
Assert-PathExists -LiteralPath $releaseZipPath -Description "Release zip archive"

Write-Host ""
Write-Host "Build completed successfully." -ForegroundColor Green
Write-Host "Version: $versionValue"
Write-Host "App directory: $distAppRoot"
Write-Host "Release zip: $releaseZipPath"
