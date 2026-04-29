[CmdletBinding()]
param(
    [switch]$Clean,
    [switch]$IncludeBuildDeps,
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

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

function Resolve-Uri {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseUri,
        [Parameter(Mandatory = $true)]
        [string]$Reference
    )

    $base = [System.Uri]$BaseUri
    $resolved = [System.Uri]::new($base, $Reference)
    return $resolved.AbsoluteUri
}

function Invoke-FileDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $destinationDir = Split-Path -Parent $DestinationPath
    if ($destinationDir) {
        New-Item -ItemType Directory -Path $destinationDir -Force | Out-Null
    }

    Write-Host "Downloading $Description from $Uri" -ForegroundColor Yellow
    $client = New-Object System.Net.WebClient
    try {
        $client.Headers["User-Agent"] = "SunPack dev bootstrap"
        $client.DownloadFile($Uri, $DestinationPath)
    } finally {
        $client.Dispose()
    }
}

function Get-7ZipWindowsDownloadInfo {
    param([string]$BuildArch = "x64")

    $downloadPageUri = "https://www.7-zip.org/download.html"
    $client = New-Object System.Net.WebClient
    try {
        $client.Headers["User-Agent"] = "SunPack dev bootstrap"
        $html = $client.DownloadString($downloadPageUri)
    } finally {
        $client.Dispose()
    }

    $sevenZipArch = if ($BuildArch -eq "arm64") { "arm64" } else { "x64" }
    $installerPattern = 'href="([^"]*7z\d+-' + [regex]::Escape($sevenZipArch) + '\.exe)"'
    $installerMatch = [regex]::Match($html, $installerPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $installerMatch.Success) {
        throw "Could not locate the latest 7-Zip $sevenZipArch installer link on $downloadPageUri"
    }

    return @{
        DownloadPageUri = $downloadPageUri
        InstallerUri = Resolve-Uri -BaseUri $downloadPageUri -Reference $installerMatch.Groups[1].Value
    }
}

function Ensure-Bundled7ZipAssets {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolsRoot,
        [Parameter(Mandatory = $true)]
        [string]$LicenseDestinationPath,
        [Parameter(Mandatory = $true)]
        [string]$BuildArch
    )

    $requiredToolFiles = @(
        "7z.exe",
        "7z.dll",
        "7z.sfx",
        "7zCon.sfx",
        "7-zip.dll"
    )
    if ($BuildArch -eq "x64") {
        $requiredToolFiles += "7-zip32.dll"
    }

    $missingToolFiles = @(
        $requiredToolFiles | Where-Object {
            -not (Test-Path -LiteralPath (Join-Path $ToolsRoot $_))
        }
    )

    $licenseMissing = -not (Test-Path -LiteralPath $LicenseDestinationPath)
    if ($missingToolFiles.Count -eq 0 -and -not $licenseMissing) {
        Write-Host "Bundled 7-Zip files are already present." -ForegroundColor Green
        return
    }

    Write-Step "Bootstrapping bundled 7-Zip files"
    if ($missingToolFiles.Count -gt 0) {
        Write-Host ("Missing bundled 7-Zip files: {0}" -f ($missingToolFiles -join ", ")) -ForegroundColor Yellow
    }
    if ($licenseMissing) {
        Write-Host "Missing 7-Zip license file." -ForegroundColor Yellow
    }

    $downloadInfo = Get-7ZipWindowsDownloadInfo -BuildArch $BuildArch
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sunpack-dev-7zip-" + [guid]::NewGuid().ToString("N"))
    $installerPath = Join-Path $tempRoot ("7zip-" + $BuildArch + "-installer.exe")
    $installRoot = Join-Path $tempRoot "installed"

    try {
        New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
        Invoke-FileDownload -Uri $downloadInfo.InstallerUri -DestinationPath $installerPath -Description "7-Zip $BuildArch installer"

        Write-Host "Installing 7-Zip into temporary workspace $installRoot" -ForegroundColor Yellow
        $process = Start-Process -FilePath $installerPath -ArgumentList @("/S", "/D=$installRoot") -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "7-Zip installer exited with code $($process.ExitCode)"
        }

        New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
        foreach ($fileName in $requiredToolFiles) {
            $sourcePath = Join-Path $installRoot $fileName
            Assert-PathExists -LiteralPath $sourcePath -Description "Downloaded 7-Zip component $fileName"
            Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $ToolsRoot $fileName) -Force
        }

        $optionalFiles = @("descript.ion")
        foreach ($fileName in $optionalFiles) {
            $sourcePath = Join-Path $installRoot $fileName
            if (Test-Path -LiteralPath $sourcePath) {
                Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $ToolsRoot $fileName) -Force
            }
        }

        $licenseSourcePath = Join-Path $installRoot "License.txt"
        Assert-PathExists -LiteralPath $licenseSourcePath -Description "Downloaded 7-Zip license file"
        New-Item -ItemType Directory -Path (Split-Path -Parent $LicenseDestinationPath) -Force | Out-Null
        Copy-Item -LiteralPath $licenseSourcePath -Destination $LicenseDestinationPath -Force
    } finally {
        Remove-IfExists -LiteralPath $tempRoot
    }
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

    throw "maturin executable not found. Install maturin or make it available in PATH."
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

    throw "cmake executable not found. Install CMake or make it available in PATH."
}

function Ensure-Maturin {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string]$VenvScripts
    )

    try {
        Invoke-Native -FilePath $PythonPath -Arguments @("-m", "pip", "install", "maturin>=1.8,<2") | Out-Host
    } catch {
        Write-Warning "maturin install failed. Falling back to already-available maturin executable."
    }
    return Get-MaturinCommand -VenvScripts $VenvScripts
}

function Ensure-CMake {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string]$VenvScripts
    )

    try {
        Invoke-Native -FilePath $PythonPath -Arguments @("-m", "pip", "install", "cmake>=3.25") | Out-Host
    } catch {
        Write-Warning "CMake install failed. Falling back to already-available cmake executable."
    }
    return Get-CMakeCommand -VenvScripts $VenvScripts
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
    Copy-Item -LiteralPath $wrapperDll -Destination (Join-Path $ToolsRoot "sevenzip_password_tester_capi.dll") -Force
    Copy-Item -LiteralPath $workerExe -Destination (Join-Path $ToolsRoot "sevenzip_worker.exe") -Force
}

function Test-NativeImport {
    param([string]$PythonPath)

    $code = @"
import sunpack_native as n
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
        "from sunpack.support.sevenzip_native import NativePasswordTester; tester = NativePasswordTester(); assert tester.available(), (tester.wrapper_path, tester.seven_zip_dll_path)"
    )
}

function Test-SevenZipWorker {
    param([string]$PythonPath)

    Invoke-Native -FilePath $PythonPath -Arguments @(
        "-c",
        "from sunpack.support.resources import get_7z_dll_path, get_sevenzip_worker_path; import os; assert os.path.exists(get_sevenzip_worker_path()); assert os.path.exists(get_7z_dll_path())"
    )
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
            Write-Host "$Label modules are already importable in the local environment." -ForegroundColor Yellow
            return
        }
        throw
    }
}

function Install-PackageOrValidate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string]$PackageName,
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    try {
        Invoke-Native -FilePath $PythonPath -Arguments @("-m", "pip", "install", $PackageName)
        return
    } catch {
        Write-Warning "$Label install failed. Falling back to already-available module."
        if (Test-PythonImports -PythonPath $PythonPath -Modules @($ModuleName)) {
            Write-Host "$Label module is already importable in the local environment." -ForegroundColor Yellow
            return
        }
        throw
    }
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot
$buildArch = $Arch.ToLowerInvariant()
$processArch = Get-ProcessBuildArch
$rustTarget = Get-RustTarget -BuildArch $buildArch

Write-Step "Environment preflight"
if ($env:OS -ne "Windows_NT") {
    throw "This setup script only supports Windows."
}
Write-Host "Requested architecture: $buildArch"
Write-Host "Python/process architecture: $processArch"
if ($processArch -ne $buildArch) {
    throw "Development setup for native Python extensions must run under a target-architecture Python. This process is '$processArch', so it cannot prepare a real '$buildArch' environment."
}

$pythonCommand = Get-PythonCommand
$venvPath = Join-Path $repoRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvScripts = Join-Path $venvPath "Scripts"
$requirementsPath = Join-Path $repoRoot "requirements.txt"
$buildRequirementsPath = Join-Path $repoRoot "requirements-build.txt"
$nativeCrateRoot = Join-Path $repoRoot "native\sunpack_native"
$nativeCargoToml = Join-Path $nativeCrateRoot "Cargo.toml"
$sevenZipWrapperRoot = Join-Path $repoRoot "native\sevenzip_password_tester"
$sevenZipWrapperBuildDir = Join-Path $sevenZipWrapperRoot ("build-" + $buildArch)
$buildRoot = Join-Path $repoRoot "build"
$nativeWheelRoot = Join-Path $buildRoot ("native-wheels-dev-" + $buildArch)
$toolsRoot = if ($buildArch -eq "x64") { Join-Path $repoRoot "tools" } else { Join-Path $repoRoot ("tools-" + $buildArch) }
$sevenZipDllPath = Join-Path $toolsRoot "7z.dll"
$sevenZipLicensePath = Join-Path $repoRoot "licenses\7zip-license.txt"

Assert-PathExists -LiteralPath $requirementsPath -Description "requirements.txt"
Assert-PathExists -LiteralPath $nativeCargoToml -Description "sunpack_native Cargo manifest"
Assert-CommandExists -Command "cargo" -Description "Rust toolchain"
if ($IncludeBuildDeps) {
    Assert-PathExists -LiteralPath $buildRequirementsPath -Description "requirements-build.txt"
}

if ($Clean) {
    Write-Step "Cleaning local virtual environment"
    Remove-IfExists -LiteralPath $venvPath
}

Write-Step "Preparing local virtual environment"
if (-not (Test-Path -LiteralPath $venvPython)) {
    Invoke-Native -FilePath $pythonCommand -Arguments @("-m", "venv", "--system-site-packages", $venvPath)
}

Invoke-Native -FilePath $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip")
Install-RequirementsOrValidate -PythonPath $venvPython -RequirementsFile $requirementsPath -RequiredModules @("psutil", "send2trash", "watchdog", "zstandard") -Label "Runtime dependency"
Install-PackageOrValidate -PythonPath $venvPython -PackageName "pytest" -ModuleName "pytest" -Label "Test dependency"
if ($IncludeBuildDeps) {
    Install-RequirementsOrValidate -PythonPath $venvPython -RequirementsFile $buildRequirementsPath -RequiredModules @("PyInstaller", "maturin", "cmake") -Label "Build dependency"
}

$env:Path = "$venvScripts;$env:Path"
$env:PYTHONPATH = $repoRoot
$env:VIRTUAL_ENV = $venvPath

Write-Step "Building and installing Rust native extension"
$maturinCommand = Ensure-Maturin -PythonPath $venvPython -VenvScripts $venvScripts
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

Ensure-Bundled7ZipAssets -ToolsRoot $toolsRoot -LicenseDestinationPath $sevenZipLicensePath -BuildArch $buildArch
$cmakeCommand = Ensure-CMake -PythonPath $venvPython -VenvScripts $venvScripts
Build-SevenZipWrapper -CMakeCommand $cmakeCommand -WrapperRoot $sevenZipWrapperRoot -BuildDir $sevenZipWrapperBuildDir -ToolsRoot $toolsRoot -SevenZipDllPath $sevenZipDllPath -BuildArch $buildArch
Test-SevenZipWrapper -PythonPath $venvPython
Test-SevenZipWorker -PythonPath $venvPython

Write-Step "Verifying local source execution"
Invoke-Native -FilePath $venvPython -Arguments @("sunpack.py", "--help")
Invoke-Native -FilePath $venvPython -Arguments @("-m", "pytest", "--version")

Write-Host ""
Write-Host "Local development environment is ready." -ForegroundColor Green
Write-Host "Virtual env: $venvPath"
Write-Host "Activate: $venvPath\\Scripts\\Activate.ps1"
