[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Clean,
    [string]$Version
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

    Invoke-Native -FilePath $PythonPath -Arguments @(
        "-c",
        "import smart_unpacker_native as n; assert n.native_available(); assert n.scanner_version(); assert callable(n.scan_directory_entries); assert callable(n.list_regular_files_in_directory); assert callable(n.scan_carrier_archive); assert callable(n.scan_magics_anywhere); assert callable(n.scan_zip_central_directory_names); assert callable(n.inspect_zip_eocd_structure); assert callable(n.inspect_pe_overlay_structure)"
    )
}

function Test-SevenZipWrapper {
    param([string]$PythonPath)

    Invoke-Native -FilePath $PythonPath -Arguments @(
        "-c",
        "from smart_unpacker.support.sevenzip_native import NativePasswordTester; tester = NativePasswordTester(); assert tester.available(), (tester.wrapper_path, tester.seven_zip_dll_path)"
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
        [string]$SevenZipDllPath
    )

    Write-Step "Building 7z.dll C++ wrapper"
    Assert-PathExists -LiteralPath (Join-Path $WrapperRoot "CMakeLists.txt") -Description "7z wrapper CMake project"
    Assert-PathExists -LiteralPath $SevenZipDllPath -Description "Bundled 7z.dll"
    Invoke-Native -FilePath $CMakeCommand -Arguments @("-S", $WrapperRoot, "-B", $BuildDir, "-DCMAKE_BUILD_TYPE=Release")
    Invoke-Native -FilePath $CMakeCommand -Arguments @("--build", $BuildDir, "--config", "Release")
    Invoke-Native -FilePath "ctest" -Arguments @("--test-dir", $BuildDir, "-C", "Release", "--output-on-failure")

    $wrapperDll = Join-Path $BuildDir "Release\sevenzip_password_tester_capi.dll"
    Assert-PathExists -LiteralPath $wrapperDll -Description "Built 7z wrapper DLL"
    Copy-Item -LiteralPath $wrapperDll -Destination (Join-Path $ToolsRoot "sevenzip_password_tester_capi.dll") -Force
}

function Assert-PackagedNativeExtension {
    param([string]$PackageRoot)

    $nativeExtension = Get-ChildItem -LiteralPath $PackageRoot -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -like "smart_unpacker_native*.pyd" -or
            $_.Name -like "smart_unpacker_native*.dll"
        } |
        Select-Object -First 1

    if ($null -eq $nativeExtension) {
        throw "Packaged smart_unpacker_native extension not found under: $PackageRoot"
    }

    Write-Host ("Packaged native extension: {0}" -f $nativeExtension.FullName) -ForegroundColor Green
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

Write-Step "Environment preflight"
if ($env:OS -ne "Windows_NT") {
    throw "This build script only supports Windows."
}

$pythonCommand = Get-PythonCommand
$venvPath = Join-Path $repoRoot ".venv-build"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvScripts = Join-Path $venvPath "Scripts"
$specPath = Join-Path $repoRoot "SmartUnpacker.spec"
$requirementsPath = Join-Path $repoRoot "requirements.txt"
$buildRequirementsPath = Join-Path $repoRoot "requirements-build.txt"
$nativeCrateRoot = Join-Path $repoRoot "native\smart_unpacker_native"
$nativeCargoToml = Join-Path $nativeCrateRoot "Cargo.toml"
$sevenZipWrapperRoot = Join-Path $repoRoot "native\sevenzip_password_tester"
$sevenZipWrapperBuildDir = Join-Path $sevenZipWrapperRoot "build"
$toolsRoot = Join-Path $repoRoot "tools"
$sevenZipPath = Join-Path $toolsRoot "7z.exe"
$sevenZipDllPath = Join-Path $toolsRoot "7z.dll"
$sevenZipWrapperDllPath = Join-Path $toolsRoot "sevenzip_password_tester_capi.dll"
$sevenZipLicensePath = Join-Path $repoRoot "licenses\7zip-license.txt"
$distRoot = Join-Path $repoRoot "dist"
$buildRoot = Join-Path $repoRoot "build"
$nativeWheelRoot = Join-Path $buildRoot "native-wheels"
$releaseRoot = Join-Path $repoRoot "release"
$distAppRoot = Join-Path $distRoot "sunpack"
$distExePath = Join-Path $distAppRoot "sunpack.exe"
$distInternalRoot = Join-Path $distAppRoot "_internal"
$distToolsRoot = Join-Path $distAppRoot "tools"
$distLicensesRoot = Join-Path $distAppRoot "licenses"
$versionValue = Get-ReleaseVersion -ExplicitVersion $Version -RepoRoot $repoRoot
$releaseZipName = "sunpack-windows-x64-{0}.zip" -f $versionValue
$releaseZipPath = Join-Path $releaseRoot $releaseZipName
$runAcceptanceTests = -not $SkipTests

if ($promptForAcceptanceTests) {
    $runAcceptanceTests = Confirm-AcceptanceTests
}

Assert-PathExists -LiteralPath $requirementsPath -Description "requirements.txt"
Assert-PathExists -LiteralPath $buildRequirementsPath -Description "requirements-build.txt"
Assert-PathExists -LiteralPath $specPath -Description "PyInstaller spec"
Assert-PathExists -LiteralPath $nativeCargoToml -Description "smart_unpacker_native Cargo manifest"
Assert-PathExists -LiteralPath (Join-Path $sevenZipWrapperRoot "CMakeLists.txt") -Description "7z wrapper CMake project"
Assert-PathExists -LiteralPath $sevenZipPath -Description "Bundled 7-Zip executable"
Assert-PathExists -LiteralPath $sevenZipDllPath -Description "Bundled 7-Zip runtime DLL"
Assert-PathExists -LiteralPath $sevenZipLicensePath -Description "7-Zip license file"
Assert-CommandExists -Command "cargo" -Description "Rust toolchain"

if ($Clean) {
    Write-Step "Cleaning build virtual environment"
    Remove-IfExists -LiteralPath $venvPath
}

Write-Step "Preparing build virtual environment"
if (-not (Test-Path -LiteralPath $venvPython)) {
    Invoke-Native -FilePath $pythonCommand -Arguments @("-m", "venv", "--system-site-packages", $venvPath)
}

Invoke-Native -FilePath $venvPython -Arguments @("-m", "pip", "install", "--upgrade", "pip")
Install-RequirementsOrValidate -PythonPath $venvPython -RequirementsFile $requirementsPath -RequiredModules @("psutil", "send2trash") -Label "Runtime dependency"
Install-RequirementsOrValidate -PythonPath $venvPython -RequirementsFile $buildRequirementsPath -RequiredModules @("PyInstaller", "cmake") -Label "Build dependency"
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
    "--out", $nativeWheelRoot
)
$nativeWheelPath = Get-LatestWheel -WheelRoot $nativeWheelRoot
Invoke-Native -FilePath $venvPython -Arguments @("-m", "pip", "install", "--force-reinstall", $nativeWheelPath)
Test-NativeImport -PythonPath $venvPython

Build-SevenZipWrapper -CMakeCommand $cmakeCommand -WrapperRoot $sevenZipWrapperRoot -BuildDir $sevenZipWrapperBuildDir -ToolsRoot $toolsRoot -SevenZipDllPath $sevenZipDllPath
Assert-PathExists -LiteralPath $sevenZipWrapperDllPath -Description "Bundled 7z wrapper DLL"
Test-SevenZipWrapper -PythonPath $venvPython

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
Invoke-Native -FilePath $venvPython -Arguments @("-m", "PyInstaller", "--noconfirm", $specPath)

Write-Step "Validating packaged outputs"
Assert-PathExists -LiteralPath $distExePath -Description "Packaged sunpack executable"
Assert-PathExists -LiteralPath $distInternalRoot -Description "PyInstaller internal resource directory"
Assert-PackagedNativeExtension -PackageRoot $distAppRoot
Assert-PathMissing -LiteralPath (Join-Path $distInternalRoot "builtin_passwords.txt") -Description "Duplicate internal password file"
Assert-PathMissing -LiteralPath (Join-Path $distInternalRoot "smart_unpacker_config.json") -Description "Duplicate internal config file"

Write-Step "Adding release metadata and helper scripts"
$distPasswordPath = Join-Path $distAppRoot "builtin_passwords.txt"
$distConfigPath = Join-Path $distAppRoot "smart_unpacker_config.json"
$distAdvancedConfigPath = Join-Path $distAppRoot "smart_unpacker_advanced_config.json"
Copy-Item -LiteralPath (Join-Path $repoRoot "builtin_passwords.txt") -Destination $distPasswordPath -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "smart_unpacker_config.json") -Destination $distConfigPath -Force
Copy-IfExists -Source (Join-Path $repoRoot "smart_unpacker_advanced_config.json") -Destination $distAdvancedConfigPath
Copy-Item -LiteralPath $toolsRoot -Destination $distToolsRoot -Recurse -Force

New-Item -ItemType Directory -Path $distLicensesRoot -Force | Out-Null
Copy-Item -LiteralPath $sevenZipLicensePath -Destination (Join-Path $distLicensesRoot "7zip-license.txt") -Force

$distScriptsRoot = Join-Path $distAppRoot "scripts"
New-Item -ItemType Directory -Path $distScriptsRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\register_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "register_context_menu.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\unregister_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "unregister_context_menu.ps1") -Force

Assert-PathExists -LiteralPath $distPasswordPath -Description "External password file"
Assert-PathExists -LiteralPath $distConfigPath -Description "External config file"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7z.exe") -Description "External tools/7z.exe"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7z.dll") -Description "External tools/7z.dll"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "sevenzip_password_tester_capi.dll") -Description "External tools/sevenzip_password_tester_capi.dll"
Assert-PathExists -LiteralPath (Join-Path $distLicensesRoot "7zip-license.txt") -Description "External 7-Zip license file"

$versionFilePath = Join-Path $distAppRoot "VERSION.txt"
$gitCommit = Get-GitCommit -RepoRoot $repoRoot
$pythonVersion = (& $venvPython --version).Trim()
$metadata = @(
    "product=SmartUnpacker"
    "version=$versionValue"
    "git_commit=$gitCommit"
    "python=$pythonVersion"
    "built_at_utc=$([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))"
)
[System.IO.File]::WriteAllLines($versionFilePath, $metadata)

Write-Step "Running packaged smoke tests"
Invoke-Native -FilePath $distExePath -Arguments @("--help")
Invoke-Native -FilePath $distExePath -Arguments @("passwords", "--json")
Invoke-Native -FilePath $distExePath -Arguments @("inspect", (Join-Path $repoRoot "tests"), "--json")

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
