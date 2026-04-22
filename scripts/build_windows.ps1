[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$Clean,
    [string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-PythonCommand {
    $candidates = @("python", "py")
    foreach ($candidate in $candidates) {
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

function Get-ReleaseVersion {
    param(
        [string]$ExplicitVersion,
        [string]$RepoRoot
    )

    if ($ExplicitVersion) {
        return $ExplicitVersion
    }

    try {
        $gitVersion = (& git -C $RepoRoot describe --tags --always 2>$null).Trim()
        if ($LASTEXITCODE -eq 0 -and $gitVersion) {
            return $gitVersion
        }
    } catch {
    }

    return (Get-Date -Format "yyyyMMdd-HHmmss")
}

function Get-GitCommit {
    param([string]$RepoRoot)
    try {
        $commit = (& git -C $RepoRoot rev-parse --short HEAD 2>$null).Trim()
        if ($LASTEXITCODE -eq 0 -and $commit) {
            return $commit
        }
    } catch {
    }
    return "unknown"
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
$sevenZipPath = Join-Path $repoRoot "tools\7z.exe"
$sevenZipLicensePath = Join-Path $repoRoot "licenses\7zip-license.txt"
$distRoot = Join-Path $repoRoot "dist"
$buildRoot = Join-Path $repoRoot "build"
$releaseRoot = Join-Path $repoRoot "release"
$distAppRoot = Join-Path $distRoot "SmartUnpacker"
$distExePath = Join-Path $distAppRoot "SmartUnpacker.exe"
$distInternalRoot = Join-Path $distAppRoot "_internal"
$distToolsRoot = Join-Path $distAppRoot "tools"
$distLicensesRoot = Join-Path $distAppRoot "licenses"
$versionValue = Get-ReleaseVersion -ExplicitVersion $Version -RepoRoot $repoRoot
$releaseZipName = "SmartUnpacker-windows-x64-{0}.zip" -f $versionValue
$releaseZipPath = Join-Path $releaseRoot $releaseZipName

Assert-PathExists -LiteralPath $requirementsPath -Description "requirements.txt"
Assert-PathExists -LiteralPath $buildRequirementsPath -Description "requirements-build.txt"
Assert-PathExists -LiteralPath $specPath -Description "PyInstaller spec"
Assert-PathExists -LiteralPath $sevenZipPath -Description "Bundled 7-Zip executable"
Assert-PathExists -LiteralPath $sevenZipLicensePath -Description "7-Zip license file"

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
Install-RequirementsOrValidate -PythonPath $venvPython -RequirementsFile $buildRequirementsPath -RequiredModules @("PyInstaller") -Label "Build dependency"

$env:Path = "$venvScripts;$env:Path"

Write-Step "Cleaning previous build outputs"
Remove-IfExists -LiteralPath $buildRoot
Remove-IfExists -LiteralPath $distRoot
Remove-IfExists -LiteralPath $releaseRoot
New-Item -ItemType Directory -Path $releaseRoot -Force | Out-Null

if (-not $SkipTests) {
    Write-Step "Running acceptance tests"
    Invoke-Native -FilePath (Join-Path $repoRoot "run_acceptance_tests.ps1")
} else {
    Write-Host "Skipping acceptance tests by request." -ForegroundColor Yellow
}

Write-Step "Building Windows release with PyInstaller"
Invoke-Native -FilePath $venvPython -Arguments @("-m", "PyInstaller", "--noconfirm", $specPath)

Write-Step "Validating packaged outputs"
Assert-PathExists -LiteralPath $distExePath -Description "Packaged SmartUnpacker executable"
Assert-PathExists -LiteralPath $distInternalRoot -Description "PyInstaller internal resource directory"
Assert-PathExists -LiteralPath (Join-Path $distInternalRoot "builtin_passwords.txt") -Description "Bundled password file"
Assert-PathExists -LiteralPath (Join-Path $distInternalRoot "smart_unpacker_config.json") -Description "Bundled config file"

Write-Step "Adding release metadata and helper scripts"
$distPasswordPath = Join-Path $distAppRoot "builtin_passwords.txt"
$distConfigPath = Join-Path $distAppRoot "smart_unpacker_config.json"
Copy-Item -LiteralPath (Join-Path $distInternalRoot "builtin_passwords.txt") -Destination $distPasswordPath -Force
Copy-Item -LiteralPath (Join-Path $distInternalRoot "smart_unpacker_config.json") -Destination $distConfigPath -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "tools") -Destination $distToolsRoot -Recurse -Force

New-Item -ItemType Directory -Path $distLicensesRoot -Force | Out-Null
Copy-Item -LiteralPath $sevenZipLicensePath -Destination (Join-Path $distLicensesRoot "7zip-license.txt") -Force

$distScriptsRoot = Join-Path $distAppRoot "scripts"
New-Item -ItemType Directory -Path $distScriptsRoot -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\register_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "register_context_menu.ps1") -Force
Copy-Item -LiteralPath (Join-Path $repoRoot "scripts\unregister_context_menu.ps1") -Destination (Join-Path $distScriptsRoot "unregister_context_menu.ps1") -Force

Assert-PathExists -LiteralPath $distPasswordPath -Description "External password file"
Assert-PathExists -LiteralPath $distConfigPath -Description "External config file"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7z.exe") -Description "External tools/7z.exe"
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
Invoke-Native -FilePath $distExePath -Arguments @("inspect", (Join-Path $repoRoot "fixtures"), "--json")

Write-Step "Creating distributable zip archive"
if (Test-Path -LiteralPath $releaseZipPath) {
    Remove-Item -LiteralPath $releaseZipPath -Force
}
Compress-Archive -Path $distAppRoot -DestinationPath $releaseZipPath -Force
Assert-PathExists -LiteralPath $releaseZipPath -Description "Release zip archive"

Write-Host ""
Write-Host "Build completed successfully." -ForegroundColor Green
Write-Host "Version: $versionValue"
Write-Host "App directory: $distAppRoot"
Write-Host "Release zip: $releaseZipPath"
