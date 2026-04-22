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
        $client.Headers["User-Agent"] = "SmartUnpacker build bootstrap"
        $client.DownloadFile($Uri, $DestinationPath)
    } finally {
        $client.Dispose()
    }
}

function Get-7ZipWindowsDownloadInfo {
    $downloadPageUri = "https://www.7-zip.org/download.html"
    $client = New-Object System.Net.WebClient
    try {
        $client.Headers["User-Agent"] = "SmartUnpacker build bootstrap"
        $html = $client.DownloadString($downloadPageUri)
    } finally {
        $client.Dispose()
    }

    $installerMatch = [regex]::Match($html, 'href="([^"]*7z\d+-x64\.exe)"', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $installerMatch.Success) {
        throw "Could not locate the latest 7-Zip x64 installer link on $downloadPageUri"
    }

    return @{
        DownloadPageUri = $downloadPageUri
        InstallerUri = Resolve-Uri -BaseUri $downloadPageUri -Reference $installerMatch.Groups[1].Value
    }
}

function Ensure-Bundled7ZipAssets {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$ToolsRoot,
        [Parameter(Mandatory = $true)]
        [string]$LicenseDestinationPath
    )

    $requiredToolFiles = @(
        "7z.exe",
        "7z.dll",
        "7z.sfx",
        "7zCon.sfx",
        "7-zip.dll",
        "7-zip32.dll"
    )

    $missingToolFiles = @(
        $requiredToolFiles | Where-Object {
            -not (Test-Path -LiteralPath (Join-Path $ToolsRoot $_))
        }
    )

    $licenseMissing = -not (Test-Path -LiteralPath $LicenseDestinationPath)
    if ($missingToolFiles.Count -eq 0 -and -not $licenseMissing) {
        return
    }

    Write-Step "Bootstrapping bundled 7-Zip files"
    if ($missingToolFiles.Count -gt 0) {
        Write-Host ("Missing bundled 7-Zip files: {0}" -f ($missingToolFiles -join ", ")) -ForegroundColor Yellow
    }
    if ($licenseMissing) {
        Write-Host "Missing 7-Zip license file." -ForegroundColor Yellow
    }

    $downloadInfo = Get-7ZipWindowsDownloadInfo
    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("smart-unpacker-7zip-" + [guid]::NewGuid().ToString("N"))
    $installerPath = Join-Path $tempRoot "7zip-x64-installer.exe"
    $installRoot = Join-Path $tempRoot "installed"

    try {
        New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
        Invoke-FileDownload -Uri $downloadInfo.InstallerUri -DestinationPath $installerPath -Description "7-Zip x64 installer"

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
$toolsRoot = Join-Path $repoRoot "tools"
$sevenZipPath = Join-Path $repoRoot "tools\7z.exe"
$sevenZipDllPath = Join-Path $repoRoot "tools\7z.dll"
$sevenZipSfxPath = Join-Path $repoRoot "tools\7z.sfx"
$sevenZipConSfxPath = Join-Path $repoRoot "tools\7zCon.sfx"
$sevenZipShellDllPath = Join-Path $repoRoot "tools\7-zip.dll"
$sevenZipShell32DllPath = Join-Path $repoRoot "tools\7-zip32.dll"
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
Ensure-Bundled7ZipAssets -RepoRoot $repoRoot -ToolsRoot $toolsRoot -LicenseDestinationPath $sevenZipLicensePath
Assert-PathExists -LiteralPath $sevenZipPath -Description "Bundled 7-Zip executable"
Assert-PathExists -LiteralPath $sevenZipDllPath -Description "Bundled 7-Zip runtime DLL"
Assert-PathExists -LiteralPath $sevenZipSfxPath -Description "Bundled 7-Zip GUI SFX module"
Assert-PathExists -LiteralPath $sevenZipConSfxPath -Description "Bundled 7-Zip console SFX module"
Assert-PathExists -LiteralPath $sevenZipShellDllPath -Description "Bundled 7-Zip shell helper DLL"
Assert-PathExists -LiteralPath $sevenZipShell32DllPath -Description "Bundled 7-Zip 32-bit shell helper DLL"
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
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7z.dll") -Description "External tools/7z.dll"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7z.sfx") -Description "External tools/7z.sfx"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7zCon.sfx") -Description "External tools/7zCon.sfx"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7-zip.dll") -Description "External tools/7-zip.dll"
Assert-PathExists -LiteralPath (Join-Path $distToolsRoot "7-zip32.dll") -Description "External tools/7-zip32.dll"
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
Invoke-WithRetry -Description "Compress-Archive release packaging" -ScriptBlock {
    Compress-Archive -Path $distAppRoot -DestinationPath $releaseZipPath -Force
}
Assert-PathExists -LiteralPath $releaseZipPath -Description "Release zip archive"

Write-Host ""
Write-Host "Build completed successfully." -ForegroundColor Green
Write-Host "Version: $versionValue"
Write-Host "App directory: $distAppRoot"
Write-Host "Release zip: $releaseZipPath"
