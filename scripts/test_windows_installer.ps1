[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallerPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
    }
}

function Test-PathEntry {
    param([string]$PathValue, [string]$Expected)
    $expectedPath = [System.IO.Path]::GetFullPath($Expected).TrimEnd('\')
    foreach ($entry in ([string]$PathValue -split ';')) {
        if (-not $entry.Trim()) {
            continue
        }
        try {
            $candidate = [System.IO.Path]::GetFullPath($entry.Trim().Trim('"')).TrimEnd('\')
        } catch {
            continue
        }
        if ($candidate.Equals($expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

$resolvedInstaller = (Resolve-Path -LiteralPath $InstallerPath).Path
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sunpack-installer-smoke-" + $PID)
$installRoot = Join-Path $testRoot "SunPack"
$installLog = Join-Path $testRoot "install.log"
$uninstallLog = Join-Path $testRoot "uninstall.log"
$folderMenuKey = "HKCU:\Software\Classes\Directory\shell\SunPack"
$backgroundMenuKey = "HKCU:\Software\Classes\Directory\Background\shell\SunPack"
$uninstaller = $null

foreach ($key in @(
    $folderMenuKey,
    $backgroundMenuKey,
    "HKCU:\Software\Classes\SunPack.FolderContextMenu",
    "HKCU:\Software\Classes\SunPack.BackgroundContextMenu"
)) {
    if (Test-Path -LiteralPath $key) {
        throw "Installer smoke test requires a clean context-menu state and will not overwrite an existing key: $key"
    }
}

New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    Invoke-Checked -FilePath $resolvedInstaller -Arguments @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/SP-",
        "/TASKS=addtopath,contextmenu",
        "/DIR=$installRoot",
        "/LOG=$installLog"
    )

    $appPath = Join-Path $installRoot "sunpack.exe"
    if (-not (Test-Path -LiteralPath $appPath)) {
        throw "Installed executable was not found: $appPath"
    }
    Invoke-Checked -FilePath $appPath -Arguments @("--help")

    $userPath = [string](Get-ItemProperty -LiteralPath "HKCU:\Environment" -Name "Path" -ErrorAction SilentlyContinue).Path
    if (-not (Test-PathEntry -PathValue $userPath -Expected $installRoot)) {
        throw "Installer did not add the application directory to the current user's PATH."
    }
    foreach ($key in @($folderMenuKey, $backgroundMenuKey)) {
        if (-not (Test-Path -LiteralPath $key)) {
            throw "Installer did not register the expected context menu key: $key"
        }
    }
    $directCommandKey = "HKCU:\Software\Classes\SunPack.FolderContextMenu\shell\DirectExtract\command"
    $directCommand = [string](Get-Item -LiteralPath $directCommandKey).GetValue("")
    if ($directCommand -notlike "*$appPath*") {
        throw "Context menu command does not reference the installed executable: $directCommand"
    }

    $uninstaller = Get-ChildItem -LiteralPath $installRoot -Filter "unins*.exe" -File | Select-Object -First 1
    if ($null -eq $uninstaller) {
        throw "Inno Setup uninstaller was not created under: $installRoot"
    }
    Invoke-Checked -FilePath $uninstaller.FullName -Arguments @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/LOG=$uninstallLog"
    )
    $uninstaller = $null

    $userPathAfter = [string](Get-ItemProperty -LiteralPath "HKCU:\Environment" -Name "Path" -ErrorAction SilentlyContinue).Path
    if (Test-PathEntry -PathValue $userPathAfter -Expected $installRoot) {
        throw "Uninstaller left the application directory in the current user's PATH."
    }
    foreach ($key in @($folderMenuKey, $backgroundMenuKey)) {
        if (Test-Path -LiteralPath $key) {
            throw "Uninstaller left a context menu key behind: $key"
        }
    }
    if (Test-Path -LiteralPath $installRoot) {
        throw "Uninstaller left the application directory behind: $installRoot"
    }

    Write-Host "Windows installer smoke test passed." -ForegroundColor Green
} finally {
    if ($null -ne $uninstaller -and (Test-Path -LiteralPath $uninstaller.FullName)) {
        try {
            & $uninstaller.FullName /VERYSILENT /SUPPRESSMSGBOXES /NORESTART | Out-Null
        } catch {
        }
    }
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
