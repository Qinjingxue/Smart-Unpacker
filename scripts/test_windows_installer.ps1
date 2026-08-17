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
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList $Arguments `
        -Wait `
        -PassThru `
        -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw "Command failed with exit code $($process.ExitCode): $FilePath $($Arguments -join ' ')"
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
$startupRunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$startupValueName = "SunPackWatchService"
$uninstaller = $null

if (Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName -ErrorAction SilentlyContinue) {
    throw "Installer smoke test requires a clean startup state and will not overwrite an existing Run value: $startupValueName"
}

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
        "/TASKS=addtopath,contextmenu,autostart",
        "/DIR=$installRoot",
        "/LOG=$installLog"
    )

    $appPath = Join-Path $installRoot "sunpack.exe"
    $watchAppPath = Join-Path $installRoot "sunpack-watch.exe"
    $builtinPasswordsPath = Join-Path $installRoot "builtin_passwords.txt"
    if (-not (Test-Path -LiteralPath $appPath)) {
        throw "Installed executable was not found: $appPath"
    }
    if (-not (Test-Path -LiteralPath $watchAppPath)) {
        throw "Installed watch GUI executable was not found: $watchAppPath"
    }
    if (-not (Test-Path -LiteralPath $builtinPasswordsPath)) {
        throw "Installed builtin password file was not found: $builtinPasswordsPath"
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
    $startupCommand = [string](Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName).$startupValueName
    if ($startupCommand -ne ('"{0}"' -f $watchAppPath)) {
        throw "Startup Run value is incorrect: $startupCommand"
    }

    $watchRootsPath = Join-Path $installRoot "sunpack_watch_roots.txt"
    $watchRootsContent = "D:\Archives`nE:\Incoming`n"
    Set-Content -LiteralPath $watchRootsPath -Value $watchRootsContent -Encoding UTF8 -NoNewline
    $builtinPasswordsContent = "installer-smoke-user-password`n"
    Set-Content -LiteralPath $builtinPasswordsPath -Value $builtinPasswordsContent -Encoding UTF8 -NoNewline
    $staleUpgradeMarker = Join-Path $installRoot "stale-upgrade-marker.json"
    Set-Content -LiteralPath $staleUpgradeMarker -Value "stale" -Encoding UTF8
    $staleConfigDir = Join-Path $installRoot "config"
    New-Item -ItemType Directory -Path $staleConfigDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $staleConfigDir "old-settings.json") -Value "stale" -Encoding UTF8
    Invoke-Checked -FilePath $resolvedInstaller -Arguments @(
        "/VERYSILENT",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/SP-",
        "/TASKS=addtopath,contextmenu,autostart",
        "/DIR=$installRoot",
        "/LOG=$installLog"
    )
    $watchRootsAfterUpgrade = Get-Content -LiteralPath $watchRootsPath -Raw -Encoding UTF8
    if ($watchRootsAfterUpgrade -ne $watchRootsContent) {
        throw "Upgrade install overwrote the existing watch roots file: $watchRootsPath"
    }
    $builtinPasswordsAfterUpgrade = Get-Content -LiteralPath $builtinPasswordsPath -Raw -Encoding UTF8
    if ($builtinPasswordsAfterUpgrade -ne $builtinPasswordsContent) {
        throw "Upgrade install overwrote the existing builtin password file: $builtinPasswordsPath"
    }
    if (Test-Path -LiteralPath $staleUpgradeMarker) {
        throw "Upgrade install left stale application data behind: $staleUpgradeMarker"
    }
    if (Test-Path -LiteralPath $staleConfigDir) {
        throw "Upgrade install left stale configuration data behind: $staleConfigDir"
    }
    Remove-Item -LiteralPath $watchRootsPath -Force
    Remove-Item -LiteralPath $builtinPasswordsPath -Force
    $watchStateDir = Join-Path $installRoot ".sunpack_watch"
    New-Item -ItemType Directory -Path $watchStateDir -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $watchStateDir "watch.stop") -Value "installer-smoke" -Encoding UTF8
    $localSunPackCache = Join-Path $env:LOCALAPPDATA "SunPack\cache"
    New-Item -ItemType Directory -Path $localSunPackCache -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $localSunPackCache "machine_probe.json") -Value "{}" -Encoding UTF8
    Set-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName -Value ('"{0}"' -f $watchAppPath)

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
    if (Get-ItemProperty -LiteralPath $startupRunKey -Name $startupValueName -ErrorAction SilentlyContinue) {
        throw "Uninstaller left the startup Run value behind: $startupValueName"
    }
    if (Test-Path -LiteralPath $watchStateDir) {
        throw "Uninstaller left the watch state directory behind: $watchStateDir"
    }
    if (Test-Path -LiteralPath $localSunPackCache) {
        throw "Uninstaller left the local SunPack cache behind: $localSunPackCache"
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
