param(
    [string]$AppPath,
    [string]$PythonPath,
    [string]$MenuText = "Smart Unpacker",
    [string]$IconPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-Launcher {
    param(
        [string]$RepoRoot,
        [string]$PreferredAppPath,
        [string]$PreferredPythonPath
    )

    if ($PreferredAppPath) {
        $resolvedApp = (Resolve-Path -LiteralPath $PreferredAppPath).Path
        return @{
            Mode = "app"
            AppPath = $resolvedApp
            IconPath = $resolvedApp
        }
    }

    $exeCandidates = @(
        (Join-Path $RepoRoot "SmartUnpacker.exe"),
        (Join-Path $RepoRoot "dist\SmartUnpacker\SmartUnpacker.exe"),
        (Join-Path $RepoRoot "dist\SmartUnpacker.exe")
    )
    foreach ($candidate in $exeCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            $resolvedExe = (Resolve-Path -LiteralPath $candidate).Path
            return @{
                Mode = "app"
                AppPath = $resolvedExe
                IconPath = $resolvedExe
            }
        }
    }

    $defaultScript = Join-Path $RepoRoot "smart-unpacker.py"
    if (-not (Test-Path -LiteralPath $defaultScript)) {
        throw "No usable script entry was found. Expected smart-unpacker.py at the repository root."
    }
    $resolvedScript = (Resolve-Path -LiteralPath $defaultScript).Path

    $pythonCandidates = @()
    if ($PreferredPythonPath) {
        $pythonCandidates += $PreferredPythonPath
    }
    foreach ($commandName in @("python", "py")) {
        $command = Get-Command $commandName -ErrorAction SilentlyContinue
        if ($command) {
            $pythonCandidates += $command.Source
        }
    }
    $pythonCandidates = $pythonCandidates | Select-Object -Unique

    foreach ($candidate in $pythonCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            $resolvedPython = (Resolve-Path -LiteralPath $candidate).Path
            return @{
                Mode = "python"
                AppPath = $resolvedPython
                ScriptPath = $resolvedScript
                IconPath = $resolvedPython
            }
        }
    }

    throw "No usable Python interpreter was found. Please pass -PythonPath explicitly."
}

function New-CommandString {
    param(
        [hashtable]$Launcher,
        [string]$TargetToken
    )

    if ($Launcher.Mode -eq "app") {
        return ('"{0}" extract "{1}" --prompt-passwords --pause-on-exit' -f $Launcher.AppPath, $TargetToken)
    }

    return ('"{0}" "{1}" extract "{2}" --prompt-passwords --pause-on-exit' -f $Launcher.AppPath, $Launcher.ScriptPath, $TargetToken)
}

function Set-ContextMenuEntry {
    param(
        [string]$KeyPath,
        [string]$MenuLabel,
        [string]$CommandLine,
        [string]$IconValue
    )

    $null = New-Item -Path $KeyPath -Force
    Set-Item -Path $KeyPath -Value $MenuLabel
    Set-ItemProperty -Path $KeyPath -Name "Icon" -Value $IconValue

    $commandKey = Join-Path $KeyPath "command"
    $null = New-Item -Path $commandKey -Force
    Set-Item -Path $commandKey -Value $CommandLine
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$launcher = Resolve-Launcher -RepoRoot $repoRoot -PreferredAppPath $AppPath -PreferredPythonPath $PythonPath
$resolvedIconPath = if ($IconPath) { (Resolve-Path -LiteralPath $IconPath).Path } else { $launcher.IconPath }

$folderKey = "HKCU:\Software\Classes\Directory\shell\SmartUnpacker"
$backgroundKey = "HKCU:\Software\Classes\Directory\Background\shell\SmartUnpacker"

$folderCommand = New-CommandString -Launcher $launcher -TargetToken "%1"
$backgroundCommand = New-CommandString -Launcher $launcher -TargetToken "%V"

Set-ContextMenuEntry -KeyPath $folderKey -MenuLabel $MenuText -CommandLine $folderCommand -IconValue $resolvedIconPath
Set-ContextMenuEntry -KeyPath $backgroundKey -MenuLabel $MenuText -CommandLine $backgroundCommand -IconValue $resolvedIconPath

Write-Host "Context menu registration completed." -ForegroundColor Green
Write-Host "Folder menu key:" $folderKey
Write-Host "Directory background key:" $backgroundKey
Write-Host "Launch mode:" $launcher.Mode
if ($launcher.Mode -eq "app") {
    Write-Host "App path:" $launcher.AppPath
} else {
    Write-Host "Python path:" $launcher.AppPath
    Write-Host "Script path:" $launcher.ScriptPath
}
Write-Host ""
Write-Host ('You can now right-click a folder or directory background and choose "{0}".' -f $MenuText)
