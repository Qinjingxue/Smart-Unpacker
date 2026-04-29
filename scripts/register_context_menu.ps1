param(
    [string]$AppPath,
    [string]$PythonPath,
    [string]$MenuText,
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
        $appIcon = Resolve-PackRelicIcon -RepoRoot $RepoRoot -FallbackPath $resolvedApp
        return @{
            Mode = "app"
            AppPath = $resolvedApp
            IconPath = $appIcon
        }
    }

    $exeCandidates = @(
        (Join-Path $RepoRoot "sunpack.exe"),
        (Join-Path $RepoRoot "dist\\packrelic\sunpack.exe"),
        (Join-Path $RepoRoot "dist\sunpack.exe"),
        (Join-Path $RepoRoot "pkrc.exe"),
        (Join-Path $RepoRoot "dist\\packrelic\pkrc.exe"),
        (Join-Path $RepoRoot "dist\pkrc.exe")
    )
    foreach ($candidate in $exeCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            $resolvedExe = (Resolve-Path -LiteralPath $candidate).Path
            $appIcon = Resolve-PackRelicIcon -RepoRoot $RepoRoot -FallbackPath $resolvedExe
            return @{
                Mode = "app"
                AppPath = $resolvedExe
                IconPath = $appIcon
            }
        }
    }

    $defaultScript = Join-Path $RepoRoot "pkrc.py"
    if (-not (Test-Path -LiteralPath $defaultScript)) {
        throw "No usable script entry was found. Expected pkrc.py at the repository root."
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
            $appIcon = Resolve-PackRelicIcon -RepoRoot $RepoRoot -FallbackPath $resolvedPython
            return @{
                Mode = "python"
                AppPath = $resolvedPython
                ScriptPath = $resolvedScript
                IconPath = $appIcon
            }
        }
    }

    throw "No usable Python interpreter was found. Please pass -PythonPath explicitly."
}

function Resolve-PackRelicIcon {
    param(
        [string]$RepoRoot,
        [string]$FallbackPath
    )

    $iconPath = Join-Path $RepoRoot "packrelic.ico"
    if (Test-Path -LiteralPath $iconPath) {
        return (Resolve-Path -LiteralPath $iconPath).Path
    }
    return $FallbackPath
}

function New-CommandString {
    param(
        [hashtable]$Launcher,
        [string]$TargetToken,
        [string]$OutDirToken,
        [bool]$PromptPasswords
    )

    $passwordArg = if ($PromptPasswords) { " --ask-pw" } else { "" }
    if ($Launcher.Mode -eq "app") {
        return ('"{0}" extract "{1}" --out-dir "{2}"{3} --pause' -f $Launcher.AppPath, $TargetToken, $OutDirToken, $passwordArg)
    }

    return ('"{0}" "{1}" extract "{2}" --out-dir "{3}"{4} --pause' -f $Launcher.AppPath, $Launcher.ScriptPath, $TargetToken, $OutDirToken, $passwordArg)
}

function Set-ContextMenuParent {
    param(
        [string]$KeyPath,
        [string]$MenuLabel,
        [string]$IconValue,
        [string]$SubCommandsKey
    )

    $null = New-Item -Path $KeyPath -Force
    Set-Item -Path $KeyPath -Value $MenuLabel
    Set-ItemProperty -Path $KeyPath -Name "MUIVerb" -Value $MenuLabel
    Set-ItemProperty -Path $KeyPath -Name "Icon" -Value $IconValue
    Set-ItemProperty -Path $KeyPath -Name "ExtendedSubCommandsKey" -Value $SubCommandsKey
    Remove-ItemProperty -Path $KeyPath -Name "SubCommands" -ErrorAction SilentlyContinue
    $localShellKey = Join-Path $KeyPath "shell"
    if (Test-Path -LiteralPath $localShellKey) {
        Remove-Item -LiteralPath $localShellKey -Recurse -Force
    }
}

function Set-ContextMenuCommand {
    param(
        [string]$ParentKeyPath,
        [string]$CommandName,
        [string]$MenuLabel,
        [string]$CommandLine,
        [string]$IconValue
    )

    $keyPath = Join-Path (Join-Path $ParentKeyPath "shell") $CommandName
    $null = New-Item -Path $keyPath -Force
    Set-Item -Path $keyPath -Value $MenuLabel
    Set-ItemProperty -Path $keyPath -Name "MUIVerb" -Value $MenuLabel
    Set-ItemProperty -Path $keyPath -Name "Icon" -Value $IconValue
    $commandKey = Join-Path $keyPath "command"
    $null = New-Item -Path $commandKey -Force
    Set-Item -Path $commandKey -Value $CommandLine
}

function Get-DefaultMenuText {
    param([string]$RepoRoot)

    $configPath = Join-Path $RepoRoot "packrelic_config.json"
    if (-not (Test-Path -LiteralPath $configPath)) {
        return "PackRelic"
    }

    try {
        $payload = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
        $language = [string]$payload.cli.language
        if ($language.Trim().ToLower().StartsWith("zh")) {
            return New-ChineseMenuText
        }
    } catch {
    }
    return "PackRelic"
}

function New-ChineseMenuText {
    return -join @(
        [char]0x667A,
        [char]0x80FD,
        [char]0x89E3,
        [char]0x538B
    )
}

function New-ChineseText {
    param([int[]]$CodePoints)

    return -join ($CodePoints | ForEach-Object { [char]$_ })
}

function Get-SubMenuTexts {
    param([string]$MenuText)

    if ($MenuText -eq (New-ChineseMenuText)) {
        return @{
            Prompt = New-ChineseText @(0x4EA4, 0x4E92, 0x8F93, 0x5165, 0x5BC6, 0x7801, 0x89E3, 0x538B)
            Direct = New-ChineseText @(0x76F4, 0x63A5, 0x89E3, 0x538B)
        }
    }
    return @{
        Prompt = "Extract with password prompt"
        Direct = "Extract directly"
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$launcher = Resolve-Launcher -RepoRoot $repoRoot -PreferredAppPath $AppPath -PreferredPythonPath $PythonPath
$resolvedIconPath = if ($IconPath) { (Resolve-Path -LiteralPath $IconPath).Path } else { $launcher.IconPath }
$resolvedMenuText = if ($MenuText) { $MenuText } else { Get-DefaultMenuText -RepoRoot $repoRoot }

$folderKey = "HKCU:\Software\Classes\Directory\shell\PackRelic"
$backgroundKey = "HKCU:\Software\Classes\Directory\Background\shell\PackRelic"
$folderSubCommandsName = "PackRelic.FolderContextMenu"
$backgroundSubCommandsName = "PackRelic.BackgroundContextMenu"
$folderSubCommandsKey = "HKCU:\Software\Classes\$folderSubCommandsName"
$backgroundSubCommandsKey = "HKCU:\Software\Classes\$backgroundSubCommandsName"
$subMenuTexts = Get-SubMenuTexts -MenuText $resolvedMenuText

$folderPromptCommand = New-CommandString -Launcher $launcher -TargetToken "%1" -OutDirToken "%1" -PromptPasswords $true
$folderDirectCommand = New-CommandString -Launcher $launcher -TargetToken "%1" -OutDirToken "%1" -PromptPasswords $false
$backgroundPromptCommand = New-CommandString -Launcher $launcher -TargetToken "%V" -OutDirToken "%V" -PromptPasswords $true
$backgroundDirectCommand = New-CommandString -Launcher $launcher -TargetToken "%V" -OutDirToken "%V" -PromptPasswords $false

Set-ContextMenuParent -KeyPath $folderKey -MenuLabel $resolvedMenuText -IconValue $resolvedIconPath -SubCommandsKey $folderSubCommandsName
Set-ContextMenuCommand -ParentKeyPath $folderSubCommandsKey -CommandName "PromptPassword" -MenuLabel $subMenuTexts.Prompt -CommandLine $folderPromptCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $folderSubCommandsKey -CommandName "DirectExtract" -MenuLabel $subMenuTexts.Direct -CommandLine $folderDirectCommand -IconValue $resolvedIconPath
Set-ContextMenuParent -KeyPath $backgroundKey -MenuLabel $resolvedMenuText -IconValue $resolvedIconPath -SubCommandsKey $backgroundSubCommandsName
Set-ContextMenuCommand -ParentKeyPath $backgroundSubCommandsKey -CommandName "PromptPassword" -MenuLabel $subMenuTexts.Prompt -CommandLine $backgroundPromptCommand -IconValue $resolvedIconPath
Set-ContextMenuCommand -ParentKeyPath $backgroundSubCommandsKey -CommandName "DirectExtract" -MenuLabel $subMenuTexts.Direct -CommandLine $backgroundDirectCommand -IconValue $resolvedIconPath

Write-Host "Context menu registration completed." -ForegroundColor Green
Write-Host "Folder menu key:" $folderKey
Write-Host "Directory background key:" $backgroundKey
Write-Host "Folder submenu key:" $folderSubCommandsKey
Write-Host "Directory background submenu key:" $backgroundSubCommandsKey
Write-Host "Launch mode:" $launcher.Mode
if ($launcher.Mode -eq "app") {
    Write-Host "App path:" $launcher.AppPath
} else {
    Write-Host "Python path:" $launcher.AppPath
    Write-Host "Script path:" $launcher.ScriptPath
}
Write-Host ""
Write-Host ('You can now right-click a folder or directory background and choose "{0}" -> "{1}" or "{2}".' -f $resolvedMenuText, $subMenuTexts.Prompt, $subMenuTexts.Direct)
