[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [string]$MaterialRoot = "repair_training\material",
    [string]$Formats = "",
    [string[]]$Sample = @(),
    [switch]$RemoveFormatDirectories,
    [switch]$KeepRepairWorkspace
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "repair training scripts are Windows-only"
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$MaterialPath = if ([System.IO.Path]::IsPathRooted($MaterialRoot)) {
    [System.IO.Path]::GetFullPath($MaterialRoot)
} else {
    [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $MaterialRoot))
}

function Test-PathInside {
    param(
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Parent
    )
    $childFull = [System.IO.Path]::GetFullPath($Child).TrimEnd('\')
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\')
    return $childFull.Equals($parentFull, [System.StringComparison]::OrdinalIgnoreCase) -or
        $childFull.StartsWith($parentFull + "\", [System.StringComparison]::OrdinalIgnoreCase)
}

function ConvertTo-NameSet {
    param([string[]]$Values)
    $set = @{}
    foreach ($value in $Values) {
        foreach ($part in "$value".Split(",")) {
            $name = $part.Trim()
            if ($name) {
                $set[$name.ToLowerInvariant()] = $true
            }
        }
    }
    return $set
}

$TrainingRoot = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot "repair_training"))
if (-not (Test-PathInside -Child $MaterialPath -Parent $TrainingRoot)) {
    throw "Refusing to clear material outside repair_training: $MaterialPath"
}

$formatSet = ConvertTo-NameSet @($Formats)
$sampleSet = ConvertTo-NameSet $Sample
$summary = [ordered]@{
    material_root = $MaterialPath
    repair_workspace = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot ".sunpack\repair-plan-workspace"))
    removed = 0
    skipped = 0
    preserved_format_dirs = -not [bool]$RemoveFormatDirectories
    filters = [ordered]@{
        formats = @($formatSet.Keys | Sort-Object)
        samples = @($sampleSet.Keys | Sort-Object)
    }
}

if (-not (Test-Path -LiteralPath $MaterialPath)) {
    New-Item -ItemType Directory -Path $MaterialPath -Force | Out-Null
    $summary.created_material_root = $true
    $summary | ConvertTo-Json -Depth 5
    exit 0
}

$materialResolved = (Resolve-Path -LiteralPath $MaterialPath).Path
if (-not (Test-PathInside -Child $materialResolved -Parent $TrainingRoot)) {
    throw "Refusing to clear resolved material outside repair_training: $materialResolved"
}

$formatDirs = Get-ChildItem -LiteralPath $materialResolved -Directory -Force
foreach ($formatDir in $formatDirs) {
    $formatName = $formatDir.Name.ToLowerInvariant()
    if ($formatSet.Count -gt 0 -and -not $formatSet.ContainsKey($formatName)) {
        $summary.skipped++
        continue
    }

    if ($RemoveFormatDirectories -and $sampleSet.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess($formatDir.FullName, "remove format material directory")) {
            Remove-Item -LiteralPath $formatDir.FullName -Recurse -Force
            $summary.removed++
        }
        continue
    }

    $children = Get-ChildItem -LiteralPath $formatDir.FullName -Force
    foreach ($child in $children) {
        if ($child.Name -in @(".gitkeep", ".gitignore")) {
            $summary.skipped++
            continue
        }
        if ($sampleSet.Count -gt 0) {
            $sampleKey = $child.BaseName.ToLowerInvariant()
            if ($child.PSIsContainer) {
                $sampleKey = $child.Name.ToLowerInvariant()
            }
            if (-not $sampleSet.ContainsKey($sampleKey)) {
                $summary.skipped++
                continue
            }
        }
        if ($PSCmdlet.ShouldProcess($child.FullName, "remove material sample artifact")) {
            Remove-Item -LiteralPath $child.FullName -Recurse -Force
            $summary.removed++
        }
    }
}

$rootFiles = Get-ChildItem -LiteralPath $materialResolved -File -Force
foreach ($file in $rootFiles) {
    if ($file.Name -in @(".gitkeep", ".gitignore")) {
        $summary.skipped++
        continue
    }
    if ($PSCmdlet.ShouldProcess($file.FullName, "remove root material file")) {
        Remove-Item -LiteralPath $file.FullName -Force
        $summary.removed++
    }
}

if (-not $KeepRepairWorkspace) {
    $workspace = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot ".sunpack\repair-plan-workspace"))
    $sunpackRoot = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot ".sunpack"))
    if ((Test-Path -LiteralPath $workspace) -and (Test-PathInside -Child $workspace -Parent $sunpackRoot)) {
        if ($PSCmdlet.ShouldProcess($workspace, "remove repair plan workspace")) {
            Remove-Item -LiteralPath $workspace -Recurse -Force
            $summary.removed++
        }
    }
}

$summary | ConvertTo-Json -Depth 5
