[CmdletBinding()]
param(
    [string]$DatasetDir = "repair_training\datasets",
    [Alias("Input")]
    [string[]]$InputPath = @(),
    [string]$ModelRoot = "repair_training\models",
    [string]$Output = "repair_training\datasets\ltr_data_quality_report.json",
    [switch]$Markdown,
    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "repair training scripts are Windows-only"
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $Python)) {
    $Python = "python"
}
$env:PYTHONPATH = "$RepoRoot"

function Expand-TrainingList {
    param([string[]]$Items)
    $output = @()
    foreach ($item in $Items) {
        foreach ($part in "$item".Split(",")) {
            $value = $part.Trim()
            if ($value) {
                $output += $value
            }
        }
    }
    return $output
}

$ArgsList = @(
    "repair_training\report_ltr_data.py",
    "--dataset-dir", $DatasetDir,
    "--model-root", $ModelRoot,
    "--output", $Output
)
foreach ($item in (Expand-TrainingList $InputPath)) {
    if ($item) {
        $ArgsList += @("--input", $item)
    }
}
if ($Markdown) {
    $ArgsList += "--markdown"
}
if ($ExtraArgs.Count -gt 0) {
    $ArgsList += $ExtraArgs
}

Push-Location $RepoRoot
try {
    & $Python @ArgsList
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
