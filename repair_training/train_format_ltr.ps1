[CmdletBinding()]
param(
    [Alias("Input")]
    [string[]]$InputPath = @(),
    [string]$OutputDir = "repair_training\models\by_format",
    [string]$Formats = "",
    [string]$FeatureViews = "",
    [int]$Seed = 2026,
    [int]$MinTrainableQueries = 30,
    [int]$MinCandidatesPerQuery = 2,
    [switch]$IncludeSingleCandidateQueries,
    [switch]$NoInstallDeps
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
            if ($value) { $output += $value }
        }
    }
    return $output
}

Push-Location $RepoRoot
try {
    if (-not $NoInstallDeps) {
        & $Python -m pip install -r (Join-Path $RepoRoot "repair_training\requirements-training.txt")
        if ($LASTEXITCODE -ne 0) {
            throw "training dependency installation failed (exit code $LASTEXITCODE)"
        }
    }

    $ArgsList = @(
        "repair_training\train_format_ltr.py",
        "--output-dir", $OutputDir,
        "--seed", "$Seed",
        "--min-trainable-queries", "$MinTrainableQueries",
        "--min-candidates-per-query", "$MinCandidatesPerQuery"
    )
    foreach ($item in (Expand-TrainingList $InputPath)) {
        if ($item) { $ArgsList += @("--input", $item) }
    }
    if ($Formats) { $ArgsList += @("--formats", $Formats) }
    if ($FeatureViews) { $ArgsList += @("--feature-views", $FeatureViews) }
    if ($IncludeSingleCandidateQueries) { $ArgsList += "--include-single-candidate-queries" }

    Write-Host "==> Training repair LTR models by format" -ForegroundColor Cyan
    Write-Host ("    Python: " + $Python) -ForegroundColor DarkGray
    Write-Host ("    OutputDir: " + $OutputDir) -ForegroundColor DarkGray
    & $Python @ArgsList
    if ($LASTEXITCODE -ne 0) {
        throw "format LTR training failed (exit code $LASTEXITCODE)"
    }
}
finally {
    Pop-Location
}
