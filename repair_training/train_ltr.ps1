[CmdletBinding()]
param(
    [Alias("Input")]
    [string[]]$InputPath = @(),
    [ValidateSet("stable_only", "stable_plus_teacher", "teacher_only_baseline")]
    [string]$FeatureView = "stable_only",
    [ValidateSet("all", "zip", "tar", "tar_gz", "tar_bz2", "tar_xz", "gzip", "bzip2", "xz", "zstd", "7z", "rar")]
    [string]$FormatScope = "all",
    [ValidateSet("immediate", "future", "discounted", "blended", "strategy")]
    [string]$LabelTarget = "strategy",
    [ValidateSet("query", "episode", "source_sample")]
    [string]$SplitBy = "query",
    [switch]$AllFeatureViews,
    [string]$OutputDir = "repair_training\models\baseline_ltr",
    [int]$Seed = 2026,
    [switch]$NoInstallDeps,
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

Push-Location $RepoRoot
try {
    if (-not $NoInstallDeps) {
        & $Python -m pip install -r (Join-Path $RepoRoot "repair_training\requirements-training.txt")
        if ($LASTEXITCODE -ne 0) {
            throw "training dependency installation failed (exit code $LASTEXITCODE)"
        }
    }

    $views = if ($AllFeatureViews) {
        @("stable_only", "stable_plus_teacher", "teacher_only_baseline")
    } else {
        @($FeatureView)
    }

    foreach ($view in $views) {
        $viewOutput = if ($AllFeatureViews) {
            Join-Path $OutputDir $view
        } else {
            $OutputDir
        }
        $ArgsList = @(
            "repair_training\train_ltr.py",
            "--feature-view", $view,
            "--format-scope", $FormatScope,
            "--label-target", $LabelTarget,
            "--split-by", $SplitBy,
            "--output-dir", $viewOutput,
            "--seed", "$Seed"
        )
        foreach ($item in (Expand-TrainingList $InputPath)) {
            if ($item) {
                $ArgsList += @("--input", $item)
            }
        }
        if ($ExtraArgs.Count -gt 0) {
            $ArgsList += $ExtraArgs
        }
        Write-Host "==> Training repair LTR baseline ($view)" -ForegroundColor Cyan
        Write-Host ("    Python: " + $Python) -ForegroundColor DarkGray
        Write-Host ("    OutputDir: " + $viewOutput) -ForegroundColor DarkGray
        & $Python @ArgsList
        if ($LASTEXITCODE -ne 0) {
            throw "LTR training failed for $view (exit code $LASTEXITCODE)"
        }
    }
}
finally {
    Pop-Location
}
