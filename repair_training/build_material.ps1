[CmdletBinding()]
param(
    [string]$MaterialRoot = "repair_training\material",
    [int]$PerSample = 50,
    [string]$Seed = "random",
    [string]$Formats = "",
    [string]$Sample = "",
    [switch]$NoPretty,
    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot
$env:PYTHONPATH = $repoRoot

function Get-TrainingPython {
    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPython) {
        return $venvPython
    }
    foreach ($candidate in @("python", "py")) {
        try {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {
        }
    }
    throw "Python interpreter not found. Run scripts\setup_windows_dev.ps1 first or add Python to PATH."
}

$python = Get-TrainingPython
$argsList = @(
    "repair_training\build_repair_plan_corpus.py",
    "--material-root", $MaterialRoot,
    "--per-sample", "$PerSample",
    "--seed", $Seed
)

if ($Formats) {
    $argsList += @("--formats", $Formats)
}
if ($Sample) {
    $argsList += @("--sample", $Sample)
}
if ($NoPretty) {
    $argsList += "--no-pretty"
}
if ($ExtraArgs.Length -gt 0) {
    $argsList += $ExtraArgs
}

Write-Host "==> Building repair training damaged material" -ForegroundColor Cyan
Write-Host ("    Python: " + $python) -ForegroundColor DarkGray
Write-Host ("    MaterialRoot: " + $MaterialRoot) -ForegroundColor DarkGray
& $python $argsList
if ($LASTEXITCODE -ne 0) {
    throw "repair training material build failed (exit code $LASTEXITCODE)"
}

