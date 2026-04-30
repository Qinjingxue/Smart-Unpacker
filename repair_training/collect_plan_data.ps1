[CmdletBinding()]
param(
    [string]$MaterialRoot = "repair_training\material",
    [string]$Manifest = "",
    [string]$SuccessOutput = ".sunpack\datasets\repair_plan_ltr_success.jsonl",
    [string]$FailureOutput = ".sunpack\datasets\repair_plan_ltr_failure.jsonl",
    [int]$MaxRounds = 3,
    [int]$MaxCandidatesPerRound = 10,
    [double]$CaseTimeoutSeconds = 45.0,
    [string]$Formats = "",
    [string]$Sample = "",
    [switch]$Append,
    [switch]$NoPretty,
    [switch]$Progress,
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
    "repair_training\collect_repair_plan_data.py",
    "--success-output", $SuccessOutput,
    "--failure-output", $FailureOutput,
    "--max-rounds", "$MaxRounds",
    "--max-candidates-per-round", "$MaxCandidatesPerRound",
    "--case-timeout-seconds", "$CaseTimeoutSeconds"
)

if ($Manifest) {
    $argsList += @("--manifest", $Manifest)
} else {
    $argsList += @("--material-root", $MaterialRoot)
}
if ($Formats) {
    $argsList += @("--formats", $Formats)
}
if ($Sample) {
    $argsList += @("--sample", $Sample)
}
if ($Append) {
    $argsList += "--append"
}
if ($NoPretty) {
    $argsList += "--no-pretty"
}
if ($Progress) {
    $argsList += "--progress"
}
if ($ExtraArgs.Length -gt 0) {
    $argsList += $ExtraArgs
}

Write-Host "==> Collecting repair plan training data" -ForegroundColor Cyan
Write-Host ("    Python: " + $python) -ForegroundColor DarkGray
if ($Manifest) {
    Write-Host ("    Manifest: " + $Manifest) -ForegroundColor DarkGray
} else {
    Write-Host ("    MaterialRoot: " + $MaterialRoot) -ForegroundColor DarkGray
}
& $python $argsList
if ($LASTEXITCODE -ne 0) {
    throw "repair plan data collection failed (exit code $LASTEXITCODE)"
}

