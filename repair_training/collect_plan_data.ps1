[CmdletBinding()]
param(
    [string]$MaterialRoot = "repair_training\material",
    [string]$Manifest = "",
    [string]$RunDir = "",
    [string]$RunName = "zip_runtime_graph",
    [string]$SuccessOutput = "",
    [string]$FailureOutput = "",
    [string]$SummaryOutput = "",
    [string]$Workspace = "",
    [int]$CollectorShard = -1,
    [int]$CollectorWorkers = 6,
    [ValidateSet("process_per_sample", "worker_pool", "inprocess")]
    [string]$SampleExecutionMode = "worker_pool",
    [int]$SampleWorkerCount = 0,
    [int]$MaxRounds = 6,
    [int]$MaxCandidatesPerRound = 10,
    [ValidateSet("greedy", "greedy_current_selector", "beam", "counterfactual")]
    [string]$RolloutMode = "beam",
    [int]$BeamSize = 8,
    [int]$BranchTopK = 5,
    [int]$CounterfactualExtra = 2,
    [int]$MaxTotalStatesPerSample = 20,
    [double]$FutureLabelDiscount = 0.8,
    [ValidateSet("lazy", "eager")]
    [string]$ProposalMode = "lazy",
    [int]$MaterializeTopKPerRound = 8,
    [int]$MaxExpensiveMaterializationsPerRound = 3,
    [switch]$MaterializeSelectedOnly,
    [switch]$IncludeUnmaterializedLabels,
    [double]$CaseTimeoutSeconds = 180.0,
    [double]$StreamLargeSizeMb = 0,
    [double]$StreamLargeCaseTimeoutSeconds = 0,
    [int]$StreamLargeMaxCandidatesPerRound = 0,
    [switch]$SkipLargeStreamSamples,
    [double]$TotalTimeoutSeconds = 0,
    [double]$IdleTimeoutSeconds = 0,
    [double]$HeartbeatSeconds = 5.0,
    [string]$DebugEvents = "",
    [switch]$DisableRepairCache,
    [switch]$ProfileMaterializationCandidates,
    [string]$Formats = "zip",
    [string]$Sample = "",
    [int]$Limit = 0,
    [switch]$Append,
    [switch]$KeepTemp,
    [switch]$SkipAnalysisReport,
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
$runtimeWorkers = $CollectorWorkers
if ($SampleWorkerCount -gt 0) {
    $runtimeWorkers = $SampleWorkerCount
}
$runtimeWorkers = [Math]::Max(1, [int]$runtimeWorkers)
$argsList = @(
    "repair_training\collect_runtime_repair_graph.py",
    "--run-name", $RunName,
    "--max-rounds", "$MaxRounds",
    "--max-states", "$MaxTotalStatesPerSample",
    "--branch-top-k", "$BranchTopK",
    "--future-label-discount", "$FutureLabelDiscount",
    "--materialize-top-k", "$MaterializeTopKPerRound",
    "--case-timeout-seconds", "$CaseTimeoutSeconds",
    "--workers", "$runtimeWorkers"
)
if ($RunDir) {
    $argsList += @("--run-dir", $RunDir)
}
if ($SuccessOutput) {
    $argsList += @("--success-output", $SuccessOutput)
}
if ($FailureOutput) {
    $argsList += @("--failure-output", $FailureOutput)
}
if ($SummaryOutput) {
    $argsList += @("--summary-output", $SummaryOutput)
}
if ($Workspace) {
    $argsList += @("--workspace", $Workspace)
}
if ($DebugEvents) {
    $argsList += @("--debug-events-output", $DebugEvents)
}

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
if ($Limit -gt 0) {
    $argsList += @("--limit", "$Limit")
}
if ($Append) {
    $argsList += "--append"
}
if ($KeepTemp) {
    $argsList += "--keep-temp"
}
if ($SkipAnalysisReport) {
    $argsList += "--skip-analysis-report"
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
