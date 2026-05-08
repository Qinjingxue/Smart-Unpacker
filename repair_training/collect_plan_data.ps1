[CmdletBinding()]
param(
    [string]$MaterialRoot = "repair_training\material",
    [string]$Manifest = "",
    [string]$SuccessOutput = "repair_training\datasets\repair_plan_ltr_success.jsonl",
    [string]$FailureOutput = "repair_training\datasets\repair_plan_ltr_failure.jsonl",
    [string]$SummaryOutput = "",
    [string]$Workspace = ".sunpack\repair-plan-workspace",
    [int]$CollectorShard = -1,
    [int]$CollectorWorkers = 1,
    [ValidateSet("process_per_sample", "worker_pool", "inprocess")]
    [string]$SampleExecutionMode = "worker_pool",
    [int]$SampleWorkerCount = 0,
    [int]$MaxRounds = 8,
    [int]$MaxCandidatesPerRound = 10,
    [ValidateSet("greedy", "greedy_current_selector", "beam", "counterfactual")]
    [string]$RolloutMode = "beam",
    [int]$BeamSize = 8,
    [int]$BranchTopK = 5,
    [int]$CounterfactualExtra = 2,
    [int]$MaxTotalStatesPerSample = 80,
    [double]$FutureLabelDiscount = 0.8,
    [ValidateSet("lazy", "eager")]
    [string]$ProposalMode = "lazy",
    [int]$MaterializeTopKPerRound = 10,
    [switch]$MaterializeSelectedOnly,
    [switch]$IncludeUnmaterializedLabels,
    [double]$CaseTimeoutSeconds = 45.0,
    [double]$StreamLargeSizeMb = 0,
    [double]$StreamLargeCaseTimeoutSeconds = 0,
    [int]$StreamLargeMaxCandidatesPerRound = 0,
    [switch]$SkipLargeStreamSamples,
    [double]$TotalTimeoutSeconds = 0,
    [double]$IdleTimeoutSeconds = 0,
    [double]$HeartbeatSeconds = 5.0,
    [string]$DebugEvents = "",
    [string]$Formats = "",
    [string]$Sample = "",
    [int]$Limit = 0,
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
    "--workspace", $Workspace,
    "--collector-shard", "$CollectorShard",
    "--collector-workers", "$CollectorWorkers",
    "--sample-execution-mode", $SampleExecutionMode,
    "--sample-worker-count", "$SampleWorkerCount",
    "--max-rounds", "$MaxRounds",
    "--max-candidates-per-round", "$MaxCandidatesPerRound",
    "--rollout-mode", $RolloutMode,
    "--beam-size", "$BeamSize",
    "--branch-top-k", "$BranchTopK",
    "--counterfactual-extra", "$CounterfactualExtra",
    "--max-total-states-per-sample", "$MaxTotalStatesPerSample",
    "--future-label-discount", "$FutureLabelDiscount",
    "--proposal-mode", $ProposalMode,
    "--materialize-top-k-per-round", "$MaterializeTopKPerRound",
    "--case-timeout-seconds", "$CaseTimeoutSeconds",
    "--stream-large-size-mb", "$StreamLargeSizeMb",
    "--stream-large-case-timeout-seconds", "$StreamLargeCaseTimeoutSeconds",
    "--stream-large-max-candidates-per-round", "$StreamLargeMaxCandidatesPerRound",
    "--heartbeat-seconds", "$HeartbeatSeconds"
)
if ($TotalTimeoutSeconds -gt 0) {
    $argsList += @("--total-timeout-seconds", "$TotalTimeoutSeconds")
}
if ($SummaryOutput) {
    $argsList += @("--summary-output", $SummaryOutput)
}
if ($IdleTimeoutSeconds -gt 0) {
    $argsList += @("--idle-timeout-seconds", "$IdleTimeoutSeconds")
}
if ($DebugEvents) {
    $argsList += @("--debug-events", $DebugEvents)
}
if ($SkipLargeStreamSamples) {
    $argsList += "--skip-large-stream-samples"
}
if ($MaterializeSelectedOnly) {
    $argsList += "--materialize-selected-only"
}
if ($IncludeUnmaterializedLabels) {
    $argsList += "--no-skip-unmaterialized-labels"
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
