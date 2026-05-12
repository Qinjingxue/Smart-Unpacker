<#
.SYNOPSIS
    Full offline RL training pipeline — source material → corrupted archives → rollout data → model.
.DESCRIPTION
    Automates the complete RL training workflow:
      1. Clean previous artifacts (material, datasets, models, workspace)
      2. Derive corrupted archives from source material
      3. Build corruption cases
      4. Collect repair-plan rollout data via sunpack (parallel)
      5. Train offline RL Q-value model (LightGBM)
      6. Print results

    Uses .venv\Scripts\python.exe automatically.
    All intermediate artifacts are cleaned before starting.
.PARAMETER SourceRoot
    Source material directory. Default: repair_training\source_material
.PARAMETER Formats
    Archive formats to process (comma-separated). Default: zip
.PARAMETER ArchivesPerSample
    Number of corrupted archives to derive per source sample. Default: 3
.PARAMETER PerSample
    Number of corruption cases per sample for corpus building. Default: 5
.PARAMETER MaxRounds
    Max repair rollout rounds during data collection. Default: 2
.PARAMETER MaxCandidatesPerRound
    Max candidates per repair round. Default: 6
.PARAMETER CollectWorkers
    Parallel workers for data collection. Default: 8
.PARAMETER MaxActiveCollectors
    Max concurrent collectors. Default: 4
.PARAMETER CaseTimeoutSeconds
    Timeout per corruption case (seconds). Default: 30
.PARAMETER Seed
    Random seed for reproducibility. Default: 2026
.PARAMETER NEstimators
    LightGBM n_estimators. Default: 300
.PARAMETER LearningRate
    LightGBM learning_rate. Default: 0.04
.PARAMETER NumLeaves
    LightGBM num_leaves. Default: 31
.PARAMETER SkipCollect
    Skip the data collection step (use existing datasets).
.PARAMETER SkipTrain
    Skip the training step (only generate datasets).
.EXAMPLE
    .\repair_training\train_offline_rl_full.ps1
.EXAMPLE
    .\repair_training\train_offline_rl_full.ps1 -ArchivesPerSample 5 -MaxRounds 3 -NEstimators 500
.EXAMPLE
    .\repair_training\train_offline_rl_full.ps1 -SkipCollect
#>

[CmdletBinding()]
param(
    [string]$SourceRoot = "repair_training\source_material",
    [string]$Format = "zip",
    [string]$Formats = "",
    [int]$ArchivesPerSample = 3,
    [int]$PerSample = 5,
    [int]$MaxRounds = 2,
    [int]$MaxCandidatesPerRound = 6,
    [int]$CollectWorkers = 8,
    [int]$MaxActiveCollectors = 4,
    [double]$CaseTimeoutSeconds = 30,
    [int]$Seed = 2026,
    [int]$NEstimators = 300,
    [double]$LearningRate = 0.04,
    [int]$NumLeaves = 31,
    [switch]$SkipCollect,
    [switch]$SkipTrain
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "This script is Windows-only"
}

# ── Paths ──────────────────────────────────────────────────────────────────
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw ".venv Python not found at: $Python. Run scripts\setup_windows_dev.ps1 first."
}

$MaterialRoot = Join-Path $RepoRoot "repair_training\material"
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
if (-not $Formats) { $Formats = $Format }
$RunDir = Join-Path $RepoRoot ("repair_training\runs\{0}\{1}_full_pipeline" -f $Format, $stamp)
$DatasetDir = Join-Path $RunDir "datasets"
$ModelDir = Join-Path $RunDir ("models\{0}_runtime_policy" -f $Format)
$ConfigPath = Join-Path $RepoRoot "repair_training\archive_derivation_config.json"
$Workspace = Join-Path $RunDir "tmp\workspace"
$CorpusDir = Join-Path $RepoRoot "repair_training\tmp\corpus"

$SuccessData = Join-Path $DatasetDir "runtime_graph_success.jsonl"
$FailureData = Join-Path $DatasetDir "runtime_graph_failure.jsonl"
$ParallelSummary = Join-Path $DatasetDir "runtime_graph_summary.json"

$DeriveScript = Join-Path $RepoRoot "repair_training\derive_archives.py"
$BuildScript = "repair_training.formats.$Format.build_material"
$CollectScript = Join-Path $RepoRoot "repair_training\collect_plan_data_parallel.ps1"
$TrainScript = "repair_training.core.train_policy"

$env:PYTHONPATH = "$RepoRoot"

# ── Helpers ────────────────────────────────────────────────────────────────
function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor Cyan
}

function Write-SubStep {
    param([string]$Message)
    Write-Host "  -> $Message" -ForegroundColor Yellow
}

function Write-OK {
    param([string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Magenta
}

function Remove-IfExists {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path -LiteralPath $Path)) {
            return $true
        }
    }
    return $false
}

function Invoke-Python {
    param([string]$Script, [string[]]$Arguments)
    $fullScript = if ([System.IO.Path]::IsPathRooted($Script)) { $Script } else { Join-Path $RepoRoot $Script }
    Write-Host "    python $fullScript $($Arguments -join ' ')" -ForegroundColor DarkGray
    & $Python $fullScript @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python script failed (exit code $LASTEXITCODE): $Script"
    }
}

# ── Step 0: Clean Everything ───────────────────────────────────────────────
Write-Step "Step 0: Cleaning previous artifacts"

Write-SubStep "Cleaning material directory"
$materialRemoved = 0
if (Test-Path -LiteralPath $MaterialRoot) {
    $formatDirs = Get-ChildItem -LiteralPath $MaterialRoot -Directory -Force -ErrorAction SilentlyContinue
    foreach ($dir in $formatDirs) {
        $children = Get-ChildItem -LiteralPath $dir.FullName -Force -ErrorAction SilentlyContinue
        foreach ($child in $children) {
            if ($child.Name -in @(".gitkeep", ".gitignore")) { continue }
            Remove-Item -LiteralPath $child.FullName -Recurse -Force -ErrorAction SilentlyContinue
            $materialRemoved++
        }
    }
}
Write-OK "Removed $materialRemoved material items"

Write-SubStep "Cleaning RL model directory"
if (Remove-IfExists $ModelDir) { Write-OK "Removed model directory" } else { Write-OK "Model directory already clean" }
New-Item -ItemType Directory -Path $ModelDir -Force | Out-Null

Write-SubStep "Cleaning old RL datasets"
$dataRemoved = 0
foreach ($f in @($SuccessData, $FailureData, $ParallelSummary)) {
    if (Remove-IfExists $f) { $dataRemoved++ }
}
Write-OK "Removed $dataRemoved old dataset files"

Write-SubStep "Cleaning workspace"
if (Remove-IfExists $Workspace) { Write-OK "Removed repair workspace" } else { Write-OK "Workspace already clean" }

Write-SubStep "Cleaning corpus"
if (Remove-IfExists $CorpusDir) { Write-OK "Removed corpus directory" } else { Write-OK "Corpus already clean" }

Write-Host ""
Write-Host "  Python: $Python" -ForegroundColor DarkGray
Write-Host "  Sources: $SourceRoot" -ForegroundColor DarkGray
Write-Host "  Formats: $Formats" -ForegroundColor DarkGray
Write-Host "  Archives/sample: $ArchivesPerSample | Cases/sample: $PerSample" -ForegroundColor DarkGray
Write-Host "  Max rounds: $MaxRounds | Candidates/round: $MaxCandidatesPerRound" -ForegroundColor DarkGray
Write-Host "  Workers: $CollectWorkers | Active: $MaxActiveCollectors | Timeout: ${CaseTimeoutSeconds}s" -ForegroundColor DarkGray
Write-Host "  Seed: $Seed | Trees: $NEstimators | LR: $LearningRate | Leaves: $NumLeaves" -ForegroundColor DarkGray

# ── Step 1: Derive Corrupted Archives ──────────────────────────────────────
Write-Step "Step 1: Deriving corrupted archives from source material"

Invoke-Python -Script $DeriveScript -Arguments @(
    "--source-root", (Join-Path $RepoRoot $SourceRoot),
    "--material-root", $MaterialRoot,
    "--config", $ConfigPath,
    "--formats", $Formats,
    "--archives-per-sample", "$ArchivesPerSample",
    "--seed", "$Seed"
)
Write-OK "Archive derivation complete"

# ── Step 2: Build Corruption Corpus ────────────────────────────────────────
Write-Step "Step 2: Building corruption cases"

    Write-Host "    python -m $BuildScript --material-root $MaterialRoot --per-sample $PerSample --formats $Formats --seed $Seed" -ForegroundColor DarkGray
    & $Python -m $BuildScript "--material-root" $MaterialRoot "--per-sample" "$PerSample" "--formats" $Formats "--seed" "$Seed"
    if ($LASTEXITCODE -ne 0) {
        throw "Python module failed (exit code $LASTEXITCODE): $BuildScript"
    }
Write-OK "Corpus build complete"

# ── Step 3: Collect Repair-Plan Rollout Data ───────────────────────────────
if (-not $SkipCollect) {
    Write-Step "Step 3: Collecting repair-plan rollout data (parallel sunpack)"

    $collectArgs = @{
        Format = $Format
        MaterialRoot = "repair_training\material"
        RunDir = $RunDir
        SuccessOutput = $SuccessData
        FailureOutput = $FailureData
        ParallelSummaryOutput = $ParallelSummary
        Formats = $Formats
        MaxRounds = $MaxRounds
        MaxCandidatesPerRound = $MaxCandidatesPerRound
        RolloutMode = "greedy"
        CaseTimeoutSeconds = $CaseTimeoutSeconds
        CollectWorkers = $CollectWorkers
        MaxActiveCollectors = $MaxActiveCollectors
        FutureLabelDiscount = 0.8
        ProposalMode = "lazy"
        MaterializeTopKPerRound = 4
        MaxTotalStatesPerSample = 6
    }

    Push-Location $RepoRoot
    try {
        & $CollectScript @collectArgs
        if ($LASTEXITCODE -ne 0) {
            throw "Data collection failed (exit code $LASTEXITCODE)"
        }
    }
    finally {
        Pop-Location
    }
    Write-OK "Data collection complete"
}
else {
    Write-Step "Step 3: Skipping data collection (--SkipCollect)"
}

# ── Step 4: Count Data ─────────────────────────────────────────────────────
Write-Step "Step 4: Checking dataset"

# Use Python for fast line counting (much faster than Get-Content for large JSONL)
$countScript = @"
import json
sc = 0; fc = 0; rc = 0
for path, counter in [("$($SuccessData -replace '\\','/')", 0), ("$($FailureData -replace '\\','/')", 1)]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip():
                    continue
                if counter == 0:
                    sc += 1
                    if isinstance(json.loads(line).get('rl'), dict):
                        rc += 1
                else:
                    fc += 1
                    if isinstance(json.loads(line).get('rl'), dict):
                        rc += 1
    except FileNotFoundError:
        pass
print(sc, fc, rc)
"@
$counts = & $Python -c $countScript
$parts = $counts -split '\s+'
$successRows = [int]$parts[0]
$failureRows = [int]$parts[1]
$rlRows = [int]$parts[2]

Write-OK "Success rows: $successRows | Failure rows: $failureRows | RL rows: $rlRows"

if ($successRows -eq 0) {
    Write-Warn "No data rows found. Training will likely fail."
}

# ── Step 5: Train Offline RL Model ─────────────────────────────────────────
if (-not $SkipTrain) {
    Write-Step "Step 5: Training offline RL Q-value model"

    Write-Host "    python -m $TrainScript --format $Format --dataset-dir $DatasetDir --output-dir $ModelDir ..." -ForegroundColor DarkGray
    & $Python -m $TrainScript `
        "--format", $Format,
        "--dataset-dir", $DatasetDir,
        "--output-dir", $ModelDir,
        "--format-scope", $Formats,
        "--target", "root_transition_return_v1",
        "--feature-view", "runtime_minimal_native_validation",
        "--sample-weight-mode", "root_transition_v1",
        "--seed", "$Seed",
        "--n-estimators", "$NEstimators",
        "--learning-rate", "$LearningRate",
        "--num-leaves", "$NumLeaves",
        "--min-child-samples", "20"
    if ($LASTEXITCODE -ne 0) {
        throw "Python module failed (exit code $LASTEXITCODE): $TrainScript"
    }
    Write-OK "RL training complete"
}
else {
    Write-Step "Step 5: Skipping training (--SkipTrain)"
}

# ── Step 6: Print Results ──────────────────────────────────────────────────
Write-Step "Step 6: Training Results"

if (Test-Path (Join-Path $ModelDir "training_summary.json")) {
    $summary = Get-Content (Join-Path $ModelDir "training_summary.json") -Encoding UTF8 | ConvertFrom-Json
    $m = $summary.metrics

    Write-Host ""
    Write-Host "  +--------------------------------------------------------------+"
    Write-Host "  |              OFFLINE RL MODEL TRAINING RESULTS               |"
    Write-Host "  +--------------------------------------------------------------+"
    Write-Host ("  |  Rows:       {0,6}  (train: {1,5} / eval: {2,4})              |" -f $summary.row_count, $summary.train_row_count, $summary.eval_row_count)
    Write-Host ("  |  Features:   {0,6}  (view: {1,-20})        |" -f $summary.feature_count, $summary.feature_view)
    Write-Host ("  |  Target:     {0,-20}  Split: {1,-14} |" -f $summary.target, $summary.split_by)
    Write-Host "  +--------------------------------------------------------------+"
    $r2Label = "R" + [char]0x00B2 + " Score"
    Write-Host ("  |  {0,-14} {1,8:F4}                                  |" -f $r2Label, $m.r2)
    Write-Host ("  |  MAE:          {0,8:F4}                                  |" -f $m.mae)
    Write-Host ("  |  RMSE:         {0,8:F4}                                  |" -f $m.rmse)
    Write-Host "  +--------------------------------------------------------------+"
    Write-Host ("  |  Eval Queries:     {0,4}                                    |" -f $m.eval_query_count)
    Write-Host ("  |  Top-1 Return:     {0,8:F4}                                |" -f $m.top1_future_return_mean)
    Write-Host ("  |  Oracle Return:    {0,8:F4}                                |" -f $m.oracle_future_return_mean)
    Write-Host ("  |  Regret (mean):    {0,8:F6}                              |" -f $m.future_return_regret_mean)
    Write-Host ("  |  Regret (P90):     {0,8:F6}                              |" -f $m.future_return_regret_p90)
    Write-Host "  +--------------------------------------------------------------+"
    Write-Host ""

    Write-OK "Model saved to: $ModelDir"
    Write-Host "     model.txt              ($('{0:N0}' -f (Get-Item (Join-Path $ModelDir 'model.txt')).Length) bytes)"
    Write-Host "     vectorizer.joblib      ($('{0:N0}' -f (Get-Item (Join-Path $ModelDir 'vectorizer.joblib')).Length) bytes)"
    Write-Host "     feature_names.json     ($('{0:N0}' -f (Get-Item (Join-Path $ModelDir 'feature_names.json')).Length) bytes)"
    Write-Host "     training_summary.json"
    Write-Host "     metrics.json"
    Write-Host "     predictions.jsonl"
}
else {
    Write-Warn "training_summary.json not found. Training may have failed."
}

Write-Host ""
Write-Host ("=" * 72) -ForegroundColor Cyan
Write-Host "  Pipeline finished." -ForegroundColor Green
Write-Host ("=" * 72) -ForegroundColor Cyan
