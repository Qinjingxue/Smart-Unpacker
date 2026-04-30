[CmdletBinding()]
param(
    [string]$SourceRoot = "repair_training\source_material",
    [string]$MaterialRoot = "repair_training\material",
    [string]$DatasetDir = "repair_training\datasets",
    [string]$ModelRoot = "repair_training\models\by_format_pipeline",
    [string]$UnifiedModelRoot = "repair_training\models\baseline_ltr_pipeline",
    [string]$Formats = "",
    [string[]]$Sample = @(),
    [int]$ArchivesPerSample = 5,
    [int]$PerSample = 10,
    [string]$Seed = "random",
    [int]$MaxRounds = 2,
    [int]$MaxCandidatesPerRound = 6,
    [ValidateSet("greedy", "beam", "counterfactual")]
    [string]$RolloutMode = "greedy",
    [int]$BeamSize = 1,
    [int]$BranchTopK = 2,
    [int]$CounterfactualExtra = 2,
    [int]$MaxTotalStatesPerSample = 6,
    [double]$FutureLabelDiscount = 0.8,
    [ValidateSet("lazy", "eager")]
    [string]$ProposalMode = "lazy",
    [int]$MaterializeTopKPerRound = 4,
    [switch]$MaterializeSelectedOnly,
    [double]$CaseTimeoutSeconds = 12.0,
    [double]$StreamLargeSizeMb = 32,
    [double]$StreamLargeCaseTimeoutSeconds = 3,
    [int]$StreamLargeMaxCandidatesPerRound = 1,
    [switch]$SkipLargeStreamSamples,
    [switch]$IncludeLargeStreamSamples,
    [double]$TotalTimeoutSeconds = 0,
    [string]$DebugEvents = "",
    [int]$CollectWorkers = 16,
    [ValidateSet("pool", "static")]
    [string]$CollectScheduling = "pool",
    [int]$CollectQueueBatchSize = 1,
    [int]$MaxActiveCollectors = 6,
    [int]$CollectLaunchDelayMilliseconds = 150,
    [switch]$ZipStrategyDefaults,
    [switch]$DisableParallelCollect,
    [switch]$SkipDerive,
    [switch]$SkipBuild,
    [switch]$SkipCollect,
    [switch]$SkipTrain,
    [ValidateSet("immediate", "future", "discounted", "blended", "strategy", "terminal_recovery_ratio", "discounted_terminal_recovery_ratio", "strategy_recovery_ratio")]
    [string]$LabelTarget = "strategy_recovery_ratio",
    [ValidateSet("query", "episode", "source_sample", "source_profile", "profile_holdout")]
    [string]$SplitBy = "source_sample",
    [bool]$TrainByFormat = $true,
    [switch]$TrainUnifiedBaseline,
    [switch]$NoInstallTrainDeps,
    [switch]$NoPretty
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "repair training scripts are Windows-only"
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$successOutput = Join-Path $DatasetDir "repair_plan_ltr_success_pipeline.jsonl"
$failureOutput = Join-Path $DatasetDir "repair_plan_ltr_failure_pipeline.jsonl"
$reportOutput = Join-Path $DatasetDir "ltr_data_quality_report_pipeline.json"

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
    if ($ZipStrategyDefaults) {
        $Formats = "zip"
        $RolloutMode = "counterfactual"
        $MaxRounds = 3
        $BeamSize = 3
        $BranchTopK = 3
        $CounterfactualExtra = 2
        $MaterializeTopKPerRound = 6
        $MaxTotalStatesPerSample = 10
        $CaseTimeoutSeconds = 20.0
        $MaxActiveCollectors = 4
        $CollectQueueBatchSize = 3
        $SplitBy = "source_sample"
    }
    if (-not $SkipDerive) {
        $deriveArgs = @{
            SourceRoot = $SourceRoot
            MaterialRoot = $MaterialRoot
            ArchivesPerSample = $ArchivesPerSample
            Seed = $Seed
        }
        if ($Formats) { $deriveArgs["Formats"] = $Formats }
        $expandedSamples = Expand-TrainingList $Sample
        if ($expandedSamples.Count -gt 0) { $deriveArgs["Sample"] = $expandedSamples }
        if ($NoPretty) { $deriveArgs["NoPretty"] = $true }
        & (Join-Path $RepoRoot "repair_training\derive_archives.ps1") @deriveArgs
        if ($LASTEXITCODE -ne 0) { throw "derive step failed" }
    }

    if (-not $SkipBuild) {
        $buildArgs = @{
            MaterialRoot = $MaterialRoot
            PerSample = $PerSample
            Seed = $Seed
        }
        if ($Formats) { $buildArgs["Formats"] = $Formats }
        $expandedSamples = Expand-TrainingList $Sample
        if ($expandedSamples.Count -gt 0) { $buildArgs["Sample"] = ($expandedSamples -join ",") }
        if ($NoPretty) { $buildArgs["NoPretty"] = $true }
        & (Join-Path $RepoRoot "repair_training\build_material.ps1") @buildArgs
        if ($LASTEXITCODE -ne 0) { throw "build material step failed" }
    }

    if (-not $SkipCollect) {
        $collectArgs = @{
            MaterialRoot = $MaterialRoot
            SuccessOutput = $successOutput
            FailureOutput = $failureOutput
            MaxRounds = $MaxRounds
            MaxCandidatesPerRound = $MaxCandidatesPerRound
            RolloutMode = $RolloutMode
            BeamSize = $BeamSize
            BranchTopK = $BranchTopK
            CounterfactualExtra = $CounterfactualExtra
            MaxTotalStatesPerSample = $MaxTotalStatesPerSample
            FutureLabelDiscount = $FutureLabelDiscount
            ProposalMode = $ProposalMode
            MaterializeTopKPerRound = $MaterializeTopKPerRound
            CaseTimeoutSeconds = $CaseTimeoutSeconds
            StreamLargeSizeMb = $StreamLargeSizeMb
            StreamLargeCaseTimeoutSeconds = $StreamLargeCaseTimeoutSeconds
            StreamLargeMaxCandidatesPerRound = $StreamLargeMaxCandidatesPerRound
        }
        if ($MaterializeSelectedOnly) { $collectArgs["MaterializeSelectedOnly"] = $true }
        if ($SkipLargeStreamSamples -or -not $IncludeLargeStreamSamples) { $collectArgs["SkipLargeStreamSamples"] = $true }
        if ($TotalTimeoutSeconds -gt 0) { $collectArgs["TotalTimeoutSeconds"] = $TotalTimeoutSeconds }
        if ($DebugEvents) { $collectArgs["DebugEvents"] = $DebugEvents }
        if ($Formats) { $collectArgs["Formats"] = $Formats }
        $expandedSamples = Expand-TrainingList $Sample
        if ($expandedSamples.Count -gt 0) { $collectArgs["Sample"] = ($expandedSamples -join ",") }
        if ($NoPretty) { $collectArgs["NoPretty"] = $true }
        if (-not $DisableParallelCollect -and $CollectWorkers -gt 1) {
            $collectArgs["CollectWorkers"] = $CollectWorkers
            $collectArgs["Scheduling"] = $CollectScheduling
            $collectArgs["QueueBatchSize"] = $CollectQueueBatchSize
            $collectArgs["MaxActiveCollectors"] = $MaxActiveCollectors
            $collectArgs["LaunchDelayMilliseconds"] = $CollectLaunchDelayMilliseconds
            $collectArgs["ParallelSummaryOutput"] = (Join-Path $DatasetDir "collect_parallel_summary.json")
            & (Join-Path $RepoRoot "repair_training\collect_plan_data_parallel.ps1") @collectArgs
        } else {
            & (Join-Path $RepoRoot "repair_training\collect_plan_data.ps1") @collectArgs
        }
        if ($LASTEXITCODE -ne 0) { throw "collect step failed" }
    }

    if (-not $SkipTrain) {
        if ($TrainByFormat) {
            $formatTrainArgs = @{
                OutputDir = $ModelRoot
                InputPath = @($successOutput, $failureOutput)
                LabelTarget = $LabelTarget
                SplitBy = $SplitBy
            }
            if ($Formats) { $formatTrainArgs["Formats"] = $Formats }
            if ($NoInstallTrainDeps) { $formatTrainArgs["NoInstallDeps"] = $true }
            & (Join-Path $RepoRoot "repair_training\train_format_ltr.ps1") @formatTrainArgs
            if ($LASTEXITCODE -ne 0) { throw "format LTR training failed" }
        }
        if ($TrainUnifiedBaseline) {
            $trainArgs = @{
                AllFeatureViews = $true
                FormatScope = "all"
                OutputDir = $UnifiedModelRoot
                InputPath = @($successOutput, $failureOutput)
                LabelTarget = $LabelTarget
            }
            if ($NoInstallTrainDeps) { $trainArgs["NoInstallDeps"] = $true }
            & (Join-Path $RepoRoot "repair_training\train_ltr.ps1") @trainArgs
            if ($LASTEXITCODE -ne 0) { throw "unified LTR training failed" }
        }
    }

    & (Join-Path $RepoRoot "repair_training\report_ltr_data.ps1") -InputPath @($successOutput, $failureOutput) -ModelRoot $ModelRoot -Output $reportOutput -Markdown
    if ($LASTEXITCODE -ne 0) { throw "report step failed" }
}
finally {
    Pop-Location
}
