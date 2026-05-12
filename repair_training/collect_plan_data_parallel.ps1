[CmdletBinding()]
param(
    [string]$MaterialRoot = "repair_training\material",
    [string]$Manifest = "",
    [string]$RunDir = "",
    [string]$RunName = "zip_runtime_graph_parallel",
    [string]$SuccessOutput = "",
    [string]$FailureOutput = "",
    [string]$DebugEvents = "",
    [string]$ParallelSummaryOutput = "",
    [int]$CollectWorkers = 16,
    [ValidateSet("pool", "static")]
    [string]$Scheduling = "pool",
    [int]$QueueBatchSize = 10,
    [int]$MaxActiveCollectors = 6,
    [int]$LaunchDelayMilliseconds = 25,
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
    [int]$MaxExpensiveMaterializationsPerRound = 3,
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
    [switch]$DisableRepairCache,
    [switch]$ProfileMaterializationCandidates,
    [string]$Formats = "",
    [string]$Sample = "",
    [int]$Limit = 0,
    [switch]$NoPretty,
    [switch]$Progress
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "repair training scripts are Windows-only"
}

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $repoRoot

if (-not $RunDir) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeRunName = ($RunName -replace '[^A-Za-z0-9_.-]+', '_').Trim('_')
    if (-not $safeRunName) { $safeRunName = "zip_runtime_graph_parallel" }
    $RunDir = Join-Path "repair_training\runs" ("{0}_{1}" -f $stamp, $safeRunName)
}
$RunDir = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $RunDir))
$datasetDir = Join-Path $RunDir "datasets"
$logsDir = Join-Path $RunDir "logs"
$tmpDir = Join-Path $RunDir "tmp"
New-Item -ItemType Directory -Path $datasetDir, (Join-Path $RunDir "models"), (Join-Path $RunDir "reports"), $logsDir, $tmpDir -Force | Out-Null
if (-not $SuccessOutput) { $SuccessOutput = Join-Path $datasetDir "runtime_graph_success.jsonl" }
if (-not $FailureOutput) { $FailureOutput = Join-Path $datasetDir "runtime_graph_failure.jsonl" }
if (-not $ParallelSummaryOutput) { $ParallelSummaryOutput = Join-Path $datasetDir "runtime_graph_summary.json" }
if (-not $DebugEvents) { $DebugEvents = Join-Path $logsDir "debug_events.jsonl" }

function Split-TrainingCsv {
    param([string]$Raw, [switch]$Lower)
    $output = @()
    foreach ($part in "$Raw".Split(",")) {
        $value = $part.Trim()
        if ($value) {
            if ($Lower) {
                $output += $value.ToLowerInvariant()
            } else {
                $output += $value
            }
        }
    }
    return $output
}

function Resolve-TrainingPath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path $repoRoot $Path)
}

function Add-TrainingCountMap {
    param([hashtable]$Target, [object]$Source)
    if ($null -eq $Source) { return }
    foreach ($prop in $Source.PSObject.Properties) {
        $key = [string]$prop.Name
        $Target[$key] = [int]($Target[$key]) + [int]($prop.Value)
    }
}

function Get-ManifestLines {
    $formatSet = @{}
    foreach ($fmt in (Split-TrainingCsv $Formats -Lower)) { $formatSet[$fmt] = $true }
    $sampleSet = @{}
    foreach ($item in (Split-TrainingCsv $Sample)) { $sampleSet[$item] = $true }

    $lines = New-Object System.Collections.Generic.List[string]
    if ($Manifest) {
        if (-not (Test-Path -LiteralPath $Manifest)) {
            throw "manifest does not exist: $Manifest"
        }
        foreach ($line in Get-Content -LiteralPath $Manifest -Encoding UTF8) {
            if ($line.Trim()) { $lines.Add($line) }
            if ($Limit -gt 0 -and $lines.Count -ge $Limit) { break }
        }
        return @($lines)
    }

    if (-not (Test-Path -LiteralPath $MaterialRoot)) {
        throw "material root does not exist: $MaterialRoot"
    }
    $root = (Resolve-Path -LiteralPath $MaterialRoot).Path
    $manifests = Get-ChildItem -LiteralPath $MaterialRoot -Recurse -Filter damage_manifest.jsonl | Sort-Object FullName
    foreach ($item in $manifests) {
        $relative = $item.FullName.Substring($root.Length).TrimStart("\", "/")
        $parts = $relative -split "[\\/]"
        if ($parts.Length -lt 3) { continue }
        $fmt = $parts[0]
        $sampleName = $parts[1]
        if ($formatSet.Count -gt 0 -and -not $formatSet.ContainsKey($fmt.ToLowerInvariant())) { continue }
        if ($sampleSet.Count -gt 0 -and -not $sampleSet.ContainsKey($sampleName)) { continue }
        foreach ($line in Get-Content -LiteralPath $item.FullName -Encoding UTF8) {
            if ($line.Trim()) { $lines.Add($line) }
            if ($Limit -gt 0 -and $lines.Count -ge $Limit) { return @($lines) }
        }
    }
    return @($lines)
}

$records = @(Get-ManifestLines)
if ($records.Count -eq 0) {
    throw "no repair training manifest records found"
}

$workerCount = [Math]::Max(1, [Math]::Min([int]$CollectWorkers, $records.Count))
$batchSize = [Math]::Max(1, [int]$QueueBatchSize)
$activeLimit = [Math]::Max(1, [Math]::Min([int]$MaxActiveCollectors, $workerCount))
$launchDelayMs = [Math]::Max(0, [int]$LaunchDelayMilliseconds)
$shardRoot = Join-Path $datasetDir ".collect_shards"
if (Test-Path -LiteralPath $shardRoot) {
    Remove-Item -LiteralPath $shardRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $shardRoot -Force | Out-Null

function Append-JsonlFileNoBom {
    param([string]$Source, [string]$Target)
    if (-not (Test-Path -LiteralPath $Source)) {
        return
    }
    $text = [System.IO.File]::ReadAllText($Source, [System.Text.Encoding]::UTF8)
    if (-not $text) {
        return
    }
    if (-not $text.EndsWith("`n")) {
        $text += "`n"
    }
    [System.IO.File]::AppendAllText($Target, $text, [System.Text.UTF8Encoding]::new($false))
}

function New-CollectorArgs {
    param(
        [object]$Unit,
        [int]$Slot,
        [string]$EventsPath
    )
    $argsList = New-Object System.Collections.Generic.List[string]
    foreach ($value in @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $collectScript,
        "-Manifest", (Resolve-TrainingPath $Unit.Manifest),
        "-SuccessOutput", (Resolve-TrainingPath $Unit.Success),
        "-FailureOutput", (Resolve-TrainingPath $Unit.Failure),
        "-SummaryOutput", (Resolve-TrainingPath $Unit.Summary),
        "-Workspace", $Unit.Workspace,
        "-RunDir", $RunDir,
        "-RunName", $RunName,
        "-CollectorShard", "$Slot",
        "-CollectorWorkers", "$workerCount",
        "-SampleExecutionMode", $SampleExecutionMode,
        "-SampleWorkerCount", "$SampleWorkerCount",
        "-MaxRounds", "$MaxRounds",
        "-MaxCandidatesPerRound", "$MaxCandidatesPerRound",
        "-RolloutMode", $RolloutMode,
        "-BeamSize", "$BeamSize",
        "-BranchTopK", "$BranchTopK",
        "-CounterfactualExtra", "$CounterfactualExtra",
        "-MaxTotalStatesPerSample", "$MaxTotalStatesPerSample",
        "-FutureLabelDiscount", "$FutureLabelDiscount",
        "-ProposalMode", $ProposalMode,
        "-MaterializeTopKPerRound", "$MaterializeTopKPerRound",
        "-MaxExpensiveMaterializationsPerRound", "$MaxExpensiveMaterializationsPerRound",
        "-CaseTimeoutSeconds", "$CaseTimeoutSeconds",
        "-StreamLargeSizeMb", "$StreamLargeSizeMb",
        "-StreamLargeCaseTimeoutSeconds", "$StreamLargeCaseTimeoutSeconds",
        "-StreamLargeMaxCandidatesPerRound", "$StreamLargeMaxCandidatesPerRound",
        "-HeartbeatSeconds", "$HeartbeatSeconds",
        "-DebugEvents", $EventsPath
    )) {
        $argsList.Add($value)
    }
    if ($TotalTimeoutSeconds -gt 0) { $argsList.Add("-TotalTimeoutSeconds"); $argsList.Add("$TotalTimeoutSeconds") }
    if ($IdleTimeoutSeconds -gt 0) { $argsList.Add("-IdleTimeoutSeconds"); $argsList.Add("$IdleTimeoutSeconds") }
    if ($MaterializeSelectedOnly) { $argsList.Add("-MaterializeSelectedOnly") }
    if ($IncludeUnmaterializedLabels) { $argsList.Add("-IncludeUnmaterializedLabels") }
    if ($SkipLargeStreamSamples) { $argsList.Add("-SkipLargeStreamSamples") }
    if ($DisableRepairCache) { $argsList.Add("-DisableRepairCache") }
    if ($ProfileMaterializationCandidates) { $argsList.Add("-ProfileMaterializationCandidates") }
    if ($NoPretty) { $argsList.Add("-NoPretty") }
    if ($Progress) { $argsList.Add("-Progress") }
    return $argsList
}

$collectScript = Join-Path $repoRoot "repair_training\collect_plan_data.ps1"

if ($Scheduling -eq "pool") {
    $tasks = @()
    for ($index = 0; $index -lt $records.Count; $index += $batchSize) {
        $taskId = [int]($index / $batchSize)
        $taskRecords = New-Object System.Collections.Generic.List[string]
        $end = [Math]::Min($records.Count - 1, $index + $batchSize - 1)
        for ($recordIndex = $index; $recordIndex -le $end; $recordIndex++) {
            $taskRecords.Add($records[$recordIndex])
        }
        $task = [PSCustomObject]@{
            Id = $taskId
            Manifest = Join-Path $shardRoot ("task_manifest_{0:D5}.jsonl" -f $taskId)
            Success = Join-Path $shardRoot ("task_success_{0:D5}.jsonl" -f $taskId)
            Failure = Join-Path $shardRoot ("task_failure_{0:D5}.jsonl" -f $taskId)
            Events = Join-Path $shardRoot ("task_events_{0:D5}.jsonl" -f $taskId)
            Summary = Join-Path $shardRoot ("task_summary_{0:D5}.json" -f $taskId)
            Stdout = Join-Path $shardRoot ("task_stdout_{0:D5}.log" -f $taskId)
            Stderr = Join-Path $shardRoot ("task_stderr_{0:D5}.log" -f $taskId)
            Workspace = Join-Path (Join-Path $tmpDir "workspace") ("pool_task_{0:D5}" -f $taskId)
            Records = $taskRecords
        }
        [System.IO.File]::WriteAllLines((Resolve-TrainingPath $task.Manifest), [string[]]$task.Records, [System.Text.UTF8Encoding]::new($false))
        $tasks += $task
    }

    $pending = New-Object System.Collections.Generic.Queue[object]
    foreach ($task in $tasks) { $pending.Enqueue($task) }
    $freeSlots = New-Object System.Collections.Generic.Queue[int]
    for ($slot = 0; $slot -lt $activeLimit; $slot++) { $freeSlots.Enqueue($slot) }
    $running = New-Object System.Collections.Generic.List[object]
    $completed = New-Object System.Collections.Generic.List[object]

    while ($pending.Count -gt 0 -or $running.Count -gt 0) {
        while ($pending.Count -gt 0 -and $freeSlots.Count -gt 0) {
            $slot = $freeSlots.Dequeue()
            $task = $pending.Dequeue()
            $eventsPath = Resolve-TrainingPath $task.Events
            $argsList = New-CollectorArgs -Unit $task -Slot $slot -EventsPath $eventsPath
            $process = Start-Process -FilePath "powershell.exe" -ArgumentList ([string[]]$argsList) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Resolve-TrainingPath $task.Stdout) -RedirectStandardError (Resolve-TrainingPath $task.Stderr)
            $running.Add([PSCustomObject]@{ Task = $task; Slot = $slot; Process = $process }) | Out-Null
            if ($launchDelayMs -gt 0) {
                Start-Sleep -Milliseconds $launchDelayMs
            }
        }

        Start-Sleep -Milliseconds 200
        for ($index = $running.Count - 1; $index -ge 0; $index--) {
            $entry = $running[$index]
            if (-not $entry.Process.HasExited) {
                continue
            }
            $entry.Process.Refresh()
            $completed.Add($entry) | Out-Null
            $freeSlots.Enqueue([int]$entry.Slot)
            $running.RemoveAt($index)
        }
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $SuccessOutput) -Force | Out-Null
    [System.IO.File]::WriteAllText((Resolve-TrainingPath $SuccessOutput), "", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Resolve-TrainingPath $FailureOutput), "", [System.Text.UTF8Encoding]::new($false))
    if ($DebugEvents) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $DebugEvents) -Force | Out-Null
        [System.IO.File]::WriteAllText((Resolve-TrainingPath $DebugEvents), "", [System.Text.UTF8Encoding]::new($false))
    }

    $summaries = @()
    $failed = @()
    foreach ($entry in $completed | Sort-Object { $_.Task.Id }) {
        $task = $entry.Task
        foreach ($pair in @(@($task.Success, $SuccessOutput), @($task.Failure, $FailureOutput))) {
            Append-JsonlFileNoBom (Resolve-TrainingPath $pair[0]) (Resolve-TrainingPath $pair[1])
        }
        if ($DebugEvents -and (Test-Path -LiteralPath (Resolve-TrainingPath $task.Events))) {
            Append-JsonlFileNoBom (Resolve-TrainingPath $task.Events) (Resolve-TrainingPath $DebugEvents)
        }
        if (Test-Path -LiteralPath (Resolve-TrainingPath $task.Summary)) {
            $summary = Get-Content -LiteralPath (Resolve-TrainingPath $task.Summary) -Raw -Encoding UTF8 | ConvertFrom-Json
            $summary | Add-Member -NotePropertyName collector_task -NotePropertyValue $task.Id -Force
            $summary | Add-Member -NotePropertyName collector_slot -NotePropertyValue $entry.Slot -Force
            $summaries += $summary
            if ([int]($summary.failed) -gt 0) {
                $failed += $task.Id
            }
        } elseif ($entry.Process.ExitCode -ne 0) {
            $failed += $task.Id
        }
    }

    $aggregate = [ordered]@{
        scheduling = "pool"
        collect_workers = $workerCount
        requested_collect_workers = $CollectWorkers
        max_active_collectors = $activeLimit
        launch_delay_milliseconds = $launchDelayMs
        queue_batch_size = $batchSize
        sample_execution_mode = $SampleExecutionMode
        sample_worker_count = $SampleWorkerCount
        task_count = $tasks.Count
        records = $records.Count
        failed_tasks = $failed
        failed_shards = $failed
        shard_count = $tasks.Count
        success_output = $SuccessOutput
        failure_output = $FailureOutput
        debug_events = $DebugEvents
        shard_root = $shardRoot
        samples = 0
        success_rows = 0
        failure_rows = 0
        timeouts = 0
        failed = 0
        skipped = 0
        state_count = 0
        expanded_state_count = 0
        branch_count = 0
        terminal_success_count = 0
        legacy_module_seen_count = 0
        duplicate_candidate_id_count = 0
        rollout_budget_exhausted = 0
        best_partial_returned_count = 0
        repair_cache_hits = 0
        repair_cache_misses = 0
        knowledge_projection_cache_hits = 0
        knowledge_projection_cache_misses = 0
        materialize_cache_hits = 0
        native_operation_cache_hits = 0
        zip_scan_artifact_hits = 0
        zip_scan_artifact_misses = 0
        expensive_materialization_skipped_count = 0
        materialize_worker_seconds_saved_estimate = 0.0
        repair_cache_by_namespace = @{}
        knowledge_projection_cache_by_projection = @{}
        materialize_cost_bucket_counts = @{}
        label_counts = @{}
        future_label_counts = @{}
        rollout_mode_counts = @{}
        terminal_status_counts = @{}
        stop_reason_counts = @{}
        best_recovery_bucket_counts = @{}
        global_stagnation_counts = @{}
        no_output_reason_counts = @{}
        no_output_by_module = @{}
        no_output_by_damage_profile = @{}
        no_output_by_atomic_family = @{}
        native_target_mismatch_counts = @{}
        native_target_mismatch_by_profile = @{}
        no_candidate_by_native_target = @{}
        validation_failed_by_profile = @{}
        post_crop_residual_fact_counts = @{}
        split_logical_stream_counts = @{}
        split_sidecar_route_counts = @{}
        split_sidecar_complete_candidate_counts = @{}
        extra_field_length_candidate_counts = @{}
        zip64_extra_no_candidate_by_profile = @{}
        descriptor_cd_conflict_diff_buckets = @{}
        route_rejected_by_required_flags = 0
        route_rejected_by_can_handle = 0
        shards = $summaries
    }
    foreach ($summary in $summaries) {
        foreach ($name in @("samples", "success_rows", "failure_rows", "timeouts", "failed", "skipped", "state_count", "expanded_state_count", "branch_count", "terminal_success_count", "legacy_module_seen_count", "duplicate_candidate_id_count", "rollout_budget_exhausted", "best_partial_returned_count", "repair_cache_hits", "repair_cache_misses", "knowledge_projection_cache_hits", "knowledge_projection_cache_misses", "materialize_cache_hits", "native_operation_cache_hits", "zip_scan_artifact_hits", "zip_scan_artifact_misses", "expensive_materialization_skipped_count", "route_rejected_by_required_flags", "route_rejected_by_can_handle")) {
            $aggregate[$name] = [int]$aggregate[$name] + [int]($summary.$name)
        }
        $aggregate["materialize_worker_seconds_saved_estimate"] = [double]$aggregate["materialize_worker_seconds_saved_estimate"] + [double]($summary.materialize_worker_seconds_saved_estimate)
        foreach ($prop in $summary.repair_cache_by_namespace.PSObject.Properties) {
            $key = [string]$prop.Name
            if (-not $aggregate["repair_cache_by_namespace"].ContainsKey($key)) {
                $aggregate["repair_cache_by_namespace"][$key] = @{ hits = 0; misses = 0 }
            }
            $aggregate["repair_cache_by_namespace"][$key]["hits"] = [int]$aggregate["repair_cache_by_namespace"][$key]["hits"] + [int]($prop.Value.hits)
            $aggregate["repair_cache_by_namespace"][$key]["misses"] = [int]$aggregate["repair_cache_by_namespace"][$key]["misses"] + [int]($prop.Value.misses)
        }
        foreach ($prop in $summary.knowledge_projection_cache_by_projection.PSObject.Properties) {
            $key = [string]$prop.Name
            if (-not $aggregate["knowledge_projection_cache_by_projection"].ContainsKey($key)) {
                $aggregate["knowledge_projection_cache_by_projection"][$key] = @{ hits = 0; misses = 0 }
            }
            $aggregate["knowledge_projection_cache_by_projection"][$key]["hits"] = [int]$aggregate["knowledge_projection_cache_by_projection"][$key]["hits"] + [int]($prop.Value.hits)
            $aggregate["knowledge_projection_cache_by_projection"][$key]["misses"] = [int]$aggregate["knowledge_projection_cache_by_projection"][$key]["misses"] + [int]($prop.Value.misses)
        }
        Add-TrainingCountMap $aggregate["label_counts"] $summary.label_counts
        Add-TrainingCountMap $aggregate["future_label_counts"] $summary.future_label_counts
        Add-TrainingCountMap $aggregate["rollout_mode_counts"] $summary.rollout_mode_counts
        Add-TrainingCountMap $aggregate["terminal_status_counts"] $summary.terminal_status_counts
        Add-TrainingCountMap $aggregate["stop_reason_counts"] $summary.stop_reason_counts
        Add-TrainingCountMap $aggregate["best_recovery_bucket_counts"] $summary.best_recovery_bucket_counts
        Add-TrainingCountMap $aggregate["materialize_cost_bucket_counts"] $summary.materialize_cost_bucket_counts
        Add-TrainingCountMap $aggregate["global_stagnation_counts"] $summary.global_stagnation_counts
        Add-TrainingCountMap $aggregate["no_output_reason_counts"] $summary.no_output_reason_counts
        Add-TrainingCountMap $aggregate["no_output_by_module"] $summary.no_output_by_module
        Add-TrainingCountMap $aggregate["no_output_by_damage_profile"] $summary.no_output_by_damage_profile
        Add-TrainingCountMap $aggregate["no_output_by_atomic_family"] $summary.no_output_by_atomic_family
        Add-TrainingCountMap $aggregate["native_target_mismatch_counts"] $summary.native_target_mismatch_counts
        Add-TrainingCountMap $aggregate["native_target_mismatch_by_profile"] $summary.native_target_mismatch_by_profile
        Add-TrainingCountMap $aggregate["no_candidate_by_native_target"] $summary.no_candidate_by_native_target
        Add-TrainingCountMap $aggregate["validation_failed_by_profile"] $summary.validation_failed_by_profile
        Add-TrainingCountMap $aggregate["post_crop_residual_fact_counts"] $summary.post_crop_residual_fact_counts
        Add-TrainingCountMap $aggregate["split_logical_stream_counts"] $summary.split_logical_stream_counts
        Add-TrainingCountMap $aggregate["split_sidecar_route_counts"] $summary.split_sidecar_route_counts
        Add-TrainingCountMap $aggregate["split_sidecar_complete_candidate_counts"] $summary.split_sidecar_complete_candidate_counts
        Add-TrainingCountMap $aggregate["extra_field_length_candidate_counts"] $summary.extra_field_length_candidate_counts
        Add-TrainingCountMap $aggregate["zip64_extra_no_candidate_by_profile"] $summary.zip64_extra_no_candidate_by_profile
        Add-TrainingCountMap $aggregate["descriptor_cd_conflict_diff_buckets"] $summary.descriptor_cd_conflict_diff_buckets
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent (Resolve-TrainingPath $ParallelSummaryOutput)) -Force | Out-Null
    ($aggregate | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath (Resolve-TrainingPath $ParallelSummaryOutput) -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $repoRoot "repair_training\latest_run.txt") -Value ($RunDir + "`n") -Encoding UTF8
    Write-Host ($aggregate | ConvertTo-Json -Depth 8) -ForegroundColor Cyan

    if ($failed.Count -gt 0) {
        throw "parallel collect failed tasks: $($failed -join ', ')"
    }

    $global:LASTEXITCODE = 0
    return
}

$shards = @()
for ($index = 0; $index -lt $workerCount; $index++) {
    $shard = [PSCustomObject]@{
        Id = $index
        Manifest = Join-Path $shardRoot ("manifest_{0:D3}.jsonl" -f $index)
        Success = Join-Path $shardRoot ("success_{0:D3}.jsonl" -f $index)
        Failure = Join-Path $shardRoot ("failure_{0:D3}.jsonl" -f $index)
        Events = Join-Path $shardRoot ("events_{0:D3}.jsonl" -f $index)
        Summary = Join-Path $shardRoot ("summary_{0:D3}.json" -f $index)
        Stdout = Join-Path $shardRoot ("stdout_{0:D3}.log" -f $index)
        Stderr = Join-Path $shardRoot ("stderr_{0:D3}.log" -f $index)
        Workspace = Join-Path ".sunpack\repair-plan-workspace" ("shard_{0:D3}" -f $index)
        Records = New-Object System.Collections.Generic.List[string]
    }
    $shards += $shard
}

for ($index = 0; $index -lt $records.Count; $index++) {
    $shards[$index % $workerCount].Records.Add($records[$index])
}

foreach ($shard in $shards) {
    [System.IO.File]::WriteAllLines((Join-Path $repoRoot $shard.Manifest), [string[]]$shard.Records, [System.Text.UTF8Encoding]::new($false))
}

$processes = @()
foreach ($shard in $shards) {
    $argsList = New-Object System.Collections.Generic.List[string]
    foreach ($value in @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $collectScript,
        "-Manifest", (Join-Path $repoRoot $shard.Manifest),
        "-SuccessOutput", (Join-Path $repoRoot $shard.Success),
        "-FailureOutput", (Join-Path $repoRoot $shard.Failure),
        "-SummaryOutput", (Join-Path $repoRoot $shard.Summary),
        "-Workspace", $shard.Workspace,
        "-CollectorShard", "$($shard.Id)",
        "-CollectorWorkers", "$workerCount",
        "-SampleExecutionMode", $SampleExecutionMode,
        "-SampleWorkerCount", "$SampleWorkerCount",
        "-MaxRounds", "$MaxRounds",
        "-MaxCandidatesPerRound", "$MaxCandidatesPerRound",
        "-RolloutMode", $RolloutMode,
        "-BeamSize", "$BeamSize",
        "-BranchTopK", "$BranchTopK",
        "-CounterfactualExtra", "$CounterfactualExtra",
        "-MaxTotalStatesPerSample", "$MaxTotalStatesPerSample",
        "-FutureLabelDiscount", "$FutureLabelDiscount",
        "-ProposalMode", $ProposalMode,
        "-MaterializeTopKPerRound", "$MaterializeTopKPerRound",
        "-CaseTimeoutSeconds", "$CaseTimeoutSeconds",
        "-StreamLargeSizeMb", "$StreamLargeSizeMb",
        "-StreamLargeCaseTimeoutSeconds", "$StreamLargeCaseTimeoutSeconds",
        "-StreamLargeMaxCandidatesPerRound", "$StreamLargeMaxCandidatesPerRound",
        "-HeartbeatSeconds", "$HeartbeatSeconds",
        "-DebugEvents", (Join-Path $repoRoot $shard.Events)
    )) {
        $argsList.Add($value)
    }
    if ($TotalTimeoutSeconds -gt 0) { $argsList.Add("-TotalTimeoutSeconds"); $argsList.Add("$TotalTimeoutSeconds") }
    if ($IdleTimeoutSeconds -gt 0) { $argsList.Add("-IdleTimeoutSeconds"); $argsList.Add("$IdleTimeoutSeconds") }
    if ($MaterializeSelectedOnly) { $argsList.Add("-MaterializeSelectedOnly") }
    if ($IncludeUnmaterializedLabels) { $argsList.Add("-IncludeUnmaterializedLabels") }
    if ($SkipLargeStreamSamples) { $argsList.Add("-SkipLargeStreamSamples") }
    if ($DisableRepairCache) { $argsList.Add("-DisableRepairCache") }
    if ($ProfileMaterializationCandidates) { $argsList.Add("-ProfileMaterializationCandidates") }
    if ($NoPretty) { $argsList.Add("-NoPretty") }
    if ($Progress) { $argsList.Add("-Progress") }

    $processes += [PSCustomObject]@{
        Shard = $shard
        Process = Start-Process -FilePath "powershell.exe" -ArgumentList ([string[]]$argsList) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $repoRoot $shard.Stdout) -RedirectStandardError (Join-Path $repoRoot $shard.Stderr)
    }
}

foreach ($entry in $processes) {
    $entry.Process.WaitForExit()
    $entry.Process.Refresh()
}

New-Item -ItemType Directory -Path (Split-Path -Parent $SuccessOutput) -Force | Out-Null
[System.IO.File]::WriteAllText((Join-Path $repoRoot $SuccessOutput), "", [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText((Join-Path $repoRoot $FailureOutput), "", [System.Text.UTF8Encoding]::new($false))
if ($DebugEvents) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $DebugEvents) -Force | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $repoRoot $DebugEvents), "", [System.Text.UTF8Encoding]::new($false))
}

$summaries = @()
$failed = @()
foreach ($entry in $processes | Sort-Object { $_.Shard.Id }) {
    $shard = $entry.Shard
    foreach ($pair in @(@($shard.Success, $SuccessOutput), @($shard.Failure, $FailureOutput))) {
        Append-JsonlFileNoBom (Join-Path $repoRoot $pair[0]) (Join-Path $repoRoot $pair[1])
    }
    if ($DebugEvents -and (Test-Path -LiteralPath (Join-Path $repoRoot $shard.Events))) {
        Append-JsonlFileNoBom (Join-Path $repoRoot $shard.Events) (Join-Path $repoRoot $DebugEvents)
    }
    if (Test-Path -LiteralPath (Join-Path $repoRoot $shard.Summary)) {
        $summary = Get-Content -LiteralPath (Join-Path $repoRoot $shard.Summary) -Raw -Encoding UTF8 | ConvertFrom-Json
        $summaries += $summary
        if ([int]($summary.failed) -gt 0) {
            $failed += $shard.Id
        }
    } elseif ($entry.Process.ExitCode -ne 0) {
        $failed += $shard.Id
    }
}

$aggregate = [ordered]@{
    collect_workers = $workerCount
    requested_collect_workers = $CollectWorkers
    max_active_collectors = $workerCount
    launch_delay_milliseconds = 0
    queue_batch_size = 0
    sample_execution_mode = $SampleExecutionMode
    sample_worker_count = $SampleWorkerCount
    task_count = $shards.Count
    records = $records.Count
    failed_shards = $failed
    shard_count = $shards.Count
    success_output = $SuccessOutput
    failure_output = $FailureOutput
    debug_events = $DebugEvents
    shard_root = $shardRoot
    samples = 0
    success_rows = 0
    failure_rows = 0
    timeouts = 0
    failed = 0
    skipped = 0
    state_count = 0
    expanded_state_count = 0
    branch_count = 0
    terminal_success_count = 0
    legacy_module_seen_count = 0
    duplicate_candidate_id_count = 0
    rollout_budget_exhausted = 0
    best_partial_returned_count = 0
    repair_cache_hits = 0
    repair_cache_misses = 0
    knowledge_projection_cache_hits = 0
    knowledge_projection_cache_misses = 0
    materialize_cache_hits = 0
    native_operation_cache_hits = 0
    zip_scan_artifact_hits = 0
    zip_scan_artifact_misses = 0
    expensive_materialization_skipped_count = 0
    materialize_worker_seconds_saved_estimate = 0.0
    repair_cache_by_namespace = @{}
    knowledge_projection_cache_by_projection = @{}
    materialize_cost_bucket_counts = @{}
    label_counts = @{}
    future_label_counts = @{}
    rollout_mode_counts = @{}
    terminal_status_counts = @{}
    stop_reason_counts = @{}
    best_recovery_bucket_counts = @{}
    global_stagnation_counts = @{}
    no_output_reason_counts = @{}
    no_output_by_module = @{}
    no_output_by_damage_profile = @{}
    no_output_by_atomic_family = @{}
    native_target_mismatch_counts = @{}
    native_target_mismatch_by_profile = @{}
    no_candidate_by_native_target = @{}
    validation_failed_by_profile = @{}
    post_crop_residual_fact_counts = @{}
    split_logical_stream_counts = @{}
    split_sidecar_route_counts = @{}
    split_sidecar_complete_candidate_counts = @{}
    extra_field_length_candidate_counts = @{}
    zip64_extra_no_candidate_by_profile = @{}
    descriptor_cd_conflict_diff_buckets = @{}
    route_rejected_by_required_flags = 0
    route_rejected_by_can_handle = 0
    shards = $summaries
}
foreach ($summary in $summaries) {
    foreach ($name in @("samples", "success_rows", "failure_rows", "timeouts", "failed", "skipped", "state_count", "expanded_state_count", "branch_count", "terminal_success_count", "legacy_module_seen_count", "duplicate_candidate_id_count", "rollout_budget_exhausted", "best_partial_returned_count", "repair_cache_hits", "repair_cache_misses", "knowledge_projection_cache_hits", "knowledge_projection_cache_misses", "materialize_cache_hits", "native_operation_cache_hits", "zip_scan_artifact_hits", "zip_scan_artifact_misses", "expensive_materialization_skipped_count", "route_rejected_by_required_flags", "route_rejected_by_can_handle")) {
        $aggregate[$name] = [int]$aggregate[$name] + [int]($summary.$name)
    }
    $aggregate["materialize_worker_seconds_saved_estimate"] = [double]$aggregate["materialize_worker_seconds_saved_estimate"] + [double]($summary.materialize_worker_seconds_saved_estimate)
    foreach ($prop in $summary.repair_cache_by_namespace.PSObject.Properties) {
        $key = [string]$prop.Name
        if (-not $aggregate["repair_cache_by_namespace"].ContainsKey($key)) {
            $aggregate["repair_cache_by_namespace"][$key] = @{ hits = 0; misses = 0 }
        }
        $aggregate["repair_cache_by_namespace"][$key]["hits"] = [int]$aggregate["repair_cache_by_namespace"][$key]["hits"] + [int]($prop.Value.hits)
        $aggregate["repair_cache_by_namespace"][$key]["misses"] = [int]$aggregate["repair_cache_by_namespace"][$key]["misses"] + [int]($prop.Value.misses)
    }
    foreach ($prop in $summary.knowledge_projection_cache_by_projection.PSObject.Properties) {
        $key = [string]$prop.Name
        if (-not $aggregate["knowledge_projection_cache_by_projection"].ContainsKey($key)) {
            $aggregate["knowledge_projection_cache_by_projection"][$key] = @{ hits = 0; misses = 0 }
        }
        $aggregate["knowledge_projection_cache_by_projection"][$key]["hits"] = [int]$aggregate["knowledge_projection_cache_by_projection"][$key]["hits"] + [int]($prop.Value.hits)
        $aggregate["knowledge_projection_cache_by_projection"][$key]["misses"] = [int]$aggregate["knowledge_projection_cache_by_projection"][$key]["misses"] + [int]($prop.Value.misses)
    }
    Add-TrainingCountMap $aggregate["label_counts"] $summary.label_counts
    Add-TrainingCountMap $aggregate["future_label_counts"] $summary.future_label_counts
    Add-TrainingCountMap $aggregate["rollout_mode_counts"] $summary.rollout_mode_counts
    Add-TrainingCountMap $aggregate["terminal_status_counts"] $summary.terminal_status_counts
    Add-TrainingCountMap $aggregate["stop_reason_counts"] $summary.stop_reason_counts
    Add-TrainingCountMap $aggregate["best_recovery_bucket_counts"] $summary.best_recovery_bucket_counts
    Add-TrainingCountMap $aggregate["materialize_cost_bucket_counts"] $summary.materialize_cost_bucket_counts
    Add-TrainingCountMap $aggregate["global_stagnation_counts"] $summary.global_stagnation_counts
    Add-TrainingCountMap $aggregate["no_output_reason_counts"] $summary.no_output_reason_counts
    Add-TrainingCountMap $aggregate["no_output_by_module"] $summary.no_output_by_module
    Add-TrainingCountMap $aggregate["no_output_by_damage_profile"] $summary.no_output_by_damage_profile
    Add-TrainingCountMap $aggregate["no_output_by_atomic_family"] $summary.no_output_by_atomic_family
    Add-TrainingCountMap $aggregate["native_target_mismatch_counts"] $summary.native_target_mismatch_counts
    Add-TrainingCountMap $aggregate["native_target_mismatch_by_profile"] $summary.native_target_mismatch_by_profile
    Add-TrainingCountMap $aggregate["no_candidate_by_native_target"] $summary.no_candidate_by_native_target
    Add-TrainingCountMap $aggregate["validation_failed_by_profile"] $summary.validation_failed_by_profile
    Add-TrainingCountMap $aggregate["post_crop_residual_fact_counts"] $summary.post_crop_residual_fact_counts
    Add-TrainingCountMap $aggregate["split_logical_stream_counts"] $summary.split_logical_stream_counts
    Add-TrainingCountMap $aggregate["split_sidecar_route_counts"] $summary.split_sidecar_route_counts
    Add-TrainingCountMap $aggregate["split_sidecar_complete_candidate_counts"] $summary.split_sidecar_complete_candidate_counts
    Add-TrainingCountMap $aggregate["extra_field_length_candidate_counts"] $summary.extra_field_length_candidate_counts
    Add-TrainingCountMap $aggregate["zip64_extra_no_candidate_by_profile"] $summary.zip64_extra_no_candidate_by_profile
    Add-TrainingCountMap $aggregate["descriptor_cd_conflict_diff_buckets"] $summary.descriptor_cd_conflict_diff_buckets
}

New-Item -ItemType Directory -Path (Split-Path -Parent (Resolve-TrainingPath $ParallelSummaryOutput)) -Force | Out-Null
($aggregate | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath (Resolve-TrainingPath $ParallelSummaryOutput) -Encoding UTF8
Set-Content -LiteralPath (Join-Path $repoRoot "repair_training\latest_run.txt") -Value ($RunDir + "`n") -Encoding UTF8
Write-Host ($aggregate | ConvertTo-Json -Depth 8) -ForegroundColor Cyan

if ($failed.Count -gt 0) {
    throw "parallel collect failed shards: $($failed -join ', ')"
}

$global:LASTEXITCODE = 0
