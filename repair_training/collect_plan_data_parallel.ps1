[CmdletBinding()]
param(
    [string]$MaterialRoot = "repair_training\material",
    [string]$Manifest = "",
    [string]$SuccessOutput = "repair_training\datasets\repair_plan_ltr_success.jsonl",
    [string]$FailureOutput = "repair_training\datasets\repair_plan_ltr_failure.jsonl",
    [string]$DebugEvents = "",
    [string]$ParallelSummaryOutput = "repair_training\datasets\collect_parallel_summary.json",
    [int]$CollectWorkers = 16,
    [ValidateSet("pool", "static")]
    [string]$Scheduling = "pool",
    [int]$QueueBatchSize = 1,
    [int]$MaxActiveCollectors = 6,
    [int]$LaunchDelayMilliseconds = 150,
    [int]$MaxRounds = 3,
    [int]$MaxCandidatesPerRound = 10,
    [ValidateSet("greedy", "greedy_current_selector", "beam", "counterfactual")]
    [string]$RolloutMode = "greedy",
    [int]$BeamSize = 1,
    [int]$BranchTopK = 2,
    [int]$CounterfactualExtra = 2,
    [int]$MaxTotalStatesPerSample = 6,
    [double]$FutureLabelDiscount = 0.8,
    [ValidateSet("lazy", "eager")]
    [string]$ProposalMode = "lazy",
    [int]$MaterializeTopKPerRound = 2,
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
$datasetDir = Split-Path -Parent $SuccessOutput
if (-not $datasetDir) { $datasetDir = "repair_training\datasets" }
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
        "-Manifest", (Join-Path $repoRoot $Unit.Manifest),
        "-SuccessOutput", (Join-Path $repoRoot $Unit.Success),
        "-FailureOutput", (Join-Path $repoRoot $Unit.Failure),
        "-SummaryOutput", (Join-Path $repoRoot $Unit.Summary),
        "-Workspace", $Unit.Workspace,
        "-CollectorShard", "$Slot",
        "-CollectorWorkers", "$workerCount",
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
        "-DebugEvents", $EventsPath
    )) {
        $argsList.Add($value)
    }
    if ($TotalTimeoutSeconds -gt 0) { $argsList.Add("-TotalTimeoutSeconds"); $argsList.Add("$TotalTimeoutSeconds") }
    if ($IdleTimeoutSeconds -gt 0) { $argsList.Add("-IdleTimeoutSeconds"); $argsList.Add("$IdleTimeoutSeconds") }
    if ($MaterializeSelectedOnly) { $argsList.Add("-MaterializeSelectedOnly") }
    if ($IncludeUnmaterializedLabels) { $argsList.Add("-IncludeUnmaterializedLabels") }
    if ($SkipLargeStreamSamples) { $argsList.Add("-SkipLargeStreamSamples") }
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
            Workspace = Join-Path ".sunpack\repair-plan-workspace" ("pool_task_{0:D5}" -f $taskId)
            Records = $taskRecords
        }
        [System.IO.File]::WriteAllLines((Join-Path $repoRoot $task.Manifest), [string[]]$task.Records, [System.Text.UTF8Encoding]::new($false))
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
            $eventsPath = Join-Path $repoRoot $task.Events
            $argsList = New-CollectorArgs -Unit $task -Slot $slot -EventsPath $eventsPath
            $process = Start-Process -FilePath "powershell.exe" -ArgumentList ([string[]]$argsList) -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $repoRoot $task.Stdout) -RedirectStandardError (Join-Path $repoRoot $task.Stderr)
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
    [System.IO.File]::WriteAllText((Join-Path $repoRoot $SuccessOutput), "", [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::WriteAllText((Join-Path $repoRoot $FailureOutput), "", [System.Text.UTF8Encoding]::new($false))
    if ($DebugEvents) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $DebugEvents) -Force | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $repoRoot $DebugEvents), "", [System.Text.UTF8Encoding]::new($false))
    }

    $summaries = @()
    $failed = @()
    foreach ($entry in $completed | Sort-Object { $_.Task.Id }) {
        $task = $entry.Task
        foreach ($pair in @(@($task.Success, $SuccessOutput), @($task.Failure, $FailureOutput))) {
            Append-JsonlFileNoBom (Join-Path $repoRoot $pair[0]) (Join-Path $repoRoot $pair[1])
        }
        if ($DebugEvents -and (Test-Path -LiteralPath (Join-Path $repoRoot $task.Events))) {
            Append-JsonlFileNoBom (Join-Path $repoRoot $task.Events) (Join-Path $repoRoot $DebugEvents)
        }
        if (Test-Path -LiteralPath (Join-Path $repoRoot $task.Summary)) {
            $summary = Get-Content -LiteralPath (Join-Path $repoRoot $task.Summary) -Raw -Encoding UTF8 | ConvertFrom-Json
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
        rollout_budget_exhausted = 0
        label_counts = @{}
        future_label_counts = @{}
        rollout_mode_counts = @{}
        terminal_status_counts = @{}
        shards = $summaries
    }
    foreach ($summary in $summaries) {
        foreach ($name in @("samples", "success_rows", "failure_rows", "timeouts", "failed", "skipped", "state_count", "expanded_state_count", "branch_count", "terminal_success_count", "rollout_budget_exhausted")) {
            $aggregate[$name] = [int]$aggregate[$name] + [int]($summary.$name)
        }
        Add-TrainingCountMap $aggregate["label_counts"] $summary.label_counts
        Add-TrainingCountMap $aggregate["future_label_counts"] $summary.future_label_counts
        Add-TrainingCountMap $aggregate["rollout_mode_counts"] $summary.rollout_mode_counts
        Add-TrainingCountMap $aggregate["terminal_status_counts"] $summary.terminal_status_counts
    }

    New-Item -ItemType Directory -Path (Split-Path -Parent $ParallelSummaryOutput) -Force | Out-Null
    ($aggregate | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $ParallelSummaryOutput -Encoding UTF8
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
    rollout_budget_exhausted = 0
    label_counts = @{}
    future_label_counts = @{}
    rollout_mode_counts = @{}
    terminal_status_counts = @{}
    shards = $summaries
}
foreach ($summary in $summaries) {
    foreach ($name in @("samples", "success_rows", "failure_rows", "timeouts", "failed", "skipped", "state_count", "expanded_state_count", "branch_count", "terminal_success_count", "rollout_budget_exhausted")) {
        $aggregate[$name] = [int]$aggregate[$name] + [int]($summary.$name)
    }
    Add-TrainingCountMap $aggregate["label_counts"] $summary.label_counts
    Add-TrainingCountMap $aggregate["future_label_counts"] $summary.future_label_counts
    Add-TrainingCountMap $aggregate["rollout_mode_counts"] $summary.rollout_mode_counts
    Add-TrainingCountMap $aggregate["terminal_status_counts"] $summary.terminal_status_counts
}

New-Item -ItemType Directory -Path (Split-Path -Parent $ParallelSummaryOutput) -Force | Out-Null
($aggregate | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $ParallelSummaryOutput -Encoding UTF8
Write-Host ($aggregate | ConvertTo-Json -Depth 8) -ForegroundColor Cyan

if ($failed.Count -gt 0) {
    throw "parallel collect failed shards: $($failed -join ', ')"
}

$global:LASTEXITCODE = 0
