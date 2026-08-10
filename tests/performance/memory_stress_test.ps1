param(
    [int]$ArchiveCount = 80,
    [int]$BatchCount = 3,
    [int]$PayloadMiB = 1
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$distRoot = Join-Path $projectRoot 'dist\sunpack-x64-lite'
$sunpackExe = Join-Path $distRoot 'sunpack.exe'
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sunpack-memory-stress-" + [guid]::NewGuid().ToString('N'))
$seedDir = Join-Path $testRoot 'seed'
$seedZip = Join-Path $testRoot 'seed.zip'
$runtimeRoot = Join-Path $testRoot 'runtime'
$watchRoot = Join-Path $testRoot 'watch'
$watchOut = Join-Path $watchRoot 'out'
$samples = [System.Collections.Generic.List[object]]::new()

function Add-Sample([string]$scenario, [int]$batch, [string]$phase) {
    foreach ($name in @('sunpack-runtime', 'sunpack-watch')) {
        $process = Get-Process -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
        $samples.Add([pscustomobject]@{
            timestamp = [datetime]::Now.ToString('o')
            scenario = $scenario
            batch = $batch
            phase = $phase
            process = $name
            running = $null -ne $process
            pid = if ($process) { $process.Id } else { $null }
            working_set_mib = if ($process) { [math]::Round($process.WorkingSet64 / 1MB, 2) } else { $null }
            private_mib = if ($process) { [math]::Round($process.PrivateMemorySize64 / 1MB, 2) } else { $null }
            handles = if ($process) { $process.HandleCount } else { $null }
        })
    }
}

function New-ArchiveBatch([string]$directory, [int]$batch) {
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    1..$ArchiveCount | ForEach-Object {
        Copy-Item -LiteralPath $seedZip -Destination (Join-Path $directory ("batch{0:D2}-{1:D4}.zip" -f $batch, $_))
    }
}

function Wait-WatchBatch([string]$directory, [int]$batch, [int]$timeoutSeconds = 180) {
    $deadline = [datetime]::UtcNow.AddSeconds($timeoutSeconds)
    do {
        $count = @(Get-ChildItem -LiteralPath $directory -Directory -Filter ("batch{0:D2}-*" -f $batch) -ErrorAction SilentlyContinue).Count
        if ($count -ge $ArchiveCount) { return $count }
        Start-Sleep -Milliseconds 500
    } while ([datetime]::UtcNow -lt $deadline)
    throw "watch batch $batch timed out; completed $count/$ArchiveCount"
}

New-Item -ItemType Directory -Force -Path $seedDir, $runtimeRoot, $watchRoot, $watchOut | Out-Null
$bytes = New-Object byte[] ($PayloadMiB * 1MB)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[System.IO.File]::WriteAllBytes((Join-Path $seedDir 'payload.bin'), $bytes)
Compress-Archive -LiteralPath (Join-Path $seedDir 'payload.bin') -DestinationPath $seedZip -CompressionLevel Optimal

try {
    & $sunpackExe --persistent-shutdown | Out-Null
    Start-Sleep -Seconds 1
    Add-Sample 'runtime' 0 'baseline'
    for ($batch = 1; $batch -le $BatchCount; $batch++) {
        $inputDir = Join-Path $runtimeRoot ("input-{0:D2}" -f $batch)
        $outputDir = Join-Path $runtimeRoot ("output-{0:D2}" -f $batch)
        New-ArchiveBatch $inputDir $batch
        & $sunpackExe extract $inputDir --out-dir $outputDir --cleanup k --no-flatten --no-pause --quiet
        if ($LASTEXITCODE -ne 0) { throw "runtime batch $batch failed with exit code $LASTEXITCODE" }
        Add-Sample 'runtime' $batch 'completed'
        Start-Sleep -Seconds 3
        Add-Sample 'runtime' $batch 'idle-3s'
    }
    Start-Sleep -Seconds 18
    Add-Sample 'runtime' $BatchCount 'idle-21s'

    & $sunpackExe watch stop --no-pause --quiet | Out-Null
    Start-Sleep -Seconds 1
    & $sunpackExe watch add $watchRoot --start --no-pause --quiet | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not add temporary watch root" }
    Start-Sleep -Seconds 2
    Add-Sample 'watch' 0 'baseline'
    for ($batch = 1; $batch -le $BatchCount; $batch++) {
        New-ArchiveBatch $watchRoot $batch
        $null = Wait-WatchBatch $watchRoot $batch
        Add-Sample 'watch' $batch 'completed'
        Start-Sleep -Seconds 3
        Add-Sample 'watch' $batch 'idle-3s'
    }
    Start-Sleep -Seconds 20
    Add-Sample 'watch' $BatchCount 'idle-23s'
}
finally {
    & $sunpackExe watch remove $watchRoot --no-pause --quiet | Out-Null
    & $sunpackExe watch stop --no-pause --quiet | Out-Null
    & $sunpackExe watch start --no-pause --quiet | Out-Null
    & $sunpackExe --persistent-shutdown | Out-Null
    $samples | ConvertTo-Json -Depth 4
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
