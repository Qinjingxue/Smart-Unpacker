param(
    [string]$SourceRoot = "repair_training\source_material",
    [string]$MaterialRoot = "repair_training\material",
    [string]$Config = "repair_training\archive_derivation_config.json",
    [string]$Formats = "",
    [string[]]$Sample = @(),
    [int]$Workers = -1,
    [double]$TaskTimeoutSeconds = 0,
    [switch]$RandomMode,
    [switch]$NoRandomMode,
    [int]$ArchivesPerSample = 0,
    [string]$Seed = "",
    [switch]$NoPretty,
    [string[]]$ExtraArgs = @()
)

$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") {
    throw "repair training scripts are Windows-only"
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = "python"
}

$env:PYTHONPATH = "$RepoRoot"
$ArgsList = @(
    (Join-Path $RepoRoot "repair_training\derive_archives.py"),
    "--source-root", (Join-Path $RepoRoot $SourceRoot),
    "--material-root", (Join-Path $RepoRoot $MaterialRoot),
    "--config", (Join-Path $RepoRoot $Config)
)
if ($Formats) {
    $ArgsList += @("--formats", $Formats)
}
foreach ($Item in $Sample) {
    if ($Item) {
        $ArgsList += @("--sample", $Item)
    }
}
if ($Workers -ge 0) {
    $ArgsList += @("--workers", "$Workers")
}
if ($TaskTimeoutSeconds -gt 0) {
    $ArgsList += @("--task-timeout-seconds", "$TaskTimeoutSeconds")
}
if ($RandomMode) {
    $ArgsList += "--random-mode"
}
if ($NoRandomMode) {
    $ArgsList += "--no-random-mode"
}
if ($ArchivesPerSample -gt 0) {
    $ArgsList += @("--archives-per-sample", "$ArchivesPerSample")
}
if ($Seed) {
    $ArgsList += @("--seed", $Seed)
}
if ($NoPretty) {
    $ArgsList += "--no-pretty"
}
if ($ExtraArgs.Count -gt 0) {
    $ArgsList += $ExtraArgs
}

Push-Location $RepoRoot
try {
    & $Python @ArgsList
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
