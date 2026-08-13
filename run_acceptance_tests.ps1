[CmdletBinding()]
param(
    [switch]$VerboseOutput,
    [switch]$NoWait,
    [switch]$SkipEnvironmentRefresh,
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [ValidateSet("full", "lite")]
    [string]$RepairSystem = "full",
    [int]$StepTimeoutSeconds = 900
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

$script:StepResults = @()

function Invoke-TestStep {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,
        [Parameter(Mandatory = $true)]
        [string[]]$Command,
        [int]$TimeoutSeconds = $StepTimeoutSeconds
    )

    Write-Host ""
    Write-Host "==> $Label" -ForegroundColor Cyan

    $argsList = @()
    if ($Command.Length -gt 1) {
        $argsList = $Command[1..($Command.Length - 1)]
    }

    $startTime = Get-Date
    $joinedCommand = $Command -join " "

    if ($VerboseOutput) {
        Write-Host ("    " + $joinedCommand) -ForegroundColor DarkGray
    }
    Write-Host ("    " + $joinedCommand) -ForegroundColor DarkGray

    $process = $null
    try {
        $process = Start-Process -FilePath $Command[0] `
            -ArgumentList $argsList `
            -NoNewWindow `
            -PassThru

        $timeoutMs = [Math]::Max(1, $TimeoutSeconds) * 1000
        if (-not $process.WaitForExit($timeoutMs)) {
            try {
                $process.Kill($true)
            } catch {
                $process.Kill()
            }
            $duration = ((Get-Date) - $startTime).TotalSeconds
            $script:StepResults += [pscustomobject]@{
                Label = $Label
                ExitCode = -1
                DurationSeconds = [math]::Round($duration, 2)
            }
            Write-Host ("    FAIL ({0:N2}s) - timed out after {1} seconds" -f $duration, $TimeoutSeconds) -ForegroundColor Red
            Write-Host ("    Command: " + $joinedCommand) -ForegroundColor DarkGray
            return
        }

        $exitCode = [int]$process.ExitCode
        $duration = ((Get-Date) - $startTime).TotalSeconds
        $script:StepResults += [pscustomobject]@{
            Label = $Label
            ExitCode = $exitCode
            DurationSeconds = [math]::Round($duration, 2)
        }

        if ($exitCode -eq 0) {
            Write-Host ("    PASS ({0:N2}s)" -f $duration) -ForegroundColor Green
            return
        }

        Write-Host ("    FAIL ({0:N2}s)" -f $duration) -ForegroundColor Red
        Write-Host ("    Command: " + $joinedCommand) -ForegroundColor DarkGray
        return
    } finally {
        if ($process) {
            $process.Dispose()
        }
    }
}

function Get-PythonCommand {
    foreach ($candidate in @("python", "py")) {
        try {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        } catch {
        }
    }
    throw "Python interpreter not found in PATH."
}

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        $joined = ($Arguments | ForEach-Object { $_ }) -join " "
        throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $joined"
    }
}

function Get-NativeSmokeCode {
    return @"
import sunpack_native as n
required = [
    'native_available', 'scanner_version',
    'scan_directory_snapshot', 'scan_directory_snapshots',
    'directory_snapshot_from_columns', 'filter_inventory_file_indices',
    'batch_file_head_facts', 'authorize_nested_candidates',
    'relations_build_candidate_groups_from_snapshot',
    'profile_directory_scan', 'list_regular_files_in_directory',
    'scan_embedded_archives', 'scan_magics_anywhere',
    'scan_zip_central_directory_names', 'inspect_zip_eocd_structure',
    'inspect_pe_overlay_structure',
    'repair_read_file_range', 'repair_concat_ranges_to_bytes',
    'repair_write_candidate', 'repair_copy_range_to_file',
    'repair_concat_ranges_to_file', 'repair_patch_file',
    'archive_state_to_bytes_native', 'archive_state_size_native',
    'archive_state_write_to_file_native', 'archive_state_zip_manifest_native',
    'zip_deep_partial_recovery', 'zip_rebuild_from_local_headers',
    'zip_directory_field_repair', 'zip_conflict_resolver_rebuild',
    'gzip_footer_fix_repair', 'gzip_deflate_member_resync_repair',
    'zstd_frame_salvage_repair', 'tar_boundary_repair',
    'compression_stream_partial_recovery',
    'compression_stream_trailing_junk_trim', 'tar_compressed_partial_recovery',
    'archive_carrier_crop_recovery',
    'seven_zip_scan_source', 'seven_zip_atomic_repair',
    'archive_nested_payload_salvage',
    'rar_block_chain_trim_recovery', 'rar_end_block_repair',
]
assert n.native_available()
missing = [name for name in required if not callable(getattr(n, name, None))]
assert not missing, missing
"@
}

function Test-PythonImports {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string[]]$Modules
    )

    $importList = ($Modules | ForEach-Object { "'$_'" }) -join ", "
    & $PythonPath -c "import importlib; modules = [$importList]; [importlib.import_module(name) for name in modules]" *> $null
    return ($LASTEXITCODE -eq 0)
}

function Get-AcceptanceTestToolRequirements {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $testToolsRoot = Join-Path $RepoRoot ".sunpack_test_tools"
    $rarRoot = Join-Path $testToolsRoot "winrar"
    $zstdRoot = Join-Path $testToolsRoot "zstd"
    return @(
        [pscustomobject]@{
            Path = Join-Path $rarRoot "Rar.exe"
            Description = "RAR archive generator"
            Arguments = @()
        },
        [pscustomobject]@{
            Path = Join-Path $rarRoot "Default.SFX"
            Description = "RAR SFX module"
            Arguments = $null
        },
        [pscustomobject]@{
            Path = Join-Path $rarRoot "WinRAR.exe"
            Description = "WinRAR archive generator"
            Arguments = $null
        },
        [pscustomobject]@{
            Path = Join-Path $zstdRoot "zstd.exe"
            Description = "zstd stream generator"
            Arguments = @("--version")
        }
    )
}

function Test-AcceptanceTestToolRuns {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string[]]$Arguments = @()
    )

    try {
        & $Path @Arguments *> $null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Test-AcceptanceRarGeneratorVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [string]$RequiredVersion = "6.22"
    )

    try {
        $output = (& $Path "iver" 2>&1 | Out-String)
        # Rar.exe returns exit code 7 for the informational iver command.
        return ($output -match ("RAR " + [regex]::Escape($RequiredVersion) + " x64"))
    } catch {
        return $false
    }
}

function Assert-AcceptanceTestTools {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot
    )

    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($tool in @(Get-AcceptanceTestToolRequirements -RepoRoot $RepoRoot)) {
        if (-not (Test-Path -LiteralPath $tool.Path -PathType Leaf)) {
            $missing.Add("$($tool.Description): $($tool.Path)")
            continue
        }
        if ($tool.Description -eq "RAR archive generator" -and
            -not (Test-AcceptanceRarGeneratorVersion -Path $tool.Path)) {
            $missing.Add("$($tool.Description) must be WinRAR 6.22 x64 for RAR4 fixtures: $($tool.Path)")
        } elseif ($null -ne $tool.Arguments -and
            -not (Test-AcceptanceTestToolRuns -Path $tool.Path -Arguments $tool.Arguments)) {
            $missing.Add("$($tool.Description) is not executable: $($tool.Path)")
        }
    }
    if ($missing.Count -gt 0) {
        throw (
            "Acceptance test generator tools are incomplete:`n  - " +
            ($missing -join "`n  - ") +
            "`nRun scripts\setup_windows_dev.ps1 on a Windows x64 environment or configure the test tool paths."
        )
    }
    Write-Host "    Acceptance generator tools are present and executable." -ForegroundColor Green
}

function Get-ModuleOrigin {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonPath,
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )

    try {
        $origin = & $PythonPath -c "import importlib.util; spec = importlib.util.find_spec('$ModuleName'); print(spec.origin if spec and spec.origin else '')" 2>$null
        if ($LASTEXITCODE -ne 0) {
            return ""
        }
        return (($origin | Out-String).Trim())
    } catch {
        return ""
    }
}

function Get-NewestSourceWriteTime {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $true)]
        [string[]]$Include
    )

    $files = @()
    foreach ($pattern in $Include) {
        $files += Get-ChildItem -LiteralPath $Root -Filter $pattern -Recurse -File -ErrorAction SilentlyContinue
    }
    if (-not $files) {
        return [datetime]::MinValue
    }
    return ($files | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1).LastWriteTimeUtc
}

function Get-OldestExistingWriteTime {
    param([string[]]$Paths)

    $files = @($Paths | Where-Object { Test-Path -LiteralPath $_ } | ForEach-Object { Get-Item -LiteralPath $_ })
    if ($files.Count -eq 0) {
        return [datetime]::MinValue
    }
    return ($files | Sort-Object LastWriteTimeUtc | Select-Object -First 1).LastWriteTimeUtc
}

function Get-EnvironmentRefreshReasons {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$VenvPython
    )

    $reasons = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path -LiteralPath $VenvPython)) {
        $reasons.Add(".venv is missing")
        return $reasons
    }

    $requiredPythonModules = @(
        "pytest",
        "psutil",
        "send2trash",
        "watchdog",
        "zstandard",
        "torch",
        "torch_geometric",
        "numpy"
    )
    if (-not (Test-PythonImports -PythonPath $VenvPython -Modules $requiredPythonModules)) {
        $reasons.Add(".venv is missing or cannot import runtime, test, or model modules")
    }

    & $VenvPython -c (Get-NativeSmokeCode) *> $null
    if ($LASTEXITCODE -ne 0) {
        $reasons.Add("sunpack_native is missing new native repair APIs")
    }

    $nativeOrigin = Get-ModuleOrigin -PythonPath $VenvPython -ModuleName "sunpack_native"
    if (-not $nativeOrigin -or -not (Test-Path -LiteralPath $nativeOrigin)) {
        $reasons.Add("sunpack_native is not importable from .venv")
    } else {
        $nativeSourceRoot = Join-Path $RepoRoot "native\sunpack_native"
        $nativeSourceNewest = Get-NewestSourceWriteTime -Root $nativeSourceRoot -Include @("*.rs", "Cargo.toml", "Cargo.lock")
        $nativeInstalledTime = (Get-Item -LiteralPath $nativeOrigin).LastWriteTimeUtc
        if ($nativeInstalledTime -lt $nativeSourceNewest) {
            $reasons.Add("installed sunpack_native is older than Rust sources")
        }
    }

    $toolsRoot = Join-Path $RepoRoot "tools"
    $requiredTools = @(
        (Join-Path $toolsRoot "7z.exe"),
        (Join-Path $toolsRoot "7zCon.sfx"),
        (Join-Path $toolsRoot "7z.dll"),
        (Join-Path $toolsRoot "sunpack_sevenzip.dll"),
        (Join-Path $toolsRoot "sunpack_sevenzip_worker.exe")
    )
    foreach ($toolPath in $requiredTools) {
        if (-not (Test-Path -LiteralPath $toolPath)) {
            $reasons.Add("required runtime tool is missing: $toolPath")
        }
    }
    foreach ($tool in @(Get-AcceptanceTestToolRequirements -RepoRoot $RepoRoot)) {
        if (-not (Test-Path -LiteralPath $tool.Path -PathType Leaf)) {
            $reasons.Add("acceptance test generator is missing: $($tool.Path)")
        } elseif ($tool.Description -eq "RAR archive generator" -and
            -not (Test-AcceptanceRarGeneratorVersion -Path $tool.Path)) {
            $reasons.Add("acceptance RAR generator must be WinRAR 6.22 x64: $($tool.Path)")
        } elseif ($null -ne $tool.Arguments -and
            -not (Test-AcceptanceTestToolRuns -Path $tool.Path -Arguments $tool.Arguments)) {
            $reasons.Add("acceptance test generator cannot run: $($tool.Path)")
        }
    }
    if ($requiredTools | Where-Object { -not (Test-Path -LiteralPath $_) }) {
        return $reasons
    }

    $wrapperRoot = Join-Path $RepoRoot "native\sevenzip_bridge"
    $wrapperSourceNewest = Get-NewestSourceWriteTime -Root $wrapperRoot -Include @("*.cpp", "*.h", "*.hpp", "CMakeLists.txt")
    $wrapperOldest = Get-OldestExistingWriteTime -Paths @(
        (Join-Path $toolsRoot "sunpack_sevenzip.dll"),
        (Join-Path $toolsRoot "sunpack_sevenzip_worker.exe")
    )
    if ($wrapperOldest -lt $wrapperSourceNewest) {
        $reasons.Add("7z wrapper tools are older than C++ sources")
    }

    return $reasons
}

function Ensure-AcceptanceEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,
        [Parameter(Mandatory = $true)]
        [string]$VenvPython
    )

    if ($SkipEnvironmentRefresh) {
        Write-Host "Skipping acceptance environment refresh by request." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "==> Acceptance environment preflight" -ForegroundColor Cyan
    if ($env:OS -ne "Windows_NT") {
        throw "This acceptance script only supports Windows."
    }

    $reasons = @(Get-EnvironmentRefreshReasons -RepoRoot $RepoRoot -VenvPython $VenvPython)
    if ($reasons.Count -eq 0) {
        Write-Host "    Environment is current." -ForegroundColor Green
        return
    }

    Write-Host "    Environment refresh required:" -ForegroundColor Yellow
    foreach ($reason in $reasons) {
        Write-Host "      - $reason" -ForegroundColor Yellow
    }
    Invoke-Native -FilePath "powershell" -Arguments @(
        "-ExecutionPolicy", "Bypass",
        "-File", (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1"),
        "-Arch", $Arch,
        "-RepairSystem", $RepairSystem
    )
}

function Wait-BeforeExit {
    param([string]$Message = "Press any key to exit...")
    if ($NoWait) {
        return
    }
    Write-Host ""
    Write-Host $Message -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

trap {
    Wait-BeforeExit
    throw
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
Ensure-AcceptanceEnvironment -RepoRoot $repoRoot -VenvPython $venvPython
Assert-AcceptanceTestTools -RepoRoot $repoRoot
$python = if (Test-Path -LiteralPath $venvPython) { $venvPython } else { Get-PythonCommand }
$env:PYTHONPATH = $repoRoot

Invoke-TestStep -Label "CLI contract tests" -Command @($python, "-m", "pytest", "-q", "tests/cli", "--durations=20")
Invoke-TestStep -Label "Unit tests" -Command @($python, "-m", "pytest", "-q", "tests/unit", "--durations=20")
Invoke-TestStep -Label "Functional tests" -Command @($python, "-m", "pytest", "-q", "tests/functional", "--durations=20")
Invoke-TestStep -Label "Integration tests" -Command @($python, "-m", "pytest", "-q", "tests/integration", "--durations=20")
Invoke-TestStep -Label "Full real archive and watch matrix" -Command @($python, "-m", "pytest", "-q", "tests/real", "--durations=20")
Invoke-TestStep -Label "CLI help smoke test" -Command @($python, "sunpack.py", "--help")
Invoke-TestStep -Label "CLI passwords smoke test" -Command @($python, "sunpack.py", "passwords", "--json")
Invoke-TestStep -Label "CLI scan smoke test" -Command @($python, "sunpack.py", "scan", (Join-Path $repoRoot "tests"), "--json")
Invoke-TestStep -Label "CLI inspect smoke test" -Command @($python, "sunpack.py", "inspect", (Join-Path $repoRoot "tests"), "--json")
Invoke-TestStep -Label "CLI config smoke test" -Command @($python, "sunpack.py", "config", "--json", "show")

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
foreach ($result in $script:StepResults) {
    if ($result.ExitCode -eq 0) {
        Write-Host ("  PASS  {0,-40} {1,6:N2}s" -f $result.Label, $result.DurationSeconds) -ForegroundColor Green
    } else {
        Write-Host ("  FAIL  {0,-40} {1,6:N2}s (exit {2})" -f $result.Label, $result.DurationSeconds, $result.ExitCode) -ForegroundColor Red
    }
}

Write-Host ""
$failedResults = @($script:StepResults | Where-Object { $_.ExitCode -ne 0 })
if ($failedResults.Count -gt 0) {
    Write-Host ("{0} acceptance test step(s) failed; all scheduled steps have completed." -f $failedResults.Count) -ForegroundColor Red
} else {
    Write-Host "All acceptance tests passed." -ForegroundColor Green
}
if (-not $NoWait) {
    if ($failedResults.Count -gt 0) {
        Wait-BeforeExit ("{0} acceptance test step(s) failed. Press any key to exit..." -f $failedResults.Count)
    } else {
        Wait-BeforeExit
    }
}
if ($failedResults.Count -gt 0) {
    exit 1
}
