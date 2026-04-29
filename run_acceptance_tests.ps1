[CmdletBinding()]
param(
    [switch]$VerboseOutput,
    [switch]$NoWait,
    [switch]$SkipEnvironmentRefresh
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
        [string[]]$Command
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
        & $Command[0] $argsList
        $exitCode = $LASTEXITCODE
        $duration = ((Get-Date) - $startTime).TotalSeconds
        $script:StepResults += [pscustomobject]@{
            Label = $Label
            ExitCode = $exitCode
            DurationSeconds = [math]::Round($duration, 2)
        }
        if ($exitCode -ne 0) {
            throw "Test step failed: $Label (exit code $exitCode)"
        }
        Write-Host ("    PASS ({0:N2}s)" -f $duration) -ForegroundColor Green
        return
    }

    $stdoutPath = [System.IO.Path]::GetTempFileName()
    $stderrPath = [System.IO.Path]::GetTempFileName()
    try {
        $process = Start-Process -FilePath $Command[0] `
            -ArgumentList $argsList `
            -NoNewWindow `
            -Wait `
            -PassThru `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath

        $exitCode = $process.ExitCode
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
        Write-Host "    Detailed output:" -ForegroundColor Yellow

        foreach ($path in @($stdoutPath, $stderrPath)) {
            if (Test-Path $path) {
                Get-Content $path | ForEach-Object {
                    Write-Host ("      " + $_)
                }
            }
        }
        throw "Test step failed: $Label (exit code $exitCode)"
    } finally {
        Remove-Item -LiteralPath $stdoutPath, $stderrPath -ErrorAction SilentlyContinue
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
    'scan_directory_entries', 'list_regular_files_in_directory',
    'scan_carrier_archive', 'scan_magics_anywhere',
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
    'tar_sparse_pax_longname_repair', 'compression_stream_partial_recovery',
    'compression_stream_trailing_junk_trim', 'tar_compressed_partial_recovery',
    'tar_metadata_downgrade_recovery', 'archive_carrier_crop_recovery',
    'seven_zip_precise_boundary_repair', 'seven_zip_crc_field_repair',
    'seven_zip_next_header_field_repair', 'seven_zip_solid_block_partial_salvage',
    'rar_file_quarantine_rebuild', 'archive_nested_payload_salvage',
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
    & $PythonPath -c "import importlib.util, sys; modules = [$importList]; missing = [name for name in modules if importlib.util.find_spec(name) is None]; sys.exit(0 if not missing else 1)" *> $null
    return ($LASTEXITCODE -eq 0)
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

    if (-not (Test-PythonImports -PythonPath $VenvPython -Modules @("pytest", "psutil", "send2trash", "watchdog", "zstandard"))) {
        $reasons.Add(".venv is missing runtime/test modules")
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
        (Join-Path $toolsRoot "7z.dll"),
        (Join-Path $toolsRoot "sevenzip_password_tester_capi.dll"),
        (Join-Path $toolsRoot "sevenzip_worker.exe")
    )
    foreach ($toolPath in $requiredTools) {
        if (-not (Test-Path -LiteralPath $toolPath)) {
            $reasons.Add("required runtime tool is missing: $toolPath")
        }
    }
    if ($requiredTools | Where-Object { -not (Test-Path -LiteralPath $_) }) {
        return $reasons
    }

    $wrapperRoot = Join-Path $RepoRoot "native\sevenzip_password_tester"
    $wrapperSourceNewest = Get-NewestSourceWriteTime -Root $wrapperRoot -Include @("*.cpp", "*.h", "*.hpp", "CMakeLists.txt")
    $wrapperOldest = Get-OldestExistingWriteTime -Paths @(
        (Join-Path $toolsRoot "sevenzip_password_tester_capi.dll"),
        (Join-Path $toolsRoot "sevenzip_worker.exe")
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
        "-File", (Join-Path $RepoRoot "scripts\setup_windows_dev.ps1")
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
$python = if (Test-Path -LiteralPath $venvPython) { $venvPython } else { Get-PythonCommand }
$env:PYTHONPATH = $repoRoot

Invoke-TestStep -Label "Unit tests" -Command @($python, "-m", "pytest", "-q", "tests/unit")
Invoke-TestStep -Label "Functional tests" -Command @($python, "-m", "pytest", "-q", "tests/functional")
Invoke-TestStep -Label "CLI contract tests" -Command @($python, "-m", "pytest", "-q", "tests/cli")
Invoke-TestStep -Label "Data case runners" -Command @($python, "-m", "pytest", "-q", "tests/runners")
Invoke-TestStep -Label "Split archive repair regressions" -Command @($python, "tests\performance_split_archives\split_archive_pressure.py", "--profile", "acceptance-batch", "--formats", "7z,rar", "--strict", "--no-json")
Invoke-TestStep -Label "Archive mixed-batch acceptance" -Command @($python, "tests\performance_split_archives\split_archive_pressure.py", "--profile", "acceptance-batch", "--strict", "--no-json")
Invoke-TestStep -Label "CLI help smoke test" -Command @($python, "sunpack.py", "--help")
Invoke-TestStep -Label "CLI passwords smoke test" -Command @($python, "sunpack.py", "passwords", "--json")
Invoke-TestStep -Label "CLI scan smoke test" -Command @($python, "sunpack.py", "scan", (Join-Path $repoRoot "tests"), "--json")
Invoke-TestStep -Label "CLI inspect smoke test" -Command @($python, "sunpack.py", "inspect", (Join-Path $repoRoot "tests"), "--json")
Invoke-TestStep -Label "CLI config smoke test" -Command @($python, "sunpack.py", "config", "--json", "show")

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
foreach ($result in $script:StepResults) {
    Write-Host ("  PASS  {0,-40} {1,6:N2}s" -f $result.Label, $result.DurationSeconds) -ForegroundColor Green
}

Write-Host ""
Write-Host "All V2 acceptance tests passed." -ForegroundColor Green
Wait-BeforeExit
