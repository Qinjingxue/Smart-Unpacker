[CmdletBinding()]
param(
    [string]$PythonPath = "",
    [string]$BrokerPath = "",
    [switch]$FullAcceptance,
    [string]$BaselinePath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$serviceName = "SunPackWatchBroker"
$unelevatedRunner = Join-Path $repoRoot "scripts\run_unelevated_process.py"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This test installs a real LocalSystem service and must run from an elevated PowerShell."
}
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    throw "Refusing to replace an existing service: $serviceName"
}

if (-not $PythonPath) {
    $PythonPath = Join-Path $repoRoot ".venv\Scripts\python.exe"
}
if (-not $BrokerPath) {
    $BrokerPath = Join-Path $repoRoot "native\target\release\sunpack-watch-broker.exe"
}
if (-not $BaselinePath) {
    $BaselinePath = Join-Path $repoRoot ".sunpack_watch_validation\latest\elevated.json"
}
$PythonPath = [System.IO.Path]::GetFullPath($PythonPath)
$BrokerPath = [System.IO.Path]::GetFullPath($BrokerPath)

if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw "Python executable not found: $PythonPath"
}
if (-not (Test-Path -LiteralPath $unelevatedRunner -PathType Leaf)) {
    throw "Unelevated process runner not found: $unelevatedRunner"
}

function Invoke-UnelevatedPython {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int]$TimeoutSeconds = 600
    )
    $runnerArguments = @(
        $unelevatedRunner,
        "--cwd", $repoRoot,
        "--timeout-seconds", [string]$TimeoutSeconds,
        "--",
        $PythonPath
    ) + $Arguments
    & $PythonPath @runnerArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Unelevated Python command failed with exit code ${LASTEXITCODE}: $($Arguments -join ' ')"
    }
}

& cargo build --locked --manifest-path (Join-Path $repoRoot "native\sunpack_watch_broker\Cargo.toml") --release
if ($LASTEXITCODE -ne 0) {
    throw "Watch Broker release build failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $BrokerPath -PathType Leaf)) {
    throw "Watch Broker executable not found: $BrokerPath"
}

$maturin = Join-Path (Split-Path -Parent $PythonPath) "maturin.exe"
if (-not (Test-Path -LiteralPath $maturin -PathType Leaf)) {
    throw "maturin.exe not found next to the selected Python: $maturin"
}
& $maturin develop --locked --release --manifest-path (Join-Path $repoRoot "native\sunpack_native\Cargo.toml")
if ($LASTEXITCODE -ne 0) {
    throw "sunpack_native development install failed with exit code $LASTEXITCODE"
}

try {
    New-Service `
        -Name $serviceName `
        -BinaryPathName ('"{0}"' -f $BrokerPath) `
        -DisplayName "SunPack Watch Broker (integration test)" `
        -Description "Temporary minimal USN broker installed by the SunPack integration test." `
        -StartupType Manual | Out-Null
    & sc.exe sidtype $serviceName unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set the test service SID type."
    }
    $serviceSddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LCRP;;;IU)"
    & sc.exe sdset $serviceName $serviceSddl | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set the test service DACL."
    }

    $resultRoot = Join-Path $repoRoot ".sunpack_watch_validation\broker"
    New-Item -ItemType Directory -Path $resultRoot -Force | Out-Null
    Invoke-UnelevatedPython -Arguments @(
        "-m", "pytest",
        (Join-Path $repoRoot "tests\integration\test_watch_broker_service.py"),
        "-q",
        ("--junitxml=" + (Join-Path $resultRoot "service-integration.xml"))
    ) -TimeoutSeconds 180

    if ($FullAcceptance) {
        if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
            throw "The direct-USN baseline report is required for strict latency comparison: $BaselinePath"
        }
        Invoke-UnelevatedPython -Arguments @(
            "-m", "pytest",
            (Join-Path $repoRoot "tests\integration\test_watch_ntfs_usn.py"),
            "-q",
            ("--junitxml=" + (Join-Path $resultRoot "ntfs-usn.xml"))
        ) -TimeoutSeconds 300

        Invoke-UnelevatedPython -Arguments @(
            (Join-Path $repoRoot "tests\integration\watch_validation.py"),
            "--output", (Join-Path $resultRoot "broker.json"),
            "--baseline", $BaselinePath
        ) -TimeoutSeconds 600

        Invoke-UnelevatedPython -Arguments @(
            "-m", "pytest",
            (Join-Path $repoRoot "tests\real\plan7_watch_downloads\test_plan7_download_modes.py"),
            (Join-Path $repoRoot "tests\real\plan7_watch_downloads\test_plan7_split_downloads.py"),
            (Join-Path $repoRoot "tests\real\plan7_watch_downloads\test_plan7_arrival_orders.py"),
            (Join-Path $repoRoot "tests\real\plan7_watch_downloads\test_plan7_lifecycle.py"),
            "-q",
            ("--junitxml=" + (Join-Path $resultRoot "plan7-downloads.xml"))
        ) -TimeoutSeconds 900

        Invoke-UnelevatedPython -Arguments @(
            (Join-Path $repoRoot "benchmarks\scenarios\watch_split_arrival.py"),
            "--modes", "shuffle_rename,shuffle_direct,interleaved_rename,interleaved_direct,head_first_rename",
            "--quiet-values", "0,1.25",
            "--runs", "1",
            "--json-out", (Join-Path $resultRoot "split-arrival.json")
        ) -TimeoutSeconds 900
    }

    $deadline = (Get-Date).AddSeconds(10)
    do {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -eq "Stopped") {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    if ($service.Status -ne "Stopped") {
        throw "Watch Broker did not stop after the final client lease was released."
    }
} finally {
    Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $serviceName | Out-Null
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline -and (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
        Start-Sleep -Milliseconds 250
    }
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        throw "Temporary Watch Broker service was not removed: $serviceName"
    }
}

Write-Host "Watch Broker service install/run/uninstall test passed." -ForegroundColor Green
