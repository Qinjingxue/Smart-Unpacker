[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("pytest", "benchmark", "acceptance", "service-suite")]
    [string]$Mode,
    [string[]]$Arguments = @(),
    [string]$ArgumentsBase64 = "",
    [string]$PythonPath = "",
    [string]$BrokerPath = "",
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64",
    [switch]$SkipBuild,
    [switch]$FullAcceptance,
    [string]$BaselinePath = "",
    [ValidateRange(0, 32)]
    [int]$ParallelWorkers = 0,
    [int]$TimeoutSeconds = 900
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

if ($ParallelWorkers -le 0) {
    $ParallelWorkers = [math]::Max(1, [math]::Floor([Environment]::ProcessorCount / 4))
}

. (Join-Path $PSScriptRoot "test_elevation.ps1")
$elevatedExitCode = Invoke-TestScriptElevated -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
if ($null -ne $elevatedExitCode) {
    exit $elevatedExitCode
}

if ($ArgumentsBase64) {
    if ($Arguments.Count -gt 0) {
        throw "Use either -Arguments or -ArgumentsBase64, not both."
    }
    $argumentsJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ArgumentsBase64))
    $Arguments = @((ConvertFrom-Json -InputObject $argumentsJson))
}

if (-not $PythonPath) {
    $PythonPath = Join-Path $repoRoot ".venv\Scripts\python.exe"
}
$PythonPath = [IO.Path]::GetFullPath($PythonPath)
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
    throw "Python executable not found: $PythonPath"
}

$brokerManifest = Join-Path $repoRoot "native\sunpack_watch_broker\Cargo.toml"
$nativeManifest = Join-Path $repoRoot "native\sunpack_native\Cargo.toml"
if (-not $SkipBuild) {
    & cargo build --locked --manifest-path $brokerManifest --release
    if ($LASTEXITCODE -ne 0) {
        throw "Watch Broker release build failed with exit code $LASTEXITCODE"
    }
    $maturin = Join-Path (Split-Path -Parent $PythonPath) "maturin.exe"
    if (-not (Test-Path -LiteralPath $maturin -PathType Leaf)) {
        throw "maturin.exe not found next to the selected Python: $maturin"
    }
    & $maturin develop --locked --release --manifest-path $nativeManifest
    if ($LASTEXITCODE -ne 0) {
        throw "sunpack_native development install failed with exit code $LASTEXITCODE"
    }
}

if (-not $BrokerPath) {
    $rustTarget = if ($Arch -eq "arm64") { "aarch64-pc-windows-msvc" } else { "x86_64-pc-windows-msvc" }
    $cachedBroker = Join-Path $repoRoot (".cache\rust-target\{0}\{1}\release\sunpack-watch-broker.exe" -f $Arch, $rustTarget)
    $defaultBroker = Join-Path $repoRoot "native\target\release\sunpack-watch-broker.exe"
    $BrokerPath = if (-not $SkipBuild) {
        $defaultBroker
    } elseif (Test-Path -LiteralPath $cachedBroker -PathType Leaf) {
        $cachedBroker
    } else {
        $defaultBroker
    }
}
$BrokerPath = [IO.Path]::GetFullPath($BrokerPath)
if (-not (Test-Path -LiteralPath $BrokerPath -PathType Leaf)) {
    throw "Watch Broker executable not found: $BrokerPath"
}

$runId = [guid]::NewGuid().ToString("N")
$serviceName = "SunPackWatchBrokerTest_$runId"
$pipeName = "\\.\pipe\SunPack.WatchBroker.Test.$runId"
if ($serviceName -eq "SunPackWatchBroker" -or -not $serviceName.StartsWith("SunPackWatchBrokerTest_")) {
    throw "Refusing to provision a non-test Watch Broker service identity: $serviceName"
}
$unelevatedRunner = Join-Path $repoRoot "scripts\run_unelevated_process.py"
$resultRoot = Join-Path $repoRoot ".sunpack_watch_validation\broker"
$serviceCreated = $false
$commandExitCode = 0

function Invoke-OrdinaryPython {
    param(
        [Parameter(Mandatory = $true)][string[]]$PythonArguments,
        [int]$CommandTimeoutSeconds = $TimeoutSeconds
    )
    $runnerArguments = @(
        $unelevatedRunner,
        "--cwd", $repoRoot,
        "--timeout-seconds", [string][Math]::Max(1, $CommandTimeoutSeconds),
        "--env", ("SUNPACK_WATCH_BROKER_SERVICE_NAME=" + $env:SUNPACK_WATCH_BROKER_SERVICE_NAME),
        "--env", ("SUNPACK_WATCH_BROKER_PIPE_NAME=" + $env:SUNPACK_WATCH_BROKER_PIPE_NAME),
        "--env", ("SUNPACK_WATCH_BROKER_BINARY_PATH=" + $env:SUNPACK_WATCH_BROKER_BINARY_PATH),
        "--env", ("SUNPACK_WATCH_BROKER_BINARY_SHA256=" + $env:SUNPACK_WATCH_BROKER_BINARY_SHA256),
        "--",
        $PythonPath
    ) + $PythonArguments
    # Keep child output visible without mixing it into the function's return
    # value. Assigning this function's result must yield exactly one exit code.
    & $PythonPath @runnerArguments | Out-Host
    $exitCode = [int]$LASTEXITCODE
    return $exitCode
}

function Assert-CommandSucceeded {
    param(
        [Parameter(Mandatory = $true)][int]$ExitCode,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if ($ExitCode -ne 0) {
        throw "$Description failed with exit code $ExitCode"
    }
}

function Assert-PytestReportComplete {
    param(
        [Parameter(Mandatory = $true)][string]$ReportPath,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) {
        throw "$Description did not produce a JUnit report: $ReportPath"
    }
    [xml]$report = Get-Content -LiteralPath $ReportPath -Raw
    $suites = @($report.SelectNodes("//testsuite"))
    $testCount = [int](($suites | Measure-Object -Property tests -Sum).Sum)
    $skippedCount = [int](($suites | Measure-Object -Property skipped -Sum).Sum)
    if ($testCount -lt 1) {
        throw "$Description collected no correctness tests"
    }
    if ($skippedCount -ne 0) {
        throw "$Description skipped $skippedCount of $testCount correctness tests"
    }
}

try {
    $binaryPath = '"{0}" --service-name "{1}" --pipe-name "{2}"' -f $BrokerPath, $serviceName, $pipeName
    New-Service `
        -Name $serviceName `
        -BinaryPathName $binaryPath `
        -DisplayName "SunPack Watch Broker (test $runId)" `
        -Description "Ephemeral isolated Watch Broker owned by the SunPack test runner." `
        -StartupType Manual | Out-Null
    $serviceCreated = $true
    & sc.exe sidtype $serviceName unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set the test service SID type."
    }
    $serviceSddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LCRP;;;IU)"
    & sc.exe sdset $serviceName $serviceSddl | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set the test service DACL."
    }

    $env:SUNPACK_WATCH_BROKER_SERVICE_NAME = $serviceName
    $env:SUNPACK_WATCH_BROKER_PIPE_NAME = $pipeName
    $env:SUNPACK_WATCH_BROKER_BINARY_PATH = $BrokerPath
    $env:SUNPACK_WATCH_BROKER_BINARY_SHA256 = (Get-FileHash -LiteralPath $BrokerPath -Algorithm SHA256).Hash.ToLowerInvariant()

    New-Item -ItemType Directory -Path $resultRoot -Force | Out-Null
    switch ($Mode) {
        "pytest" {
            $commandExitCode = Invoke-OrdinaryPython -PythonArguments (@("-m", "pytest") + $Arguments)
        }
        "benchmark" {
            $commandExitCode = Invoke-OrdinaryPython -PythonArguments (@("-m", "benchmarks") + $Arguments)
        }
        "acceptance" {
            $integrationParallelReport = Join-Path $resultRoot "acceptance-integration-parallel.xml"
            $integrationParallel = Invoke-OrdinaryPython -PythonArguments @(
                "-m", "pytest", "-q",
                "-n", [string]$ParallelWorkers, "--dist", "worksteal",
                "-m", "not requires_watch_broker", "tests/integration", "--durations=20",
                ("--junitxml=" + $integrationParallelReport)
            )
            Assert-CommandSucceeded -ExitCode $integrationParallel -Description "Parallel integration tests"
            Assert-PytestReportComplete -ReportPath $integrationParallelReport -Description "Parallel integration tests"
            $integrationBrokerReport = Join-Path $resultRoot "acceptance-integration-broker.xml"
            $integrationBroker = Invoke-OrdinaryPython -PythonArguments @(
                "-m", "pytest", "-q", "-n", "0",
                "-m", "requires_watch_broker", "tests/integration", "--durations=20",
                ("--junitxml=" + $integrationBrokerReport)
            )
            Assert-CommandSucceeded -ExitCode $integrationBroker -Description "Broker integration tests"
            Assert-PytestReportComplete -ReportPath $integrationBrokerReport -Description "Broker integration tests"
            $realParallelReport = Join-Path $resultRoot "acceptance-real-parallel.xml"
            $realParallel = Invoke-OrdinaryPython -PythonArguments @(
                "-m", "pytest", "-q",
                "-n", [string]$ParallelWorkers, "--dist", "worksteal",
                "-m", "not requires_watch_broker", "tests/real", "--durations=20",
                ("--junitxml=" + $realParallelReport)
            )
            Assert-CommandSucceeded -ExitCode $realParallel -Description "Parallel real archive tests"
            Assert-PytestReportComplete -ReportPath $realParallelReport -Description "Parallel real archive tests"
            $realWatchReport = Join-Path $resultRoot "acceptance-real-watch.xml"
            $commandExitCode = Invoke-OrdinaryPython -PythonArguments @(
                "-m", "pytest", "-q", "-n", "0",
                "tests/real/plan7_watch_downloads", "--durations=20",
                ("--junitxml=" + $realWatchReport)
            )
            Assert-CommandSucceeded -ExitCode $commandExitCode -Description "Real watch tests"
            Assert-PytestReportComplete -ReportPath $realWatchReport -Description "Real watch tests"
        }
        "service-suite" {
            $serviceTests = Invoke-OrdinaryPython -PythonArguments @(
                "-m", "pytest", (Join-Path $repoRoot "tests\integration\test_watch_broker_service.py"), "-q",
                ("--junitxml=" + (Join-Path $resultRoot "service-integration.xml"))
            ) -CommandTimeoutSeconds 180
            Assert-CommandSucceeded -ExitCode $serviceTests -Description "Watch Broker integration tests"
            if ($FullAcceptance) {
                if (-not $BaselinePath) {
                    $BaselinePath = Join-Path $repoRoot ".sunpack_watch_validation\latest\elevated.json"
                }
                if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
                    throw "The direct-USN baseline report is required: $BaselinePath"
                }
                $ntfsTests = Invoke-OrdinaryPython -PythonArguments @(
                    "-m", "pytest", (Join-Path $repoRoot "tests\integration\test_watch_ntfs_usn.py"), "-q",
                    ("--junitxml=" + (Join-Path $resultRoot "ntfs-usn.xml"))
                ) -CommandTimeoutSeconds 300
                Assert-CommandSucceeded -ExitCode $ntfsTests -Description "NTFS USN tests"
                $validation = Invoke-OrdinaryPython -PythonArguments @(
                    (Join-Path $repoRoot "tests\integration\watch_validation.py"),
                    "--transport", "broker",
                    "--output", (Join-Path $resultRoot "broker.json"),
                    "--baseline", $BaselinePath
                ) -CommandTimeoutSeconds 600
                Assert-CommandSucceeded -ExitCode $validation -Description "Watch validation"
                $plan7 = Invoke-OrdinaryPython -PythonArguments @(
                    "-m", "pytest", (Join-Path $repoRoot "tests\real\plan7_watch_downloads"), "-q",
                    ("--junitxml=" + (Join-Path $resultRoot "plan7-downloads.xml"))
                ) -CommandTimeoutSeconds 900
                Assert-CommandSucceeded -ExitCode $plan7 -Description "Plan 7 watch tests"
                $commandExitCode = Invoke-OrdinaryPython -PythonArguments @(
                    "-m", "benchmarks", "watch", "split-arrival",
                    "--modes", "shuffle_rename,shuffle_direct,interleaved_rename,interleaved_direct,head_first_rename",
                    "--quiet-values", "0,1.25", "--runs", "1",
                    "--json-out", (Join-Path $resultRoot "split-arrival.json")
                ) -CommandTimeoutSeconds 900
            }
        }
    }
    Assert-CommandSucceeded -ExitCode $commandExitCode -Description "Watch test command"
} finally {
    Remove-Item Env:SUNPACK_WATCH_BROKER_SERVICE_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:SUNPACK_WATCH_BROKER_PIPE_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:SUNPACK_WATCH_BROKER_BINARY_PATH -ErrorAction SilentlyContinue
    Remove-Item Env:SUNPACK_WATCH_BROKER_BINARY_SHA256 -ErrorAction SilentlyContinue
    if ($serviceCreated) {
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
}

Write-Host "Watch test run passed with isolated service $serviceName." -ForegroundColor Green
