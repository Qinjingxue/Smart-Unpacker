[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Uninstall")]
    [string]$Action,
    [Parameter(Mandatory = $true)]
    [string]$ServiceName,
    [Parameter(Mandatory = $true)]
    [string]$PipeName,
    [string]$BrokerPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot

. (Join-Path $PSScriptRoot "test_elevation.ps1")
$elevatedExitCode = Invoke-TestScriptElevated -ScriptPath $PSCommandPath -BoundParameters $PSBoundParameters
if ($null -ne $elevatedExitCode) {
    exit $elevatedExitCode
}

if (-not $ServiceName.StartsWith("SunPackWatchBrokerTest_")) {
    throw "Refusing to manage a non-test Watch Broker service identity: $ServiceName"
}
if (-not $PipeName.StartsWith("\\.\pipe\SunPack.WatchBroker.Test.")) {
    throw "Refusing to manage a non-test Watch Broker pipe identity: $PipeName"
}

function Get-TestService {
    return Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Remove-TestService {
    $service = Get-TestService
    if ($null -eq $service) {
        return
    }

    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to delete the temporary Watch Broker service: $ServiceName"
    }

    $deadline = (Get-Date).AddSeconds(30)
    do {
        $service = Get-TestService
        if ($null -eq $service) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ((Get-Date) -lt $deadline)
    throw "Temporary Watch Broker service was not removed: $ServiceName"
}

if ($Action -eq "Uninstall") {
    Remove-TestService
    exit 0
}

if (-not $BrokerPath) {
    throw "BrokerPath is required when installing the temporary Watch Broker service."
}
$BrokerPath = [IO.Path]::GetFullPath($BrokerPath)
if (-not (Test-Path -LiteralPath $BrokerPath -PathType Leaf)) {
    throw "Watch Broker executable not found: $BrokerPath"
}
if ($null -ne (Get-TestService)) {
    throw "Refusing to overwrite an existing Watch Broker service: $ServiceName"
}

$serviceCreated = $false
try {
    $binaryPath = '"{0}" --service-name "{1}" --pipe-name "{2}"' -f $BrokerPath, $ServiceName, $PipeName
    New-Service `
        -Name $ServiceName `
        -BinaryPathName $binaryPath `
        -DisplayName "SunPack Watch Broker (test)" `
        -Description "Temporary Watch Broker service owned by the SunPack acceptance test runner." `
        -StartupType Manual | Out-Null
    $serviceCreated = $true

    & sc.exe sidtype $ServiceName unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set the test service SID type."
    }
    $serviceSddl = "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LCRP;;;IU)"
    & sc.exe sdset $ServiceName $serviceSddl | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set the test service DACL."
    }
} catch {
    if ($serviceCreated) {
        Remove-TestService
    }
    throw
}

Write-Host "Temporary Watch Broker service installed: $ServiceName" -ForegroundColor Green
