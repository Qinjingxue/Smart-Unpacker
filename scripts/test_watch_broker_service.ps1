[CmdletBinding()]
param(
    [string]$PythonPath = "",
    [string]$BrokerPath = "",
    [switch]$FullAcceptance,
    [string]$BaselinePath = ""
)

$ErrorActionPreference = "Stop"
$runner = Join-Path $PSScriptRoot "run_watch_tests.ps1"
$arguments = @{
    Mode = "service-suite"
    FullAcceptance = $FullAcceptance
}
if ($PythonPath) {
    $arguments.PythonPath = $PythonPath
}
if ($BrokerPath) {
    $arguments.BrokerPath = $BrokerPath
}
if ($BaselinePath) {
    $arguments.BaselinePath = $BaselinePath
}

& $runner @arguments
exit $LASTEXITCODE
