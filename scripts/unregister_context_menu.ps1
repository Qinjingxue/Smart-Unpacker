Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$keys = @(
    "HKCU:\Software\Classes\Directory\shell\PackRelic",
    "HKCU:\Software\Classes\Directory\Background\shell\PackRelic",
    "HKCU:\Software\Classes\PackRelic.FolderContextMenu",
    "HKCU:\Software\Classes\PackRelic.BackgroundContextMenu"
)

foreach ($key in $keys) {
    if (Test-Path -LiteralPath $key) {
        Remove-Item -LiteralPath $key -Recurse -Force
        Write-Host "Removed:" $key
    } else {
        Write-Host "Not found:" $key
    }
}

Write-Host "Context menu unregistration completed." -ForegroundColor Green
