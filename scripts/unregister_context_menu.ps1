Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$keys = @(
    "HKCU:\Software\Classes\Directory\shell\SmartUnpacker",
    "HKCU:\Software\Classes\Directory\Background\shell\SmartUnpacker",
    "HKCU:\Software\Classes\SmartUnpacker.FolderContextMenu",
    "HKCU:\Software\Classes\SmartUnpacker.BackgroundContextMenu"
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
