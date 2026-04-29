[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackageRoot,
    [ValidateSet("x64", "arm64")]
    [string]$Arch = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Assert-PathExists {
    param(
        [string]$LiteralPath,
        [string]$Description
    )
    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        throw "$Description not found: $LiteralPath"
    }
}

function Get-ExpectedPeMachine {
    param([string]$BuildArch)
    switch ($BuildArch) {
        "x64" { return 0x8664 }
        "arm64" { return 0xAA64 }
    }
    throw "Unsupported architecture: $BuildArch"
}

function Get-PeMachineName {
    param([int]$Machine)
    switch ($Machine) {
        0x014C { return "x86" }
        0x8664 { return "x64" }
        0xAA64 { return "arm64" }
        default { return ("0x{0:X4}" -f $Machine) }
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $stream = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        if ($stream.Length -lt 0x40) {
            throw "File is too small to be a PE image: $LiteralPath"
        }
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) {
                throw "Missing MZ signature: $LiteralPath"
            }
            $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
            $peOffset = $reader.ReadUInt32()
            if ($peOffset + 6 -gt $stream.Length) {
                throw "Invalid PE header offset: $LiteralPath"
            }
            $stream.Seek([int64]$peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
            if ($reader.ReadUInt32() -ne 0x00004550) {
                throw "Missing PE signature: $LiteralPath"
            }
            return [int]$reader.ReadUInt16()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-PeMachine {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$BuildArch,
        [string]$Description = "PE image"
    )

    Assert-PathExists -LiteralPath $LiteralPath -Description $Description
    $expected = Get-ExpectedPeMachine -BuildArch $BuildArch
    $actual = Get-PeMachine -LiteralPath $LiteralPath
    if ($actual -ne $expected) {
        throw ("{0} architecture mismatch: expected {1}, got {2}: {3}" -f $Description, $BuildArch, (Get-PeMachineName -Machine $actual), $LiteralPath)
    }
    Write-Host ("PASS  {0,-42} {1}" -f $Description, $LiteralPath) -ForegroundColor Green
}

$root = (Resolve-Path -LiteralPath $PackageRoot).Path
$nativeExtension = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -like "sunpack_native*.pyd" -or
        $_.Name -like "sunpack_native*.dll"
    } |
    Select-Object -First 1

if ($null -eq $nativeExtension) {
    throw "sunpack_native extension not found under: $root"
}

Assert-PeMachine -LiteralPath (Join-Path $root "sunpack.exe") -BuildArch $Arch -Description "sunpack.exe"
Assert-PeMachine -LiteralPath $nativeExtension.FullName -BuildArch $Arch -Description "sunpack_native extension"
Assert-PeMachine -LiteralPath (Join-Path $root "tools\7z.exe") -BuildArch $Arch -Description "tools\7z.exe"
Assert-PeMachine -LiteralPath (Join-Path $root "tools\7z.dll") -BuildArch $Arch -Description "tools\7z.dll"
Assert-PeMachine -LiteralPath (Join-Path $root "tools\sevenzip_password_tester_capi.dll") -BuildArch $Arch -Description "tools\sevenzip_password_tester_capi.dll"
Assert-PeMachine -LiteralPath (Join-Path $root "tools\sevenzip_worker.exe") -BuildArch $Arch -Description "tools\sevenzip_worker.exe"

Write-Host ""
Write-Host "Package architecture validation passed: $Arch" -ForegroundColor Green
