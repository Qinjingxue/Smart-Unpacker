function Get-SunPackFileSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LiteralPath
    )

    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    $stream = $null
    $sha256 = $null
    try {
        $stream = [IO.File]::Open(
            $fullPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        $sha256 = [Security.Cryptography.SHA256]::Create()
        $digest = $sha256.ComputeHash($stream)
        return [BitConverter]::ToString($digest).Replace("-", "").ToLowerInvariant()
    } finally {
        if ($null -ne $sha256) {
            $sha256.Dispose()
        }
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Write-SunPackPowerShellDiagnostics {
    [CmdletBinding()]
    param()

    $process = [Diagnostics.Process]::GetCurrentProcess()
    try {
        $hostPath = $process.MainModule.FileName
    } finally {
        $process.Dispose()
    }
    $fileHashCommand = Get-Command -Name "Get-FileHash" -ErrorAction SilentlyContinue
    $fileHashStatus = if ($null -eq $fileHashCommand) {
        "unavailable (SunPack will use its .NET SHA-256 implementation)"
    } else {
        "available from $($fileHashCommand.Source)"
    }

    [Console]::WriteLine("PowerShell host: {0}", $hostPath)
    [Console]::WriteLine("PowerShell version: {0} ({1})", $PSVersionTable.PSVersion, $PSVersionTable.PSEdition)
    [Console]::WriteLine("Get-FileHash: {0}", $fileHashStatus)
}
