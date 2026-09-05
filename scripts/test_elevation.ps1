function ConvertTo-PowerShellSingleQuotedLiteral {
    param([Parameter(Mandatory = $true)][string]$Value)

    return "'" + $Value.Replace("'", "''") + "'"
}

function ConvertTo-PowerShellValueLiteral {
    param($Value)

    if ($null -eq $Value) {
        return '$null'
    }
    if ($Value -is [string]) {
        return ConvertTo-PowerShellSingleQuotedLiteral -Value $Value
    }
    if ($Value -is [bool]) {
        return if ($Value) { '$true' } else { '$false' }
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @($Value | ForEach-Object { ConvertTo-PowerShellValueLiteral -Value $_ })
        return '@(' + ($items -join ', ') + ')'
    }
    if ($Value -is [byte] -or $Value -is [sbyte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64] -or
        $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    }
    return ConvertTo-PowerShellSingleQuotedLiteral -Value ([string]$Value)
}

function Invoke-TestScriptElevated {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$BoundParameters
    )

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return $null
    }

    $runningInCi =
        [string]::Equals($env:CI, "true", [StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($env:GITHUB_ACTIONS, "true", [StringComparison]::OrdinalIgnoreCase)
    if ($runningInCi) {
        throw "This test requires an elevated CI runner; interactive UAC relaunch is disabled in CI."
    }

    $commandParts = @("& " + (ConvertTo-PowerShellSingleQuotedLiteral -Value $ScriptPath))
    foreach ($entry in $BoundParameters.GetEnumerator()) {
        $parameterName = [string]$entry.Key
        $parameterValue = $entry.Value
        if ($parameterValue -is [System.Management.Automation.SwitchParameter]) {
            if ($parameterValue.IsPresent) {
                $commandParts += "-$parameterName"
            }
            continue
        }
        $commandParts += "-$parameterName"
        $commandParts += ConvertTo-PowerShellValueLiteral -Value $parameterValue
    }

    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes(($commandParts -join " "))
    )
    $hostPath = (Get-Process -Id $PID).Path
    $process = Start-Process `
        -FilePath $hostPath `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encodedCommand) `
        -WorkingDirectory (Split-Path -Parent $ScriptPath) `
        -Verb RunAs `
        -Wait `
        -PassThru
    return [int]$process.ExitCode
}
