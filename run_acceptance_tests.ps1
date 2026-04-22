[CmdletBinding()]
param(
    [switch]$VerboseOutput
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
    $candidates = @("python", "py")
    foreach ($candidate in $candidates) {
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

$python = Get-PythonCommand

Invoke-TestStep -Label "CLI unit tests" -Command @($python, "-m", "unittest", "tests.cli_unit_test")
Invoke-TestStep -Label "Module unit tests" -Command @($python, "-m", "unittest", "tests.module_unit_test")
Invoke-TestStep -Label "Edge case acceptance tests" -Command @($python, "tests/edge_cases_test.py")
Invoke-TestStep -Label "Relationship grouping acceptance tests" -Command @($python, "tests/relationship_grouping_test.py")
Invoke-TestStep -Label "RPG Maker semantic acceptance test" -Command @($python, "tests/rpgmaker_semantic_test.py")
Invoke-TestStep -Label "Disguised detection profiling test" -Command @($python, "tests/disguised_detection_profile_test.py", "fixtures")

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
foreach ($result in $script:StepResults) {
    Write-Host ("  PASS  {0,-40} {1,6:N2}s" -f $result.Label, $result.DurationSeconds) -ForegroundColor Green
}
Write-Host ""
Write-Host "All logic acceptance tests passed." -ForegroundColor Green
