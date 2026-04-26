[CmdletBinding()]
param(
    [switch]$VerboseOutput,
    [switch]$NoWait
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
    foreach ($candidate in @("python", "py")) {
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

function Wait-BeforeExit {
    param([string]$Message = "Press any key to exit...")
    if ($NoWait) {
        return
    }
    Write-Host ""
    Write-Host $Message -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

trap {
    Wait-BeforeExit
    throw
}

$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
$python = if (Test-Path -LiteralPath $venvPython) { $venvPython } else { Get-PythonCommand }
$env:PYTHONPATH = $repoRoot

Invoke-TestStep -Label "Unit tests" -Command @($python, "-m", "pytest", "-q", "tests/unit")
Invoke-TestStep -Label "Functional tests" -Command @($python, "-m", "pytest", "-q", "tests/functional")
Invoke-TestStep -Label "Integration tests" -Command @($python, "-m", "pytest", "-q", "tests/integration")
Invoke-TestStep -Label "CLI contract tests" -Command @($python, "-m", "pytest", "-q", "tests/cli")
Invoke-TestStep -Label "Data case runners" -Command @($python, "-m", "pytest", "-q", "tests/runners")
Invoke-TestStep -Label "CLI help smoke test" -Command @($python, "sunpack_cli.py", "--help")
Invoke-TestStep -Label "CLI passwords smoke test" -Command @($python, "sunpack_cli.py", "passwords", "--json")
Invoke-TestStep -Label "CLI scan smoke test" -Command @($python, "sunpack_cli.py", "scan", (Join-Path $repoRoot "tests"), "--json")
Invoke-TestStep -Label "CLI inspect smoke test" -Command @($python, "sunpack_cli.py", "inspect", (Join-Path $repoRoot "tests"), "--json")
Invoke-TestStep -Label "CLI config smoke test" -Command @($python, "sunpack_cli.py", "config", "--json", "show")

Write-Host ""
Write-Host "Summary" -ForegroundColor Cyan
foreach ($result in $script:StepResults) {
    Write-Host ("  PASS  {0,-40} {1,6:N2}s" -f $result.Label, $result.DurationSeconds) -ForegroundColor Green
}

Write-Host ""
Write-Host "All V2 acceptance tests passed." -ForegroundColor Green
Wait-BeforeExit
