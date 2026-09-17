<#
.SYNOPSIS
    Configure, start, and verify the Veloce agent on Windows.

.DESCRIPTION
    Windows counterpart of installer/linux/veloce-fire-up. Works from an
    extracted runtime bundle (bin\ and lib\ beside this script's parent) and
    from the portable desktop payload (_internal\bin and _internal\lib).

    Writes %LOCALAPPDATA%\Lightrider\Veloce\agent.json pointing the agent at
    the hash-recorded FIPS module and PQC provider named by their build
    records, starts bin\veloce-agent.exe on the named pipe
    \\.\pipe\LightRider.PQC.v1, then prints `veloce --json status` and
    `veloce --json self-test`. EMS stays disabled (zero network traffic).

.PARAMETER Stop
    Stop the agent recorded in agent.pid instead of starting one.
#>
[CmdletBinding()]
param(
    [switch]$Stop
)

$ErrorActionPreference = "Stop"
$PipeName = "LightRider.PQC.v1"
$Pipe = "\\.\pipe\$PipeName"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$StateDir = if ($env:VELOCE_STATE_DIR) { $env:VELOCE_STATE_DIR } else { Join-Path $env:LOCALAPPDATA "Lightrider\Veloce" }
$Config = Join-Path $StateDir "agent.json"
$PidFile = Join-Path $StateDir "agent.pid"
$LogFile = Join-Path $StateDir "agent.log"
$ErrFile = Join-Path $StateDir "agent.err.log"

function Fail([string]$Message) {
    Write-Error "veloce-fire-up: $Message"
    exit 1
}

function Find-Dir([string[]]$Candidates) {
    foreach ($candidate in $Candidates) {
        if (Test-Path -PathType Container $candidate) { return (Resolve-Path $candidate).Path }
    }
    return $null
}

function Read-Record([string]$Path) {
    if (-not (Test-Path $Path)) { Fail "missing $Path" }
    $record = Get-Content -Raw -Encoding UTF8 $Path | ConvertFrom-Json
    if (-not $record.library) { Fail "$Path has no library field" }
    return $record
}

function Test-PipeExists {
    return [System.IO.Directory]::GetFiles("\\.\pipe\") -contains $Pipe
}

New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

if ($Stop) {
    if (Test-Path $PidFile) {
        $recorded = [int](Get-Content $PidFile).Trim()
        $process = Get-Process -Id $recorded -ErrorAction SilentlyContinue
        if ($process -and $process.ProcessName -like "veloce-agent*") {
            Stop-Process -Id $recorded -Force
            Write-Host "veloce-fire-up: stopped agent PID $recorded"
        } else {
            Write-Host "veloce-fire-up: no running agent for PID $recorded"
        }
        Remove-Item -Force $PidFile
    } else {
        Write-Host "veloce-fire-up: no agent.pid recorded"
    }
    exit 0
}

$BinDir = Find-Dir @((Join-Path $Root "bin"), (Join-Path $Root "_internal\bin"), (Join-Path $PSScriptRoot "..\_internal\bin"))
$LibDir = Find-Dir @((Join-Path $Root "lib"), (Join-Path $Root "_internal\lib"), (Join-Path $PSScriptRoot "..\_internal\lib"))
if (-not $BinDir) { Fail "cannot locate bin\ (expected beside this script's parent directory)" }
if (-not $LibDir) { Fail "cannot locate lib\ with the FIPS and PQC build records" }

$Agent = Join-Path $BinDir "veloce-agent.exe"
$Cli = Join-Path $BinDir "veloce.exe"
foreach ($required in @($Agent, $Cli)) {
    if (-not (Test-Path $required)) { Fail "missing $required" }
}

$FipsRecordPath = Join-Path $LibDir "wolfcrypt-fips.build-record.json"
$PqcRecordPath = Join-Path $LibDir "veloce-pqc.build-record.json"
$FipsRecord = Read-Record $FipsRecordPath
$PqcRecord = Read-Record $PqcRecordPath
$FipsLib = Join-Path $LibDir $FipsRecord.library
$PqcLib = Join-Path $LibDir $PqcRecord.library
foreach ($required in @($FipsLib, $PqcLib)) {
    if (-not (Test-Path $required)) { Fail "recorded library is missing: $required" }
}

$ConfigObject = [ordered]@{
    pipe        = $Pipe
    fips_lib    = $FipsLib
    fips_record = $FipsRecordPath
    pqc_lib     = $PqcLib
    pqc_record  = $PqcRecordPath
    ems         = [ordered]@{ mode = "disabled"; endpoint = ""; entropy_mixin = "off" }
    # rdseed: CPU hardware entropy (default). os-drbg: BCryptGenRandom output,
    # an unvalidated SP 800-90C chain with no security-strength claim.
    entropy     = [ordered]@{ source = $(if ($env:VELOCE_ENTROPY_SOURCE) { $env:VELOCE_ENTROPY_SOURCE } else { "rdseed" }) }
}
$ConfigJson = $ConfigObject | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText($Config, $ConfigJson + "`n", (New-Object System.Text.UTF8Encoding($false)))

$env:VELOCE_PIPE = $Pipe

if (Test-Path $PidFile) {
    $recorded = [int](Get-Content $PidFile).Trim()
    $existing = Get-Process -Id $recorded -ErrorAction SilentlyContinue
    if ($existing -and (Test-PipeExists)) {
        Write-Host "veloce-fire-up: already running as PID $recorded"
        & $Cli --json status
        & $Cli --json self-test
        exit $LASTEXITCODE
    }
    Remove-Item -Force $PidFile
}

$process = Start-Process -FilePath $Agent `
    -ArgumentList @("--config", "`"$Config`"", "--quiet") `
    -WindowStyle Hidden -PassThru `
    -RedirectStandardOutput $LogFile -RedirectStandardError $ErrFile
Set-Content -Path $PidFile -Value $process.Id -Encoding ASCII

$deadline = (Get-Date).AddSeconds(10)
while ((Get-Date) -lt $deadline) {
    if ($process.HasExited) {
        Get-Content -Tail 100 $ErrFile -ErrorAction SilentlyContinue | Write-Host
        Fail "agent exited during startup (exit code $($process.ExitCode))"
    }
    if (Test-PipeExists) { break }
    Start-Sleep -Milliseconds 250
}
if (-not (Test-PipeExists)) {
    Get-Content -Tail 100 $ErrFile -ErrorAction SilentlyContinue | Write-Host
    Fail "agent did not create $Pipe"
}

& $Cli --json status
if ($LASTEXITCODE -ne 0) { Fail "veloce status failed" }
& $Cli --json self-test
if ($LASTEXITCODE -ne 0) { Fail "veloce self-test failed" }
Write-Host "veloce-fire-up: running as PID $($process.Id)"
Write-Host "veloce-fire-up: log: $LogFile"
