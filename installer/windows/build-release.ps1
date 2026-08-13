[CmdletBinding(DefaultParameterSetName = "Runtime")]
param(
    [string]$Version = "1.0.0",
    [ValidateSet("x86_64")][string]$Arch = "x86_64",
    [Parameter(ParameterSetName = "Runtime", Mandatory = $true)]
    [string]$RuntimeDir,
    [Parameter(ParameterSetName = "Discovery", Mandatory = $true)]
    [switch]$DiscoveryOnly,
    [switch]$SkipMsi
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$PythonArgs = @(
    (Join-Path $Root "scripts\build_desktop_release.py"),
    "--platform", "windows", "--arch", $Arch, "--version", $Version
)
if ($DiscoveryOnly) {
    $PythonArgs += "--discovery-only"
} else {
    $PythonArgs += @("--runtime-dir", (Resolve-Path $RuntimeDir).Path)
}

& python @PythonArgs
if ($LASTEXITCODE -ne 0) { throw "Desktop payload build failed" }

$BuildRoot = Join-Path $Root "build\desktop\windows-$Arch"
$Payload = Join-Path $BuildRoot "dist\Veloce"
$Dist = Join-Path $Root "build\dist"
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
$Zip = Join-Path $Dist "veloce-$Version-windows-$Arch.zip"
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path (Join-Path $Payload "*") -DestinationPath $Zip
Write-Host "Windows portable release: $Zip"

if (-not $SkipMsi) {
    $Wix = Get-Command wix -ErrorAction SilentlyContinue
    if (-not $Wix) {
        throw "WiX v4 is required for MSI output; install it or pass -SkipMsi"
    }
    $Msi = Join-Path $Dist "veloce-$Version-windows-$Arch.msi"
    & $Wix.Source build `
        (Join-Path $PSScriptRoot "veloce.wxs") `
        -arch x64 `
        -d "PayloadDir=$Payload" `
        -d "ProductVersion=$Version" `
        -o $Msi
    if ($LASTEXITCODE -ne 0) { throw "MSI build failed" }
    Write-Host "Windows MSI release: $Msi"
}
