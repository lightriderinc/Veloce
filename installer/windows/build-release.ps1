<#
.SYNOPSIS
    Build the Veloce Desktop Windows release: portable ZIP, MSI, checksums.

.DESCRIPTION
    Runs the desktop packager (PyInstaller payload with the Veloce icon), then
    produces build\dist\veloce-<version>-windows-<arch>.zip, the WiX v5 MSI with
    Lightrider-branded dialogs, and an sha256sum-compatible checksum file.

    Exactly one of -RuntimeDir (full runtime) or -DiscoveryOnly must be given.
    A missing native runtime never silently downgrades a full-runtime build.

.PARAMETER CertificateThumbprint
    SHA-1 thumbprint of the Lightrider Authenticode certificate in the current
    user's or machine's certificate store. When set, Veloce.exe, the bundled
    Rust executables, the agent, and the final MSI are signed with signtool.
    Files under lib\ are never signed: they are the hash-recorded FIPS module
    and PQC provider, and rewriting them breaks the recorded SHA-256 and the
    module's in-core integrity check.

.EXAMPLE
    .\installer\windows\build-release.ps1 -Version 1.2.0 -RuntimeDir C:\secure\veloce-runtime-windows-x86_64

.EXAMPLE
    .\installer\windows\build-release.ps1 -Version 1.2.0 -DiscoveryOnly -SkipMsi
#>
[CmdletBinding(DefaultParameterSetName = "Runtime")]
param(
    [string]$Version = "1.2.0",
    [ValidateSet("x86_64")][string]$Arch = "x86_64",
    [Parameter(ParameterSetName = "Runtime", Mandatory = $true)]
    [string]$RuntimeDir,
    [Parameter(ParameterSetName = "Discovery", Mandatory = $true)]
    [switch]$DiscoveryOnly,
    [switch]$SkipMsi,
    [string]$CertificateThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
# ------------------------------------------------------------ toolchain
# Prefer the interpreter on PATH (the one `python -m pip install -r
# desktop\requirements-build.txt` targeted, and the one actions/setup-python
# provides in CI); fall back to the `py -3` launcher. The Microsoft Store
# alias stub fails the version probe and is skipped.
function Test-Python3([string]$Exe, [string[]]$LauncherArgs) {
    try {
        $major = & $Exe @LauncherArgs -c "import sys; print(sys.version_info[0])" 2>$null
        return ($LASTEXITCODE -eq 0 -and "$major".Trim() -eq "3")
    } catch { return $false }
}
$Python = $null
$PythonLauncherArgs = @()
$candidate = Get-Command python -ErrorAction SilentlyContinue
if ($candidate -and (Test-Python3 $candidate.Source @())) { $Python = $candidate }
if (-not $Python) {
    $candidate = Get-Command py -ErrorAction SilentlyContinue
    if ($candidate -and (Test-Python3 $candidate.Source @("-3"))) {
        $Python = $candidate
        $PythonLauncherArgs = @("-3")
    }
}
if (-not $Python) {
    throw "Python 3 is required; install it from https://www.python.org/downloads/windows/, disable the Microsoft Store Python app-execution aliases if necessary, and reopen PowerShell"
}
& $Python.Source @PythonLauncherArgs -c "import PyInstaller" 2>$null
if ($LASTEXITCODE -ne 0) {
    $pipHint = "$($Python.Source) $($PythonLauncherArgs -join ' ') -m pip install -r desktop\requirements-build.txt"
    throw "PyInstaller is not installed for $($Python.Source); run: $pipHint"
}
$Cargo = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $Cargo) {
    throw "Rust with the MSVC toolchain is required; install it from https://rustup.rs/ and reopen PowerShell"
}

$Branding = Join-Path $Root "assets\branding"
foreach ($asset in @("veloce.ico", "wix-banner.bmp", "wix-dialog.bmp")) {
    if (-not (Test-Path (Join-Path $Branding $asset))) {
        throw "missing branding asset assets\branding\$asset (run py -3 scripts\gen_branding.py)"
    }
}

# ------------------------------------------------------------ payload
$PythonArgs = @(
    (Join-Path $Root "scripts\build_desktop_release.py"),
    "--platform", "windows", "--arch", $Arch, "--version", $Version
)
if ($DiscoveryOnly) {
    $PythonArgs += "--discovery-only"
} else {
    $PythonArgs += @("--runtime-dir", (Resolve-Path $RuntimeDir).Path)
}

try {
    & $Python.Source @PythonLauncherArgs @PythonArgs
} catch {
    throw "Unable to run Python 3. Install it from https://www.python.org/downloads/windows/, disable the Microsoft Store Python app-execution aliases if necessary, and reopen PowerShell"
}
if ($LASTEXITCODE -ne 0) { throw "Desktop payload build failed" }

$BuildRoot = Join-Path $Root "build\desktop\windows-$Arch"
$Payload = Join-Path $BuildRoot "dist\Veloce"
$LicenseRtf = Join-Path $BuildRoot "license.rtf"
$Dist = Join-Path $Root "build\dist"
New-Item -ItemType Directory -Force -Path $Dist | Out-Null
if (-not (Test-Path $LicenseRtf)) { throw "desktop packager did not write $LicenseRtf" }

# ------------------------------------------------------------ signing
function Find-SignTool {
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path $kits) {
        $found = Get-ChildItem -Path $kits -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -like "*\x64\*" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    throw "signtool.exe not found; install the Windows SDK or omit -CertificateThumbprint"
}

function Invoke-AuthenticodeSign([string[]]$Files) {
    if (-not $CertificateThumbprint) { return }
    $signtool = Find-SignTool
    foreach ($file in $Files) {
        & $signtool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /sha1 $CertificateThumbprint $file
        if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed for $file" }
        Write-Host "signed: $file"
    }
}

# Sign Lightrider-built PE files only. lib\ holds the hash-recorded FIPS and
# PQC DLLs and is excluded on purpose (see CertificateThumbprint help).
$SignTargets = Get-ChildItem -Path $Payload -Recurse -Filter *.exe |
    Where-Object { $_.FullName -notmatch '\\lib\\' } |
    ForEach-Object { $_.FullName }
Invoke-AuthenticodeSign $SignTargets

# ------------------------------------------------------------ portable ZIP
$Artifacts = @()
$Zip = Join-Path $Dist "veloce-$Version-windows-$Arch.zip"
if (Test-Path $Zip) { Remove-Item -Force $Zip }
Compress-Archive -Path (Join-Path $Payload "*") -DestinationPath $Zip
Write-Host "Windows portable release: $Zip"
$Artifacts += $Zip

# ------------------------------------------------------------ MSI
if (-not $SkipMsi) {
    $Wix = Get-Command wix -ErrorAction SilentlyContinue
    if (-not $Wix) {
        throw "WiX 5.0.2 is required for MSI output (dotnet tool install --global wix --version 5.0.2); or pass -SkipMsi"
    }
    # WiX v7 and later require accepting the Open Source Maintenance Fee EULA
    # before use; that is a licensing decision outside this script. veloce.wxs
    # targets WiX v5, so pin the tool and its extensions to 5.0.2.
    $WixVersion = ((& $Wix.Source --version) | Select-Object -First 1).Split("+")[0].Trim()
    $WixMajor = [int]($WixVersion.Split(".")[0])
    if ($WixMajor -ne 5) {
        throw "WiX $WixVersion found; this package is built with WiX 5.0.2. Run: dotnet tool uninstall --global wix; dotnet tool install --global wix --version 5.0.2"
    }
    foreach ($extension in @("WixToolset.UI.wixext", "WixToolset.Util.wixext")) {
        $addOutput = & $Wix.Source extension add -g "$extension/$WixVersion" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host $addOutput
            throw "cannot add $extension/$WixVersion"
        }
    }

    $Msi = Join-Path $Dist "veloce-$Version-windows-$Arch.msi"
    & $Wix.Source build `
        (Join-Path $PSScriptRoot "veloce.wxs") `
        -arch x64 `
        -ext WixToolset.UI.wixext `
        -ext WixToolset.Util.wixext `
        -d "PayloadDir=$Payload" `
        -d "ProductVersion=$Version" `
        -d "BrandingDir=$Branding" `
        -d "LicenseRtf=$LicenseRtf" `
        -o $Msi
    if ($LASTEXITCODE -ne 0) { throw "MSI build failed" }
    Invoke-AuthenticodeSign @($Msi)
    Write-Host "Windows MSI release: $Msi"
    $Artifacts += $Msi
}

# ------------------------------------------------------------ checksums
# sha256sum -c compatible: lower-case hash, two spaces, file name; LF; no BOM.
$Sums = Join-Path $Dist "SHA256SUMS-windows-$Arch.txt"
$Lines = foreach ($artifact in $Artifacts) {
    $hash = (Get-FileHash -Algorithm SHA256 -Path $artifact).Hash.ToLower()
    "$hash  $(Split-Path -Leaf $artifact)"
}
[System.IO.File]::WriteAllText($Sums, (($Lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Checksums: $Sums"
Get-Content $Sums
