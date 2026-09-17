# Veloce Desktop on Windows: quick start

Veloce Desktop is a click-to-run application for Windows 10 and 11 (x86-64).
No build tools are required.

## 1. Download

From the GitHub Releases page, download one of:

| File | Use |
|---|---|
| `veloce-<version>-windows-x86_64.msi` | Installer. Adds `Veloce Desktop` to the Start Menu. |
| `veloce-<version>-windows-x86_64.zip` | Portable. Extract anywhere and run `Veloce.exe`. |
| `SHA256SUMS-windows-x86_64.txt` | Checksums for the two files above. |

Verify the download in PowerShell before installing:

```powershell
Get-FileHash .\veloce-<version>-windows-x86_64.msi -Algorithm SHA256
Get-Content .\SHA256SUMS-windows-x86_64.txt
```

The two hash values must match.

## 2. Install or extract

Double-click the MSI, accept the license, and keep the default folder
(`C:\Program Files\Veloce`). Leave `Launch Veloce Desktop` checked on the
last page. The portable ZIP needs no installation: extract it and
double-click `Veloce.exe`.

Current builds are not yet signed with a publisher certificate. Windows
SmartScreen therefore shows a warning on first launch; choose `More info`
and then `Run anyway`. Signed builds will remove this step.

## 3. Run

Veloce Desktop starts a local service on this computer only and opens your
browser. Nothing listens on the network, and no scanned content leaves the
machine.

- **qSearch**: choose a folder, click `Start qSearch`, and read the counts,
  algorithm chart, and findings table. `Open report folder` shows the
  generated reports under `Documents\Veloce Reports`.
- **Security dashboard** and **Entropy**: these pages show live data only
  when the Veloce FIPS runtime is installed. Release packages downloaded
  from GitHub are discovery-only, so they display `Agent unavailable` and
  `No live data`. That is expected and not an error.

Click `Quit Veloce` in the sidebar to stop the local service.

## 4. Reports

Each scan writes a folder under `Documents\Veloce Reports`:

| File | Content |
|---|---|
| `executive-summary.txt` | Summary to read first |
| `findings.json`, `findings.csv` | Every finding |
| `cbom.cdx.json` | CycloneDX 1.6 cryptography bill of materials |
| `m2302-inventory.json` | OMB M-23-02 inventory fields |
| `workbook-discovery-findings.csv`, `workbook-scanning-log.csv` | Rows for the Light Rider CBOM workbook |

## 5. Command line (optional)

The scanner and CLI are inside the application folder:

```powershell
cd "C:\Program Files\Veloce\_internal\bin"
.\qsearch.exe scan C:\path\to\project --out C:\reports\project
.\qsearch.exe system --out C:\reports\host
```

Run the second command from an elevated PowerShell for full host coverage.

## FIPS status of this package

Discovery-only packages contain no cryptographic module and make no FIPS
claim. The Veloce FIPS runtime for Windows is delivered separately and, until
the wolfCrypt certificate lists the Windows operating environment, reports
`pending_publication` rather than a validated-deployment claim.
