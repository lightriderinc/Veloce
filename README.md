# Veloce, the Lightrider Inc PQC SDK

Veloce V1 delivers two products in one SDK:

- **qSearch**: cryptographic discovery (source code, dependencies,
  certificates) producing a CBOM: JSON, CSV, CycloneDX 1.6, OMB M-23-02
  inventory fields, executive summary.
- **Crypto core**: a local agent embedding the wolfCrypt FIPS 140-3 module
  (CMVP certificate #4718, module v5.2.1) seeded exclusively by the
  wolfEntropy ESV source (fail-closed), with ML-KEM-768 and ML-DSA-65
  provided beside the FIPS boundary, consumed from a pure-Python SDK and a
  CLI over authenticated local IPC. Optional EMS cloud connectivity is off
  by default with a zero-network-traffic guarantee.

The authoritative implementation spec is
[`plan/veloce-engineering-guide.pdf`](plan/veloce-engineering-guide.pdf).

## Build and test (Linux x86-64)

```
bash scripts/run_gates.sh
```

Builds the FIPS module from the licensed bundle, the PQC provider, the
agent, qSearch and the CLI, then runs the release-gate battery (spec 9).
Expected final line: `ALL GATES GREEN`. See docs/quickstart.md for usage
(Python SDK, CLI, and direct wolfSSL integration) and docs/STATUS.md for
gate-by-gate status and recorded deviations.

## Discovery commands (qSearch)

```
build/bin/qsearch system --out host-inventory     # crypto modules on this host
build/bin/qsearch scan <path> --out <dir>         # source tree + certificates
build/bin/veloce system-scan                      # same host scan, via the CLI
sudo build/bin/qsearch system --out host-inventory   # full process coverage
```

Console output is the client-facing summary only: finding counts, the
quantum-vulnerable algorithms, and the next commands to run. Runtime detail
(durations, files seen, skip counts) goes to `<out>/qsearch-run.log`.

Reports written to the output directory:

| File | Purpose |
|---|---|
| `executive-summary.txt` | client summary |
| `workbook-discovery-findings.csv` | rows for Light_Rider_CBOM_Template_Updated.xlsx, sheet "Discovery Findings" (exact column match) |
| `workbook-scanning-log.csv` | one row for sheet "Scanning Log" |
| `findings.json` | canonical findings (pretty-printed) |
| `findings.csv` | flat findings table |
| `cbom.cdx.json` | CycloneDX 1.6 CBOM |
| `m2302-inventory.json` | OMB M-23-02 inventory fields |
| `qsearch-run.log` | runtime detail for this run |

Merge the agent's runtime validation records into a scan with
`build/bin/veloce cbom > agent-cbom.json` followed by
`--merge-agent-cbom agent-cbom.json`.

## Repository layout (spec 10.1 traceability)

| Path | Implements |
|---|---|
| `plan/` | Engineering plan (authoritative spec) |
| `vendor/wolfssl` | Licensed wolfSSL FIPS bundle (symlink; confidential, never published) |
| `scripts/` | Appendix A build recipes, gate runner, release assembly |
| `agent/` | C++17 Veloce agent (spec 5, 8) |
| `ipc/` | IPC protocol v1 (spec 3, 8) |
| `python/` | Pure-Python SDK, 17 public functions (spec 7.1) |
| `cli/` | Rust CLI (spec 7) |
| `qsearch/` | Rust discovery engine + CBOM outputs (spec 4) |
| `tests/` | Gate battery G0-G4 (spec 9) |
| `examples/` | SDK walkthrough; TLS sample pair lands at S3 |
| `installer/` | systemd unit, packaging layout, Windows notes |
| `cbom/` | CBOM field mapping to the Light Rider workbook (Appendix B) |
| `docs/` | quickstart, status, Zenodo release guide |
| `assets/branding/` | banner and logo assets (spec 7.3) |

## Releasing

```
bash scripts/make_release.sh    # object-code archive + wheel + checksums
```

Publication steps (DOI-versioned, all platforms): docs/zenodo-release-guide.md.

## License

Veloce ships under the Lightrider Inc commercial license (LICENSE),
wrapping the wolfSSL commercial agreement: wolfCrypt is distributed as
object code only, never as source. Attribution: built with wolfCrypt
(FIPS 140-3 certificate #4718). See THIRD_PARTY_NOTICES.md.

The `wolfssl-5.9.2-commercial-fips-linuxv5.2.1/` bundle and `vendor/` are
confidential licensed material: never commit, publish, or redistribute them
(enforced by .gitignore and scripts/make_release.sh).
