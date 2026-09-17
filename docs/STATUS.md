# Veloce V1 status: pre-release

Spec: plan/veloce-engineering-guide.pdf (v0.3, 2026-08-27).
Date: 2026-09-17. Version: 1.3.0. Platform validated by this run: Linux
x86-64. Gate battery: `bash scripts/run_gates.sh` -- all tests passing.

## 1.3.0: cloud entropy integration and the administrator entropy view

The cloud entropy mix-in (spec 6) is implemented against the production
Lightrider EMS egress (`https://ems.lightriderinc.com`, REST
`POST /v1/entropy/request`, `GET /v1/pubkey`):

1. **Transport.** `agent/src/ems_client.cpp` performs the HTTPS request
   with the TLS client of the loaded FIPS module (functions resolved from
   the same hash-verified library), pinning the ISRG Root X1 anchor by
   default (`ems.ca_file` overrides). The Free tier needs no API key
   (`fastest_available` pool); `ems.api_key` unlocks the higher pools.
2. **Verification.** The receipt is canonicalized exactly as the service
   does (sorted keys, `signature` removed, compact JSON) from the raw
   response text, and the signature is verified against the pinned key
   (`ems.pubkey_hex`) with Ed25519 (RFC 8032, added to the PQC provider as
   verify-only with a known-answer test) or ML-DSA-65. Freshness
   (`ems.max_age_s`), packet length, health flags, and `raw_entropy_stored`
   are checked. Any failure is counted, reported, and ignored (fail-safe).
3. **Mixing.** Certificate #4718 exports no additional-input or reseed entry
   point, so a verified packet is mixed by re-instantiating the DRBG with
   `wc_InitRngNonce`: fresh RDSEED entropy from the seed callback plus the
   packet as the SP 800-90A instantiation nonce. Zero credited entropy; the
   local seed source remains the sole credit; the FIPS position is unchanged.
4. **Control and status.** `set_ems_mode` (agent), `veloce ems on|off`
   (CLI), `set_ems_mode` (SDK); the desktop switch enables EMS and the
   mix-in together. `cloud-entropy-mixin` reports endpoint, policy,
   verification algorithm, packets mixed and rejected, last packet, quality
   score, and last error. Default remains disabled (zero network traffic,
   G3 test unchanged).
5. **Gate.** `tests/test_gate_g3_ems_mixin.py` runs a mock EMS over TLS
   with a test Ed25519 key: good packets are mixed (the seed callback runs
   again, approved mode holds), tampered receipts are rejected without
   affecting local operation, and the live service's published key is
   checked against the pinned default.

The desktop Entropy page was rewritten for administrators: a four-step flow
(hardware source, health checks, FIPS random generator, keys and
signatures) with the cloud feed as an optional extra input, plain-language
states, and a collapsed technical-details section carrying the
compliance-grade fields.

## 1.2.0: Windows release track and desktop interface

The Windows release moved from a bare PyInstaller payload to a branded,
verifiable deliverable (docs/windows.md, docs/desktop-releases.md):

1. **Brand assets.** `assets/branding/veloce.svg` is the single source for
   the mark; `scripts/gen_branding.py` renders the committed `veloce.ico`,
   `veloce.icns`, `veloce-256.png`, and the WixUI banner and dialog bitmaps.
   `Veloce.exe`, the Start Menu shortcut, and the Apps and features entry
   carry the icon.
2. **MSI.** `installer/windows/veloce.wxs` (WiX v5) adds the icon, the
   license dialog rendered from LICENSE at build time, and the
   install-directory dialog with Lightrider artwork. `build-release.ps1`
   adds optional Authenticode signing (`-CertificateThumbprint`; `lib\` is
   never signed because those files are hash recorded) and writes an
   `sha256sum -c` compatible `SHA256SUMS-windows-x86_64.txt`. The GitHub
   workflow now builds the discovery-only MSI as well as the ZIP.
3. **Launcher.** `installer/windows/veloce-fire-up.ps1` mirrors the Linux and
   macOS launchers: build-record-driven configuration under
   `%LOCALAPPDATA%\Lightrider\Veloce`, agent start on the named pipe, status
   and self-test output, `-Stop`. `scripts/gen_config.py` resolves library
   names from build records on all platforms and supports the Windows pipe.
4. **Vendor facts recorded.** The Windows FIPS DLL path (`DLL Release|x64`
   with the vendor v5.2.1 `user_settings.h`) and the pending publication of
   the Windows 11 OE are documented; the claim stays `pending_publication`.

The desktop interface was redesigned for readability: light appearance by
default following the system dark setting, system type stack, a single type
scale with sentence-case labels, neutral surfaces, and the Lightrider
gradient (yellow, amber, orange, red, crimson, sampled from the brand mark)
as the accent for the brand ring, primary actions, indicators, and progress
fills. State colors are reserved for live status. Behavior, element IDs, and
the local API are unchanged; the page gained `/favicon.svg`.
`tests/test_windows_artifacts.py` locks the Windows artifacts and the page
contract. Native execution of the Windows runtime remains an open item.

### Entropy seed source moved to CPU RDSEED (2026-09-17)

Review finding: the 1.1.0 seed callback read `getrandom()` and
`BCryptGenRandom`, which return operating system DRBG output. Seeding the
module's SP 800-90A DRBG from another DRBG is an SP 800-90C RBGC
construction, and on generic operating environments the operating system
RBG is not validated, so no security strength could be claimed for the
chain. The RCT/APT tests applied to that output were not an entropy
assessment, and the `entropy_verified_local: true` label overstated the
position.

Implemented: `entropy.source` selects `rdseed` (default) or `os-drbg`.
RDSEED delivers the processor's SP 800-90B conditioned entropy directly to
the module DRBG; the callback runs SP 800-90B RCT (cutoff 4) and APT
(13/512) at H = 8 bits/sample with a 1024-sample startup test, fail-closed,
and refuses to run when the processor lacks RDSEED. `os-drbg` is explicit
opt-in (arm64 macOS, development) and is reported as an unvalidated
SP 800-90C chain with no security-strength claim. Status, validation,
providers, CBOM, banner, CLI, and desktop UI expose `source_kind`,
`rbg_construction`, and `security_strength_claim`; `verified_local` is
removed. No ESV certificate is claimed for either source; the question of
which source wolfSSL will accept for the legacy IG 9.3.A module is in
`plan/wolfssl-next-steps.pdf`.

### Distribution authorization (2026-09-17)

wolfSSL authorization to distribute the wolfCrypt FIPS module as object code
inside Lightrider-branded Veloce releases is on record. The 1.2.0 GitHub
Release therefore carries the Linux x86-64 full-runtime archive (agent, CLI,
qSearch, FIPS module and PQC provider with recorded hashes) beside the
discovery-only Windows and macOS desktop packages. The release script
continues to fail the build if wolfSSL source is detected in the archive.

## 1.1.0: the macOS track is implemented

macOS moved from "desktop discovery-only" to a full platform track
(docs/macos.md): a native qSearch system collector (frameworks, dylib
sweep, Keychain roots, cert.pem, SSH policy, explicit dyld-cache and
process blind spots), `scripts/build_macos.sh` (FIPS dylib, PQC dylib,
agent, Rust tools, inline smoke gate, desktop runtime staging, tar.gz
bundle, optional .app/DMG), a launchd LaunchAgent template plus
`installer/macos/veloce-fire-up` (with `--launchd`), and Darwin support in
`scripts/gen_config.py`. Rust code cross-checks clean for
x86_64/aarch64-apple-darwin. Hard limit unchanged: no wolfCrypt
certificate lists a macOS OE, so macOS never carries a
validated-deployment claim; the build record says so explicitly.

## What changed in this pre-release

wolfSSL answered our open questions in writing on 2026-08-27. Three things
follow from that response, and all three are now implemented:

1. **wolfEntropy is gone.** wolfSSL confirmed it was never tested with our
   module (v5.2.1) and recommends against using it. The FIPS library is now
   built with `--enable-fips=v5` only.
2. **Seeding is the Lightrider local entropy provider.** The agent registers
   its own generate-seed callback (`wc_SetSeed_Cb`, the mechanism the wolfSSL
   FIPS FAQ prescribes). The callback reads OS kernel entropy (`getrandom` on
   Linux, `BCryptGenRandom` on Windows) and verifies every seed block with
   SP 800-90B-style RCT/APT health tests before the DRBG sees it. Any failure
   latches and the DRBG refuses to seed -- there is no fallback path. The
   module makes no entropy claim and falls under legacy IG 9.3.A, so this
   external documented seed source is the compliant design. Status reports it
   honestly: `entropy_esv_certified: false`, `entropy_verified_local: true`.
3. **The Windows FIPS build path is unblocked.** Only DLL builds are supported
   with FIPS (the README's static-library note was a vendor error, correction
   in wolfSSL PR #11142). The Windows 11 Pro / i7-1260P OE is tested and
   awaiting publication on certificate #4718; until the security policy lists
   it, Windows ships as `pending_publication` with no validated-deployment
   claim.

The desktop app gained an **Entropy** page: live streaming specs (provider,
DRBG, health-test counters, last seed, bytes verified) and a single toggle for
the cloud EMS entropy mix-in. The toggle calls `set_entropy_mixin`; the panel
states that cloud entropy is additional input with zero credited entropy. Raw
entropy is never displayed. The CLI gained `veloce mixin on|off`.

## Gate status

| Gate | Definition | Status |
|---|---|---|
| G0 | FIPS module self-tests green on the reference machine | GREEN. testwolfcrypt passes; build record captures hash, flags, entropy source. |
| G1 | Entropy pipeline + PQC KATs and failure injection | GREEN on Linux. Seed path proven: the DRBG only seeds through the Lightrider callback (verified-block counters > 0, zero health failures). PQC PCT + negative tests pass. Windows/macOS native runs still pending platform libraries. |
| G2 | qSearch detects planted crypto, reports blind spots | GREEN. JSON/CSV/CycloneDX/M-23-02/workbook outputs verified. |
| G3 | TLS + EMS | PARTIAL. EMS-disabled zero-network test green; mix-in state machine and desktop/CLI controls green. Hybrid TLS data plane still pending the full TLS library build. |
| G4 | Security battery + packaging | PARTIAL. IPC hardening, redaction, zeroization green on Linux. Windows MSI, icon, signing path, checksums, and launcher implemented and statically tested (tests/test_windows_artifacts.py); native Windows/macOS signing and installer execution pending. |

## Pre-release build

`bash scripts/make_release.sh` stages `build/dist/veloce-<ver>-linux-x86_64`:
agent, CLI, qSearch, desktop app, object-code libraries with recorded hashes,
docs, EULA, third-party notices. Object code only; the script hard-fails if
wolfSSL source leaks in.

## Open items

- CMVP publication of the tested Windows/Azure OEs on certificate #4718
  (wolfSSL notifies; flips the Windows claim on).
- Hybrid TLS sample pair (G3) needs the autotools TLS+MLKEM build.
- Native Windows/macOS FIPS runtime validation on real hosts (G1/G4):
  Windows steps are documented in docs/windows.md.
- ems-egress `stream.rs` is corrupted at platform HEAD and does not compile;
  platform team fix required before S3 streaming integration. The
  request/response entropy path Veloce uses first is unaffected.
- Commercial coverage of the public-tree PQC sources: wolfSSL confirmation
  still outstanding (see deviations below).
- Entropy source acceptance: wolfSSL position on RDSEED direct seeding
  versus an OS DRBG chain for the legacy IG 9.3.A module, and any ESV or
  entropy-assessment path for RDSEED on the Windows 11 and Ubuntu OEs
  (plan/wolfssl-next-steps.pdf section 4).

## Standing engineering decisions

1. The PQC provider is compiled from the public wolfSSL v5.9.2-stable tree
   because the commercial bundle strips SHAKE (spec 5.3). Object-code-only
   distribution; legal approved 2026-08-05; vendor confirmation pending.
2. `WC_MLDSA_FAULT_HARDEN` does not exist in this tree; the agent does
   verify-after-sign instead. `WC_MLKEM_FAULT_HARDEN` is compiled in.
3. The SDK adds `mldsa_generate_keypair` beyond the guidance's 17 functions
   (erratum flagged in ipc/protocol.md).
4. ML-KEM/ML-DSA randomness comes exclusively from the FIPS DRBG; the
   provider holds no self-seeded RNG state.
