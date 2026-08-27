# Veloce V1 status: pre-release

Spec: plan/veloce-engineering-guide.pdf (v0.3, 2026-08-27).
Date: 2026-08-27. Platform validated by this run: Linux x86-64.
Gate battery: `bash scripts/run_gates.sh` -- **45 tests, all passing.**

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
| G4 | Security battery + packaging | PARTIAL. IPC hardening, redaction, zeroization green on Linux. Native Windows/macOS signing and installer tests pending. |

## Pre-release build

`bash scripts/make_release.sh` stages `build/dist/veloce-<ver>-linux-x86_64`:
agent, CLI, qSearch, desktop app, object-code libraries with recorded hashes,
docs, EULA, third-party notices. Object code only; the script hard-fails if
wolfSSL source leaks in.

## Open items

- CMVP publication of the tested Windows/Azure OEs on certificate #4718
  (wolfSSL notifies; flips the Windows claim on).
- Hybrid TLS sample pair (G3) needs the autotools TLS+MLKEM build.
- Native Windows/macOS FIPS runtime validation on real hosts (G1/G4).
- ems-egress `stream.rs` is corrupted at platform HEAD and does not compile;
  platform team fix required before S3 streaming integration. The
  request/response entropy path Veloce uses first is unaffected.
- Commercial coverage of the public-tree PQC sources: wolfSSL confirmation
  still outstanding (see deviations below).

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
