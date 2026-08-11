# Veloce V1 implementation status

Reference: plan/veloce-engineering-guide.pdf. Gates per spec 9 and 10.
Date: 2026-08-05. Platform covered: Linux x86-64 (this reference machine).

## Gate status

| Gate | Definition (spec 10) | Status |
|---|---|---|
| G0 | FIPS module passes self-tests on the Linux reference machine | GREEN: testwolfcrypt "Test complete", return code 0; hash flow (configure, make, fips-hash.sh, make) automated in scripts/build_fips.sh |
| G1 | Entropy pipeline + ML-KEM/ML-DSA pass KATs and failure-injection on both OSes | GREEN on Linux: wolfEntropy wired via wc_SetSeed_Cb, nofallback fail-closed verified (DRBG refuses without seed source); PQC PCT + negative tests at startup and in gate battery. Windows source solution is present, but native agent/IPC/packaging and the approved dynamic-library configuration remain pending. |
| G2 | qSearch detects all planted crypto, reports FP/blind spots | GREEN: controlled-environment test detects RSA, ECDSA, DH, certificates (provenance "directly observed"), ML-KEM as pqc-ready; JSON/CSV/CycloneDX/M-23-02/summary outputs |
| G3 | TLS + EMS gate groups | PARTIAL: policy control plane (configure_hybrid_tls, profiles) done; EMS-disabled zero-network test GREEN; set_entropy_mixin state machine done. TLS data plane (hybrid handshake sample pair) pending: needs full TLS+MLKEM library build (autotools) |
| G4 | Full security battery + packaging | PARTIAL: IPC hardening tests GREEN (peer creds, framing, protocol version, oversized frames), diagnostic redaction GREEN, key zeroization contract GREEN; MSI/deb/rpm packaging pending (installer/ holds unit file + layout) |

Gate battery: `bash scripts/run_gates.sh` (33 tests, all passing, including the
file-exchange two-host demo exercised against a local test agent).

## Deliverables checklist (spec 7.2)

| Deliverable | Status |
|---|---|
| Python wheel (veloce_pqc, py3-none-any) | buildable: `make wheel` |
| Native agent | done (C++17, dlopen + SHA-256 verified loading) |
| wolfCrypt shared library | built from licensed bundle, hash recorded |
| qSearch binary | done (Rust, std-only) |
| CLI | done (Rust, std-only; status line from live validation) |
| Windows MSI + service | pending (vendor DLL-config item at S0) |
| Linux systemd unit | done (installer/linux/veloce-agent.service); deb/rpm wrap pending |
| API reference | ipc/protocol.md + Python docstrings |
| Architecture / security / FIPS / entropy docs | spec PDF + docs/quickstart.md + this file |
| SBOM and CBOM | CBOM: agent export (records + CycloneDX) and qSearch outputs; SBOM: pending |
| Sample TLS client/server | pending (S3, see examples/README.md) |
| Test vectors | PQC self-test (PCT + negative); ACVTS vectors pending (vendor item) |
| Performance report | pending (S1 baseline; wolfcrypt/benchmark available in build tree) |
| Known-limitations statement | this file, plus vendor items below |
| Reseller evaluation package, EULA | LICENSE v1.0 approved by Lightrider legal 2026-08-05 |
| Branding assets | assets/branding/banner.txt; CLI/agent/SDK banner implemented |

## Deviations and engineering decisions on record

1. PQC provider source. The commercial FIPS bundle strips SHAKE from
   sha3.c/sha3.h, so its ML-KEM / ML-DSA sources cannot compile from that
   bundle alone (confirms spec 5.3). The provider is built from the public
   wolfSSL tree of the same release (v5.9.2-stable, the archive wolfSSL
   signs on GitHub) using the Appendix A fallback (standalone compilation
   of wc_mlkem.*, wc_mldsa.*, sha3.c). Distribution remains object-code
   only under the commercial agreement. Lightrider legal approved this
   position on 2026-08-05. [VENDOR: confirm coverage.]
2. ML-DSA fault hardening. WC_MLDSA_FAULT_HARDEN does not exist in this
   tree; the agent implements verify-after-sign hardening instead.
   WC_MLKEM_FAULT_HARDEN is compiled into the provider.
3. mldsa_generate_keypair. The guidance's 17 functions include
   mldsa_sign/mldsa_verify but no ML-DSA keygen; the SDK adds
   mldsa_generate_keypair as an erratum extension, flagged for guidance
   reconciliation.
4. Randomness wiring. ML-KEM uses MakeKeyWithRandom / EncapsulateWithRandom
   with FIPS DRBG output; ML-DSA uses MakeKeyFromSeed and SignCtxWithSeed
   with FIPS DRBG seeds (FIPS 204 xi and rnd). The provider therefore holds
   no self-seeded RNG state.
5. ESV certificate number and exact OE coverage: reported as "vendor
   confirmation pending" in validation_status (spec open item).

## Vendor items (unchanged from spec, opened at S0)

Windows FIPS DLL configuration; user_settings.h variant for module v5.2.1;
ESV certificate number and OE applicability; hybrid TLS production group
confirmation; FIPS v7 "PQ-FS" timeline; commercial coverage of same-release
public-tree PQC sources (item 1 above). As checked 2026-08-10, wolfSSL lists
Windows 10 Enterprise/i5-1345U and Windows 11 Pro/i7-1260P as pending OEs;
their CAVP algorithm records do not yet establish CMVP OE approval under #4718.
