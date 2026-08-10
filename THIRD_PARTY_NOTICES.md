# Third-party notices

Veloce PQC SDK, Lightrider Inc.

## wolfSSL / wolfCrypt

Veloce is built with wolfCrypt (FIPS 140-3 certificate #4718), module
version 5.2.1, library wolfSSL 5.9.2.

Copyright (c) 2006-2026 wolfSSL Inc. All rights reserved.

wolfSSL and wolfCrypt are distributed inside Veloce as object code only,
under the commercial license agreement between Lightrider Inc and wolfSSL
Inc (Agreement v.01-24). The Lightrider EULA licenses Veloce and does not
sublicense wolfSSL. wolfSSL source code is confidential to that agreement
and is never included in any Veloce distribution, repository, or archive.

The Veloce PQC provider (libveloce-pqc) is compiled from wolfSSL
ML-KEM / ML-DSA / SHA-3 sources of the same release and distributed as
object code under the same agreement.

## qSearch collector integrations (planned, spec 4.1)

Collector adapters are limited by policy to Apache-2.0, MIT, or BSD
licensed tools. Bundling decisions for CryptoScan, Zeek, Suricata, and
TShark/Npcap are pending legal review (GPL components are not bundled;
fallback is bring-your-own-collector integration). No third-party collector
is bundled in this release.

## Rust and Python components

qSearch and the Veloce CLI are standard-library-only Rust programs; the
Python SDK is standard-library-only Python. No third-party packages are
vendored.
