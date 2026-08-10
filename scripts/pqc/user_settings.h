/* Veloce PQC provider build settings.
 *
 * Standalone non-FIPS compilation of ML-KEM (FIPS 203), ML-DSA (FIPS 204)
 * and SHA-3/SHAKE from the licensed wolfSSL tree, per spec 5.3 and the
 * Appendix A fallback (the commercial FIPS tree rejects a full non-FIPS
 * configure run). The resulting library lives beside the FIPS boundary
 * and draws all DRBG seed material from the FIPS DRBG through
 * wc_SetSeed_Cb (WC_RNG_SEED_CB).
 */
#ifndef VELOCE_PQC_USER_SETTINGS_H
#define VELOCE_PQC_USER_SETTINGS_H

/* FIPS 203 / 204 implementations */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_MLDSA

/* SHAKE/XOF primitives the v5 FIPS boundary strips (spec 5.3) */
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256

/* Fault hardening (spec Appendix A); ML-DSA sign is additionally
 * verify-after-sign hardened at the agent layer. */
#define WC_MLKEM_FAULT_HARDEN

/* DRBG seed callback so the agent can seed this library's Hash_DRBG
 * exclusively from the FIPS DRBG (spec 5.3). */
#define WC_RNG_SEED_CB

/* Raw-key API surface only; DER/ASN.1 import-export is not part of the
 * V1 agent interface, so asn.c is not compiled into the provider. */
#define WOLFSSL_MLDSA_NO_ASN1
#define WOLFSSL_MLKEM_NO_ASN1
#define WOLFSSL_DILITHIUM_NO_ASN1
#define NO_ASN

/* The agent serializes provider calls behind one mutex. */
#define SINGLE_THREADED

/* Trim unrelated wolfCrypt surface from this provider build. */
#define NO_SHA
#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_DES3
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_PWDBASED
#define NO_OLD_TLS
#define WOLFCRYPT_ONLY

#endif /* VELOCE_PQC_USER_SETTINGS_H */
