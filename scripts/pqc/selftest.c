/* Veloce PQC provider build gate (spec 9, PQC gate group):
 * ML-KEM-768 keygen/encap/decap roundtrip, ML-DSA-65 sign/verify,
 * plus negative tests (corrupted ciphertext and corrupted signature).
 * Exit 0 only if every check passes.
 */
#include <stdio.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#define CHECK(cond, name) \
    do { if (!(cond)) { printf("FAIL: %s\n", name); return 1; } \
         printf("ok: %s\n", name); } while (0)

int main(void)
{
    WC_RNG rng;
    CHECK(wc_InitRng(&rng) == 0, "rng init");

    /* ML-KEM-768 roundtrip */
    {
        MlKemKey alice, bob;
        unsigned char pub[WC_ML_KEM_768_PUBLIC_KEY_SIZE];
        unsigned char ct[WC_ML_KEM_768_CIPHER_TEXT_SIZE];
        unsigned char ss1[WC_ML_KEM_SS_SZ], ss2[WC_ML_KEM_SS_SZ];

        CHECK(wc_MlKemKey_Init(&alice, WC_ML_KEM_768, NULL, INVALID_DEVID) == 0,
              "mlkem init");
        CHECK(wc_MlKemKey_MakeKey(&alice, &rng) == 0, "mlkem keygen");
        CHECK(wc_MlKemKey_EncodePublicKey(&alice, pub, sizeof(pub)) == 0,
              "mlkem encode pub");

        CHECK(wc_MlKemKey_Init(&bob, WC_ML_KEM_768, NULL, INVALID_DEVID) == 0,
              "mlkem init 2");
        CHECK(wc_MlKemKey_DecodePublicKey(&bob, pub, sizeof(pub)) == 0,
              "mlkem decode pub");
        CHECK(wc_MlKemKey_Encapsulate(&bob, ct, ss1, &rng) == 0,
              "mlkem encapsulate");
        CHECK(wc_MlKemKey_Decapsulate(&alice, ss2, ct, sizeof(ct)) == 0,
              "mlkem decapsulate");
        CHECK(memcmp(ss1, ss2, sizeof(ss1)) == 0, "mlkem shared secrets equal");

        /* Negative: corrupt ciphertext must yield a different secret
         * (FIPS 203 implicit rejection). */
        ct[3] ^= 0x40;
        CHECK(wc_MlKemKey_Decapsulate(&alice, ss2, ct, sizeof(ct)) == 0,
              "mlkem decapsulate corrupted");
        CHECK(memcmp(ss1, ss2, sizeof(ss1)) != 0, "mlkem implicit rejection");

        wc_MlKemKey_Free(&alice);
        wc_MlKemKey_Free(&bob);
    }

    /* ML-DSA-65 sign/verify */
    {
        MlDsaKey key;
        unsigned char sig[6000];
        word32 sigLen = (word32)sizeof(sig);
        const unsigned char msg[] = "veloce pqc provider gate";
        int res = 0;

        CHECK(wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) == 0, "mldsa init");
        CHECK(wc_MlDsaKey_SetParams(&key, WC_ML_DSA_65) == 0, "mldsa params");
        CHECK(wc_MlDsaKey_MakeKey(&key, &rng) == 0, "mldsa keygen");
        CHECK(wc_MlDsaKey_SignCtx(&key, NULL, 0, sig, &sigLen, msg,
              sizeof(msg), &rng) == 0, "mldsa sign");
        CHECK(wc_MlDsaKey_VerifyCtx(&key, sig, sigLen, NULL, 0, msg,
              sizeof(msg), &res) == 0 && res == 1, "mldsa verify");

        /* Negative: corrupted signature must not verify. */
        sig[10] ^= 0x01;
        res = 0;
        (void)wc_MlDsaKey_VerifyCtx(&key, sig, sigLen, NULL, 0, msg,
              sizeof(msg), &res);
        CHECK(res == 0, "mldsa reject corrupted signature");

        wc_MlDsaKey_Free(&key);
    }

    /* Ed25519 verify known-answer test: RFC 8032 section 7.1, test 1
     * (empty message). Used to verify EMS receipt signatures. */
    {
        static const unsigned char pub[32] = {
            0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
            0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a };
        unsigned char sig[64] = {
            0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
            0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
            0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
            0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b };
        ed25519_key key;
        int res = 0;
        CHECK(wc_ed25519_init(&key) == 0, "ed25519 init");
        CHECK(wc_ed25519_import_public(pub, sizeof(pub), &key) == 0,
              "ed25519 import public");
        CHECK(wc_ed25519_verify_msg(sig, sizeof(sig), (const unsigned char*)"",
              0, &res, &key) == 0 && res == 1, "ed25519 RFC 8032 KAT verify");
        sig[0] ^= 0x01;
        res = 0;
        (void)wc_ed25519_verify_msg(sig, sizeof(sig), (const unsigned char*)"",
              0, &res, &key);
        CHECK(res == 0, "ed25519 reject corrupted signature");
        wc_ed25519_free(&key);
    }

    wc_FreeRng(&rng);
    printf("PQC provider self-test: all checks passed\n");
    return 0;
}
