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

    wc_FreeRng(&rng);
    printf("PQC provider self-test: all checks passed\n");
    return 0;
}
