// PQC provider implementation. Compiled against the provider build's
// settings (scripts/pqc/user_settings.h) so struct layouts match the
// loaded libveloce-pqc.so exactly; all functions resolved with dlsym,
// RTLD_LOCAL so provider symbols can never shadow the FIPS module
// (spec 5.3: distinct name and namespace).
#include "pqc_core.hpp"
#include "sha256.hpp"

#include <dlfcn.h>

#include <cstring>
#include <memory>
#include <mutex>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>

namespace veloce {

namespace {
using FnKemInit = int (*)(MlKemKey*, int, void*, int);
using FnKemFree = int (*)(MlKemKey*);
using FnKemMakeKeyWithRandom = int (*)(MlKemKey*, const unsigned char*, int);
using FnKemEncodePub = int (*)(MlKemKey*, unsigned char*, word32);
using FnKemDecodePub = int (*)(MlKemKey*, const unsigned char*, word32);
using FnKemEncodePriv = int (*)(MlKemKey*, unsigned char*, word32);
using FnKemDecodePriv = int (*)(MlKemKey*, const unsigned char*, word32);
using FnKemEncapsulateWithRandom = int (*)(MlKemKey*, unsigned char*,
                                           unsigned char*,
                                           const unsigned char*, int);
using FnKemDecapsulate = int (*)(MlKemKey*, unsigned char*,
                                 const unsigned char*, word32);

using FnDsaInit = int (*)(wc_MlDsaKey*, void*, int);
using FnDsaFree = void (*)(wc_MlDsaKey*);
using FnDsaSetParams = int (*)(wc_MlDsaKey*, byte);
using FnDsaMakeKeyFromSeed = int (*)(wc_MlDsaKey*, const byte*);
using FnDsaExportPubRaw = int (*)(wc_MlDsaKey*, byte*, word32*);
using FnDsaExportPrivRaw = int (*)(wc_MlDsaKey*, byte*, word32*);
using FnDsaImportPubRaw = int (*)(wc_MlDsaKey*, const byte*, word32);
using FnDsaImportPrivRaw = int (*)(wc_MlDsaKey*, const byte*, word32);
using FnDsaSignCtxWithSeed = int (*)(wc_MlDsaKey*, const byte*, byte, byte*,
                                     word32*, const byte*, word32,
                                     const byte*);
using FnDsaVerifyCtx = int (*)(wc_MlDsaKey*, const byte*, word32, const byte*,
                               byte, const byte*, word32, int*);

constexpr int kMlDsa65Level = 3;         // WC_ML_DSA_65
constexpr size_t kMlDsaSeedSz = 32;      // FIPS 204 xi
constexpr size_t kMlDsaSignRndSz = 32;   // FIPS 204 rnd (hedged)
constexpr size_t kMaxRaw = 8192;         // covers all ML-DSA raw sizes
} // namespace

struct PqcCore::Impl {
    void* dl = nullptr;
    FnKemInit kemInit = nullptr;
    FnKemFree kemFree = nullptr;
    FnKemMakeKeyWithRandom kemMakeKey = nullptr;
    FnKemEncodePub kemEncodePub = nullptr;
    FnKemDecodePub kemDecodePub = nullptr;
    FnKemEncodePriv kemEncodePriv = nullptr;
    FnKemDecodePriv kemDecodePriv = nullptr;
    FnKemEncapsulateWithRandom kemEncapsulate = nullptr;
    FnKemDecapsulate kemDecapsulate = nullptr;
    FnDsaInit dsaInit = nullptr;
    FnDsaFree dsaFree = nullptr;
    FnDsaSetParams dsaSetParams = nullptr;
    FnDsaMakeKeyFromSeed dsaMakeKeyFromSeed = nullptr;
    FnDsaExportPubRaw dsaExportPubRaw = nullptr;
    FnDsaExportPrivRaw dsaExportPrivRaw = nullptr;
    FnDsaImportPubRaw dsaImportPubRaw = nullptr;
    FnDsaImportPrivRaw dsaImportPrivRaw = nullptr;
    FnDsaSignCtxWithSeed dsaSignCtxWithSeed = nullptr;
    FnDsaVerifyCtx dsaVerifyCtx = nullptr;
    // The provider build is SINGLE_THREADED; serialize every call.
    std::mutex m;

    ~Impl() {
        if (dl) dlclose(dl);
    }
};

PqcCore::PqcCore() : impl_(new Impl) {}
PqcCore::~PqcCore() { delete impl_; }

bool PqcCore::load(const std::string& libPath,
                   const std::string& expectedSha256Hex, std::string& err) {
    path_ = libPath;
    sha256_ = vsha256::fileSha256Hex(libPath);
    if (sha256_.empty()) {
        err = "cannot read PQC provider library: " + libPath;
        return false;
    }
    if (!expectedSha256Hex.empty() && sha256_ != expectedSha256Hex) {
        err = "PQC provider hash mismatch: expected " + expectedSha256Hex +
              ", found " + sha256_;
        return false;
    }
    if (libPath.empty() || libPath[0] != '/') {
        err = "PQC provider path must be absolute";
        return false;
    }
    impl_->dl = dlopen(libPath.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!impl_->dl) {
        err = std::string("dlopen failed: ") + dlerror();
        return false;
    }
    auto sym = [&](const char* name) { return dlsym(impl_->dl, name); };
    impl_->kemInit = reinterpret_cast<FnKemInit>(sym("wc_MlKemKey_Init"));
    impl_->kemFree = reinterpret_cast<FnKemFree>(sym("wc_MlKemKey_Free"));
    impl_->kemMakeKey = reinterpret_cast<FnKemMakeKeyWithRandom>(
        sym("wc_MlKemKey_MakeKeyWithRandom"));
    impl_->kemEncodePub =
        reinterpret_cast<FnKemEncodePub>(sym("wc_MlKemKey_EncodePublicKey"));
    impl_->kemDecodePub =
        reinterpret_cast<FnKemDecodePub>(sym("wc_MlKemKey_DecodePublicKey"));
    impl_->kemEncodePriv =
        reinterpret_cast<FnKemEncodePriv>(sym("wc_MlKemKey_EncodePrivateKey"));
    impl_->kemDecodePriv =
        reinterpret_cast<FnKemDecodePriv>(sym("wc_MlKemKey_DecodePrivateKey"));
    impl_->kemEncapsulate = reinterpret_cast<FnKemEncapsulateWithRandom>(
        sym("wc_MlKemKey_EncapsulateWithRandom"));
    impl_->kemDecapsulate =
        reinterpret_cast<FnKemDecapsulate>(sym("wc_MlKemKey_Decapsulate"));
    impl_->dsaInit = reinterpret_cast<FnDsaInit>(sym("wc_MlDsaKey_Init"));
    impl_->dsaFree = reinterpret_cast<FnDsaFree>(sym("wc_MlDsaKey_Free"));
    impl_->dsaSetParams =
        reinterpret_cast<FnDsaSetParams>(sym("wc_MlDsaKey_SetParams"));
    impl_->dsaMakeKeyFromSeed = reinterpret_cast<FnDsaMakeKeyFromSeed>(
        sym("wc_MlDsaKey_MakeKeyFromSeed"));
    impl_->dsaExportPubRaw =
        reinterpret_cast<FnDsaExportPubRaw>(sym("wc_MlDsaKey_ExportPubRaw"));
    impl_->dsaExportPrivRaw =
        reinterpret_cast<FnDsaExportPrivRaw>(sym("wc_MlDsaKey_ExportPrivRaw"));
    impl_->dsaImportPubRaw =
        reinterpret_cast<FnDsaImportPubRaw>(sym("wc_MlDsaKey_ImportPubRaw"));
    impl_->dsaImportPrivRaw =
        reinterpret_cast<FnDsaImportPrivRaw>(sym("wc_MlDsaKey_ImportPrivRaw"));
    impl_->dsaSignCtxWithSeed = reinterpret_cast<FnDsaSignCtxWithSeed>(
        sym("wc_MlDsaKey_SignCtxWithSeed"));
    impl_->dsaVerifyCtx =
        reinterpret_cast<FnDsaVerifyCtx>(sym("wc_MlDsaKey_VerifyCtx"));

    if (!impl_->kemInit || !impl_->kemFree || !impl_->kemMakeKey ||
        !impl_->kemEncodePub || !impl_->kemDecodePub ||
        !impl_->kemEncodePriv || !impl_->kemDecodePriv ||
        !impl_->kemEncapsulate || !impl_->kemDecapsulate ||
        !impl_->dsaInit || !impl_->dsaFree || !impl_->dsaSetParams ||
        !impl_->dsaMakeKeyFromSeed || !impl_->dsaExportPubRaw ||
        !impl_->dsaExportPrivRaw || !impl_->dsaImportPubRaw ||
        !impl_->dsaImportPrivRaw || !impl_->dsaSignCtxWithSeed ||
        !impl_->dsaVerifyCtx) {
        err = "required PQC provider symbols missing";
        return false;
    }
    loaded_ = true;
    return true;
}

bool PqcCore::mlkemKeygen(const RandFn& rand, std::vector<uint8_t>& pub,
                          std::vector<uint8_t>& priv, std::string& err) {
    if (!loaded_) { err = "provider not loaded"; return false; }
    uint8_t seed[WC_ML_KEM_MAKEKEY_RAND_SZ];
    if (!rand(seed, sizeof(seed))) {
        err = "FIPS DRBG unavailable (fail-closed)";
        return false;
    }
    std::lock_guard<std::mutex> lk(impl_->m);
    auto key = std::make_unique<MlKemKey>();
    if (impl_->kemInit(key.get(), WC_ML_KEM_768, nullptr, INVALID_DEVID) != 0) {
        err = "mlkem init failed";
        return false;
    }
    int rc = impl_->kemMakeKey(key.get(), seed, static_cast<int>(sizeof(seed)));
    memset(seed, 0, sizeof(seed));
    if (rc != 0) {
        impl_->kemFree(key.get());
        err = "mlkem keygen failed (" + std::to_string(rc) + ")";
        return false;
    }
    pub.resize(WC_ML_KEM_768_PUBLIC_KEY_SIZE);
    priv.resize(WC_ML_KEM_768_PRIVATE_KEY_SIZE);
    if (impl_->kemEncodePub(key.get(), pub.data(),
                            static_cast<word32>(pub.size())) != 0 ||
        impl_->kemEncodePriv(key.get(), priv.data(),
                             static_cast<word32>(priv.size())) != 0) {
        impl_->kemFree(key.get());
        err = "mlkem key encode failed";
        return false;
    }
    impl_->kemFree(key.get());
    return true;
}

bool PqcCore::mlkemEncapsulate(const RandFn& rand,
                               const std::vector<uint8_t>& pub,
                               std::vector<uint8_t>& ct,
                               std::vector<uint8_t>& ss, std::string& err) {
    if (!loaded_) { err = "provider not loaded"; return false; }
    if (pub.size() != WC_ML_KEM_768_PUBLIC_KEY_SIZE) {
        err = "mlkem public key must be " +
              std::to_string(WC_ML_KEM_768_PUBLIC_KEY_SIZE) + " bytes";
        return false;
    }
    uint8_t m[WC_ML_KEM_ENC_RAND_SZ];
    if (!rand(m, sizeof(m))) {
        err = "FIPS DRBG unavailable (fail-closed)";
        return false;
    }
    std::lock_guard<std::mutex> lk(impl_->m);
    auto key = std::make_unique<MlKemKey>();
    if (impl_->kemInit(key.get(), WC_ML_KEM_768, nullptr, INVALID_DEVID) != 0) {
        err = "mlkem init failed";
        return false;
    }
    if (impl_->kemDecodePub(key.get(), pub.data(),
                            static_cast<word32>(pub.size())) != 0) {
        impl_->kemFree(key.get());
        err = "mlkem public key decode failed";
        return false;
    }
    ct.resize(WC_ML_KEM_768_CIPHER_TEXT_SIZE);
    ss.resize(WC_ML_KEM_SS_SZ);
    int rc = impl_->kemEncapsulate(key.get(), ct.data(), ss.data(), m,
                                   static_cast<int>(sizeof(m)));
    memset(m, 0, sizeof(m));
    impl_->kemFree(key.get());
    if (rc != 0) {
        err = "mlkem encapsulate failed (" + std::to_string(rc) + ")";
        return false;
    }
    return true;
}

bool PqcCore::mlkemDecapsulate(const std::vector<uint8_t>& priv,
                               const std::vector<uint8_t>& ct,
                               std::vector<uint8_t>& ss, std::string& err) {
    if (!loaded_) { err = "provider not loaded"; return false; }
    if (priv.size() != WC_ML_KEM_768_PRIVATE_KEY_SIZE) {
        err = "invalid mlkem private key size";
        return false;
    }
    if (ct.size() != WC_ML_KEM_768_CIPHER_TEXT_SIZE) {
        err = "mlkem ciphertext must be " +
              std::to_string(WC_ML_KEM_768_CIPHER_TEXT_SIZE) + " bytes";
        return false;
    }
    std::lock_guard<std::mutex> lk(impl_->m);
    auto key = std::make_unique<MlKemKey>();
    if (impl_->kemInit(key.get(), WC_ML_KEM_768, nullptr, INVALID_DEVID) != 0) {
        err = "mlkem init failed";
        return false;
    }
    if (impl_->kemDecodePriv(key.get(), priv.data(),
                             static_cast<word32>(priv.size())) != 0) {
        impl_->kemFree(key.get());
        err = "mlkem private key decode failed";
        return false;
    }
    ss.resize(WC_ML_KEM_SS_SZ);
    int rc = impl_->kemDecapsulate(key.get(), ss.data(), ct.data(),
                                   static_cast<word32>(ct.size()));
    impl_->kemFree(key.get());
    if (rc != 0) {
        err = "mlkem decapsulate failed (" + std::to_string(rc) + ")";
        return false;
    }
    return true;
}

bool PqcCore::mldsaKeygen(const RandFn& rand, std::vector<uint8_t>& pub,
                          std::vector<uint8_t>& priv, std::string& err) {
    if (!loaded_) { err = "provider not loaded"; return false; }
    uint8_t seed[kMlDsaSeedSz];
    if (!rand(seed, sizeof(seed))) {
        err = "FIPS DRBG unavailable (fail-closed)";
        return false;
    }
    std::lock_guard<std::mutex> lk(impl_->m);
    auto key = std::make_unique<wc_MlDsaKey>();
    if (impl_->dsaInit(key.get(), nullptr, INVALID_DEVID) != 0 ||
        impl_->dsaSetParams(key.get(), kMlDsa65Level) != 0) {
        err = "mldsa init failed";
        return false;
    }
    int rc = impl_->dsaMakeKeyFromSeed(key.get(), seed);
    memset(seed, 0, sizeof(seed));
    if (rc != 0) {
        impl_->dsaFree(key.get());
        err = "mldsa keygen failed (" + std::to_string(rc) + ")";
        return false;
    }
    pub.resize(kMaxRaw);
    priv.resize(kMaxRaw);
    word32 pubLen = static_cast<word32>(pub.size());
    word32 privLen = static_cast<word32>(priv.size());
    if (impl_->dsaExportPubRaw(key.get(), pub.data(), &pubLen) != 0 ||
        impl_->dsaExportPrivRaw(key.get(), priv.data(), &privLen) != 0) {
        impl_->dsaFree(key.get());
        err = "mldsa key export failed";
        return false;
    }
    impl_->dsaFree(key.get());
    pub.resize(pubLen);
    priv.resize(privLen);
    return true;
}

bool PqcCore::mldsaSign(const RandFn& rand, const std::vector<uint8_t>& priv,
                        const std::vector<uint8_t>& pub,
                        const std::vector<uint8_t>& msg,
                        std::vector<uint8_t>& sig, std::string& err) {
    if (!loaded_) { err = "provider not loaded"; return false; }
    uint8_t rnd[kMlDsaSignRndSz];
    if (!rand(rnd, sizeof(rnd))) {
        err = "FIPS DRBG unavailable (fail-closed)";
        return false;
    }
    std::lock_guard<std::mutex> lk(impl_->m);
    auto key = std::make_unique<wc_MlDsaKey>();
    if (impl_->dsaInit(key.get(), nullptr, INVALID_DEVID) != 0 ||
        impl_->dsaSetParams(key.get(), kMlDsa65Level) != 0) {
        err = "mldsa init failed";
        return false;
    }
    if (impl_->dsaImportPrivRaw(key.get(), priv.data(),
                                static_cast<word32>(priv.size())) != 0) {
        impl_->dsaFree(key.get());
        err = "mldsa private key import failed";
        return false;
    }
    sig.resize(kMaxRaw);
    word32 sigLen = static_cast<word32>(sig.size());
    int rc = impl_->dsaSignCtxWithSeed(key.get(), nullptr, 0, sig.data(),
                                       &sigLen, msg.data(),
                                       static_cast<word32>(msg.size()), rnd);
    memset(rnd, 0, sizeof(rnd));
    impl_->dsaFree(key.get());
    if (rc != 0) {
        err = "mldsa sign failed (" + std::to_string(rc) + ")";
        return false;
    }
    sig.resize(sigLen);

    // Fault hardening: verify-after-sign against the stored public key
    // (WC_MLDSA_FAULT_HARDEN equivalent is absent in this tree; the agent
    // provides the countermeasure).
    bool valid = false;
    std::string verr;
    if (!mldsaVerifyLocked(pub, msg, sig, valid, verr) || !valid) {
        zeroizeVec(sig);
        err = "mldsa verify-after-sign failed: possible fault";
        return false;
    }
    return true;
}

bool PqcCore::mldsaVerify(const std::vector<uint8_t>& pub,
                          const std::vector<uint8_t>& msg,
                          const std::vector<uint8_t>& sig, bool& valid,
                          std::string& err) {
    std::lock_guard<std::mutex> lk(impl_->m);
    return mldsaVerifyLocked(pub, msg, sig, valid, err);
}

bool PqcCore::selfTest(const RandFn& rand, std::string& err) {
    // Pairwise consistency + negative tests, run at startup and from
    // run_fips_self_tests (spec 9).
    std::vector<uint8_t> pub, priv, ct, ss1, ss2;
    if (!mlkemKeygen(rand, pub, priv, err)) return false;
    if (!mlkemEncapsulate(rand, pub, ct, ss1, err)) return false;
    if (!mlkemDecapsulate(priv, ct, ss2, err)) return false;
    if (ss1 != ss2) {
        err = "mlkem PCT: shared secrets differ";
        return false;
    }
    ct[5] ^= 0x20;
    std::vector<uint8_t> ss3;
    if (!mlkemDecapsulate(priv, ct, ss3, err)) return false;
    if (ss3 == ss1) {
        err = "mlkem negative test: corrupted ciphertext accepted";
        return false;
    }
    std::vector<uint8_t> dpub, dpriv, sig;
    std::vector<uint8_t> msg = {'v', 'e', 'l', 'o', 'c', 'e'};
    if (!mldsaKeygen(rand, dpub, dpriv, err)) return false;
    if (!mldsaSign(rand, dpriv, dpub, msg, sig, err)) return false;
    bool valid = false;
    if (!mldsaVerify(dpub, msg, sig, valid, err) || !valid) {
        err = err.empty() ? "mldsa PCT: signature did not verify" : err;
        return false;
    }
    sig[7] ^= 0x04;
    valid = true;
    std::string ignore;
    mldsaVerify(dpub, msg, sig, valid, ignore);
    if (valid) {
        err = "mldsa negative test: corrupted signature accepted";
        return false;
    }
    zeroizeVec(priv);
    zeroizeVec(dpriv);
    return true;
}

bool PqcCore::mldsaVerifyLocked(const std::vector<uint8_t>& pub,
                                const std::vector<uint8_t>& msg,
                                const std::vector<uint8_t>& sig, bool& valid,
                                std::string& err) {
    valid = false;
    if (!loaded_) { err = "provider not loaded"; return false; }
    auto key = std::make_unique<wc_MlDsaKey>();
    if (impl_->dsaInit(key.get(), nullptr, INVALID_DEVID) != 0 ||
        impl_->dsaSetParams(key.get(), kMlDsa65Level) != 0) {
        err = "mldsa init failed";
        return false;
    }
    if (impl_->dsaImportPubRaw(key.get(), pub.data(),
                               static_cast<word32>(pub.size())) != 0) {
        impl_->dsaFree(key.get());
        err = "mldsa public key import failed";
        return false;
    }
    int res = 0;
    int rc = impl_->dsaVerifyCtx(key.get(), sig.data(),
                                 static_cast<word32>(sig.size()), nullptr, 0,
                                 msg.data(), static_cast<word32>(msg.size()),
                                 &res);
    impl_->dsaFree(key.get());
    valid = (rc == 0 && res == 1);
    return true;
}

void PqcCore::zeroizeVec(std::vector<uint8_t>& v) {
    volatile uint8_t* p = v.data();
    for (size_t i = 0; i < v.size(); i++) p[i] = 0;
    v.clear();
}

} // namespace veloce
