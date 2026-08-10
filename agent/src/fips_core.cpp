// FIPS crypto core implementation. Compiled against the FIPS build's
// generated headers so WC_RNG has the exact layout of the loaded module;
// every function is resolved with dlsym from the dynamically loaded,
// hash-verified libwolfssl.so (spec 5.2, 8).
#include "fips_core.hpp"
#include "sha256.hpp"

#include <dlfcn.h>

#include <cstring>
#include <mutex>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

namespace veloce {

namespace {
using FnGetStatus = int (*)(void);
using FnRunAllCast = int (*)(void);
using FnInitRng = int (*)(WC_RNG*);
using FnFreeRng = int (*)(WC_RNG*);
using FnGenerateBlock = int (*)(WC_RNG*, byte*, word32);
using FnEntropyOnDemand = int (*)(void);
using FnLibVersion = const char* (*)(void);
using FnSetSeedCb = int (*)(wc_RngSeed_Cb);
} // namespace

struct FipsCore::Impl {
    void* dl = nullptr;
    FnGetStatus getStatus = nullptr;
    FnRunAllCast runAllCast = nullptr;
    FnInitRng initRng = nullptr;
    FnFreeRng freeRng = nullptr;
    FnGenerateBlock generateBlock = nullptr;
    FnEntropyOnDemand entropyOnDemand = nullptr;
    FnLibVersion libVersion = nullptr;
    FnSetSeedCb setSeedCb = nullptr;
    wc_RngSeed_Cb defaultSeed = nullptr;
    WC_RNG rng;
    bool rngReady = false;
    std::mutex m;

    ~Impl() {
        if (rngReady && freeRng) freeRng(&rng);
        if (dl) dlclose(dl);
    }
};

FipsCore::FipsCore() : impl_(new Impl) {}
FipsCore::~FipsCore() { delete impl_; }

bool FipsCore::load(const std::string& libPath,
                    const std::string& expectedSha256Hex, std::string& err) {
    path_ = libPath;
    sha256_ = vsha256::fileSha256Hex(libPath);
    if (sha256_.empty()) {
        err = "cannot read FIPS library: " + libPath;
        return false;
    }
    if (!expectedSha256Hex.empty() && sha256_ != expectedSha256Hex) {
        err = "FIPS library hash mismatch: expected " + expectedSha256Hex +
              ", found " + sha256_;
        degraded_ = true;
        lastError_ = err;
        return false;
    }
    // Absolute path only; no search-path trust (spec 8, library loading).
    if (libPath.empty() || libPath[0] != '/') {
        err = "FIPS library path must be absolute";
        return false;
    }
    impl_->dl = dlopen(libPath.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!impl_->dl) {
        err = std::string("dlopen failed: ") + dlerror();
        return false;
    }
    auto sym = [&](const char* name) { return dlsym(impl_->dl, name); };
    impl_->getStatus =
        reinterpret_cast<FnGetStatus>(sym("wolfCrypt_GetStatus_fips"));
    impl_->runAllCast =
        reinterpret_cast<FnRunAllCast>(sym("wc_RunAllCast_fips"));
    impl_->initRng = reinterpret_cast<FnInitRng>(sym("wc_InitRng"));
    impl_->freeRng = reinterpret_cast<FnFreeRng>(sym("wc_FreeRng"));
    impl_->generateBlock =
        reinterpret_cast<FnGenerateBlock>(sym("wc_RNG_GenerateBlock"));
    impl_->entropyOnDemand =
        reinterpret_cast<FnEntropyOnDemand>(sym("wc_Entropy_OnDemandTest"));
    impl_->libVersion =
        reinterpret_cast<FnLibVersion>(sym("wolfSSL_lib_version"));
    impl_->setSeedCb = reinterpret_cast<FnSetSeedCb>(sym("wc_SetSeed_Cb"));
    impl_->defaultSeed =
        reinterpret_cast<wc_RngSeed_Cb>(sym("wc_GenerateSeed"));
    if (!impl_->getStatus || !impl_->runAllCast || !impl_->initRng ||
        !impl_->freeRng || !impl_->generateBlock) {
        err = "required FIPS module symbols missing (not a FIPS build?)";
        return false;
    }
    loaded_ = true;
    return true;
}

bool FipsCore::start(std::string& err) {
    std::lock_guard<std::mutex> lk(impl_->m);
    // Module power-on self-tests ran at load; verify no error is latched.
    int st = impl_->getStatus();
    if (st != 0) {
        degraded_ = true;
        lastError_ = err =
            "FIPS module status " + std::to_string(st) + " (not approved)";
        return false;
    }
    // On-demand SP 800-90B health test of wolfEntropy (RCT + APT).
    if (impl_->entropyOnDemand) {
        int er = impl_->entropyOnDemand();
        if (er != 0) {
            degraded_ = true;
            lastError_ = err = "wolfEntropy on-demand health test failed (" +
                               std::to_string(er) + "); fail-closed";
            return false;
        }
    }
    // Install the entropy source with wc_SetSeed_Cb immediately after
    // startup (spec 5.1 wiring). The module is built with WC_RNG_SEED_CB,
    // so the DRBG refuses to instantiate until a seed source is installed;
    // wc_GenerateSeed is the module's wolfEntropy-backed seed path.
    if (impl_->setSeedCb && impl_->defaultSeed) {
        int sc = impl_->setSeedCb(impl_->defaultSeed);
        if (sc != 0) {
            degraded_ = true;
            lastError_ = err =
                "wc_SetSeed_Cb failed (" + std::to_string(sc) + ")";
            return false;
        }
    }
    // Instantiate the DRBG. With --enable-wolfEntropy=nofallback the seed
    // comes from wolfEntropy or fails; it never falls back to /dev/urandom.
    memset(&impl_->rng, 0, sizeof(impl_->rng));
    int rc = impl_->initRng(&impl_->rng);
    if (rc != 0) {
        degraded_ = true;
        lastError_ = err = "FIPS DRBG instantiate failed (" +
                           std::to_string(rc) + "); entropy fail-closed";
        return false;
    }
    impl_->rngReady = true;
    return true;
}

int FipsCore::moduleStatus() {
    if (!loaded_) return -1;
    return impl_->getStatus();
}

bool FipsCore::runCasts(std::string& err) {
    if (!loaded_) {
        err = "module not loaded";
        return false;
    }
    std::lock_guard<std::mutex> lk(impl_->m);
    int rc = impl_->runAllCast();
    if (rc != 0) {
        degraded_ = true;
        lastError_ = err =
            "conditional algorithm self-tests failed (" + std::to_string(rc) +
            ")";
        return false;
    }
    return true;
}

bool FipsCore::entropyOnDemandTest(std::string& detail) {
    if (!loaded_ || !impl_->entropyOnDemand) {
        detail = "on-demand test not exported by module";
        return loaded_;
    }
    std::lock_guard<std::mutex> lk(impl_->m);
    int rc = impl_->entropyOnDemand();
    if (rc != 0) {
        degraded_ = true;
        lastError_ = detail =
            "wolfEntropy health test failed (" + std::to_string(rc) + ")";
        return false;
    }
    detail = "RCT + APT passed (on demand)";
    return true;
}

bool FipsCore::randomBytes(uint8_t* out, size_t len) {
    if (!ok()) return false;
    std::lock_guard<std::mutex> lk(impl_->m);
    if (!impl_->rngReady) return false;
    int rc = impl_->generateBlock(&impl_->rng, out,
                                  static_cast<word32>(len));
    if (rc != 0) {
        // Reseed/generate failure: fail-closed (spec 5.1).
        degraded_ = true;
        lastError_ =
            "FIPS DRBG generate failed (" + std::to_string(rc) + ")";
        return false;
    }
    return true;
}

std::string FipsCore::libVersion() const {
    if (loaded_ && impl_->libVersion) return impl_->libVersion();
    return "";
}

} // namespace veloce
