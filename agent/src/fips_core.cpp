// FIPS crypto core implementation. Compiled against the FIPS build's
// generated headers so WC_RNG has the exact layout of the loaded module;
// every function is resolved with dlsym from the dynamically loaded,
// hash-verified libwolfssl.so (spec 5.2, 8).
#include "fips_core.hpp"
#include "platform_loader.hpp"
#include "sha256.hpp"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <mutex>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif

namespace veloce {

namespace {
using FnGetStatus = int (*)(void);
using FnRunAllCast = int (*)(void);
using FnInitRng = int (*)(WC_RNG*);
using FnFreeRng = int (*)(WC_RNG*);
using FnGenerateBlock = int (*)(WC_RNG*, byte*, word32);
using FnLibVersion = const char* (*)(void);
using FnSetSeedCb = int (*)(wc_RngSeed_Cb);

// ---------------------------------------------------------------------
// Lightrider local entropy provider (spec 5.1).
//
// The FIPS module makes no entropy claim; its security policy requires
// the crypto officer to register an external seed source through
// wc_SetSeed_Cb (wolfSSL FIPS FAQ section 2, legacy IG 9.3.A position,
// vendor-confirmed 2026-08-27). wolfEntropy is not used: it was never
// tested with module v5.2.1.
//
// Every seed block is drawn from the OS kernel entropy interface and
// verified with SP 800-90B-style continuous health tests before it is
// handed to the DRBG:
//   RCT  repetition count, cutoff 31 consecutive identical bytes
//   APT  adaptive proportion, reference byte count >= 325 in a
//        512-sample window
// Test state persists across calls. Any acquisition or test failure
// latches; the callback then refuses seeds and the DRBG fails closed
// (the FIPS build defines WC_RNG_SEED_CB, so wc_InitRng and reseeds
// return an error with no fallback path).

constexpr int kRctCutoff = 31;
constexpr int kAptWindow = 512;
constexpr int kAptCutoff = 325;

struct SeedHealth {
    // RCT state
    int lastByte = -1;
    int runLength = 0;
    // APT state
    int aptReference = -1;
    int aptCount = 0;
    int aptSamples = 0;
};

SeedHealth g_seedHealth;             // guarded by g_seedMutex
std::mutex g_seedMutex;
std::atomic<bool> g_seedLatchedFail{false};
std::atomic<uint64_t> g_seedBlocks{0};
std::atomic<uint64_t> g_seedBytes{0};
std::atomic<uint64_t> g_seedFailures{0};
std::atomic<int64_t> g_lastSeedUnix{0};

bool osKernelEntropy(byte* out, word32 sz) {
#if defined(_WIN32)
    return BCryptGenRandom(nullptr, out, sz,
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    word32 got = 0;
    while (got < sz) {
        ssize_t r = getrandom(out + got, sz - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        got += static_cast<word32>(r);
    }
    return true;
#endif
}

// Run RCT + APT over a block, updating persistent state. Returns false
// on a health-test failure.
bool healthCheck(SeedHealth& h, const byte* buf, word32 sz) {
    for (word32 i = 0; i < sz; i++) {
        int b = buf[i];
        // RCT: consecutive identical samples.
        if (b == h.lastByte) {
            if (++h.runLength >= kRctCutoff) return false;
        } else {
            h.lastByte = b;
            h.runLength = 1;
        }
        // APT: reference-sample proportion inside a fixed window.
        if (h.aptSamples == 0) {
            h.aptReference = b;
            h.aptCount = 1;
            h.aptSamples = 1;
        } else {
            if (b == h.aptReference && ++h.aptCount >= kAptCutoff)
                return false;
            if (++h.aptSamples >= kAptWindow) h.aptSamples = 0;
        }
    }
    return true;
}

// wc_RngSeed_Cb: fill `seed` with `sz` verified bytes, 0 on success.
int lightriderSeedCb(OS_Seed* os, byte* seed, word32 sz) {
    (void)os;
    if (g_seedLatchedFail.load()) return -1;
    if (!osKernelEntropy(seed, sz)) {
        g_seedLatchedFail.store(true);
        g_seedFailures.fetch_add(1);
        return -1;
    }
    {
        std::lock_guard<std::mutex> lk(g_seedMutex);
        if (!healthCheck(g_seedHealth, seed, sz)) {
            g_seedLatchedFail.store(true);
            g_seedFailures.fetch_add(1);
            std::memset(seed, 0, sz);
            return -1;
        }
    }
    g_seedBlocks.fetch_add(1);
    g_seedBytes.fetch_add(sz);
    g_lastSeedUnix.store(static_cast<int64_t>(time(nullptr)));
    return 0;
}
} // namespace

struct FipsCore::Impl {
    platform::SharedLibrary library;
    FnGetStatus getStatus = nullptr;
    FnRunAllCast runAllCast = nullptr;
    FnInitRng initRng = nullptr;
    FnFreeRng freeRng = nullptr;
    FnGenerateBlock generateBlock = nullptr;
    FnLibVersion libVersion = nullptr;
    FnSetSeedCb setSeedCb = nullptr;
    WC_RNG rng;
    bool rngReady = false;
    std::mutex m;

    ~Impl() {
        if (rngReady && freeRng) freeRng(&rng);
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
    // Absolute path only; restricted loader search, no PATH/CWD trust.
    if (!impl_->library.open(libPath, err)) return false;
    auto sym = [&](const char* name) { return impl_->library.symbol(name); };
    impl_->getStatus =
        reinterpret_cast<FnGetStatus>(sym("wolfCrypt_GetStatus_fips"));
    impl_->runAllCast =
        reinterpret_cast<FnRunAllCast>(sym("wc_RunAllCast_fips"));
    impl_->initRng = reinterpret_cast<FnInitRng>(sym("wc_InitRng"));
    impl_->freeRng = reinterpret_cast<FnFreeRng>(sym("wc_FreeRng"));
    impl_->generateBlock =
        reinterpret_cast<FnGenerateBlock>(sym("wc_RNG_GenerateBlock"));
    impl_->libVersion =
        reinterpret_cast<FnLibVersion>(sym("wolfSSL_lib_version"));
    impl_->setSeedCb = reinterpret_cast<FnSetSeedCb>(sym("wc_SetSeed_Cb"));
    if (!impl_->getStatus || !impl_->runAllCast || !impl_->initRng ||
        !impl_->freeRng || !impl_->generateBlock || !impl_->setSeedCb) {
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
    // Startup health test: verify a fresh OS-entropy sample with the same
    // RCT/APT checks used on the live seed path.
    {
        byte probe[kAptWindow];
        SeedHealth probeState;
        if (!osKernelEntropy(probe, sizeof(probe)) ||
            !healthCheck(probeState, probe, sizeof(probe))) {
            degraded_ = true;
            lastError_ = err =
                "startup entropy health test failed; fail-closed";
            return false;
        }
        std::memset(probe, 0, sizeof(probe));
    }
    // Install the Lightrider seed callback with wc_SetSeed_Cb immediately
    // after startup (spec 5.1 wiring). The module is built with
    // WC_RNG_SEED_CB, so the DRBG refuses to instantiate until a seed
    // source is installed; every block the callback returns has passed
    // RCT/APT verification.
    int sc = impl_->setSeedCb(lightriderSeedCb);
    if (sc != 0) {
        degraded_ = true;
        lastError_ = err =
            "wc_SetSeed_Cb failed (" + std::to_string(sc) + ")";
        return false;
    }
    // Instantiate the DRBG. A callback error propagates as an
    // instantiate failure; there is no fallback path.
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

bool FipsCore::entropySelfTest(std::string& detail) {
    if (!loaded_) {
        detail = "module not loaded";
        return false;
    }
    if (g_seedLatchedFail.load()) {
        detail = "seed path latched failed (fail-closed)";
        return false;
    }
    byte probe[kAptWindow];
    SeedHealth probeState;
    bool ok = osKernelEntropy(probe, sizeof(probe)) &&
              healthCheck(probeState, probe, sizeof(probe));
    std::memset(probe, 0, sizeof(probe));
    if (!ok) {
        degraded_ = true;
        lastError_ = detail = "entropy health test failed (RCT/APT)";
        return false;
    }
    detail = "RCT + APT passed (on demand, 512-byte sample)";
    return true;
}

uint64_t FipsCore::seedBlocksVerified() { return g_seedBlocks.load(); }
uint64_t FipsCore::seedBytesVerified() { return g_seedBytes.load(); }
uint64_t FipsCore::seedHealthFailures() { return g_seedFailures.load(); }
int64_t FipsCore::lastSeedUnix() { return g_lastSeedUnix.load(); }

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
