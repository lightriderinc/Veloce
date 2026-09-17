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
#include <string>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/random.h>
#endif

#if defined(__x86_64__) || defined(_M_X64)
#define VELOCE_X86_64 1
#include <immintrin.h>
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#else
#define VELOCE_X86_64 0
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
// Lightrider local entropy provider (spec 5.1, seed source revised
// 2026-09-17).
//
// The FIPS module makes no entropy claim: SP #4718 section 2.8 reads
// "N/A for this module" and the certificate caveat is "No assurance of
// the minimum strength of generated SSPs". The security policy requires
// the crypto officer to register an external seed source through
// wc_SetSeed_Cb. Two sources are implemented; the agent configuration
// selects one and there is no runtime fallback between them.
//
//   cpu-rdseed (default)
//     x86-64 RDSEED returns conditioned output of the processor's
//     SP 800-90B noise source (rated full entropy by the CPU vendor
//     documentation). It is delivered directly to the module's
//     SP 800-90A Hash_DRBG, so the construction is an entropy source
//     seeding a DRBG, not a chain of DRBGs.
//
//   os-drbg (explicit opt-in only)
//     getrandom() on Linux and BCryptGenRandom on Windows return the
//     operating system DRBG's output. Seeding one DRBG from another is
//     an SP 800-90C RBGC construction; unless the operating system RBG
//     is itself validated for the operational environment, no security
//     strength can be claimed. Provided for platforms without RDSEED
//     (arm64) and for development; status reports it as such.
//
// Health tests (SP 800-90B section 4.4), 8-bit samples, alpha = 2^-20,
// claimed H = 8 bits per sample for the RDSEED source:
//   RCT  repetition count, cutoff 1 + ceil(20 / 8) = 4
//   APT  adaptive proportion, window 512, cutoff 13
//        (smallest C with P[Binomial(512, 2^-8) >= C] <= 2^-20)
//   startup test over 1024 consecutive samples before the first seed,
//   continuous over every seed block thereafter.
// For the os-drbg source the same tests run as a sanity check only; they
// are not an entropy assessment of DRBG output.
//
// Neither source carries an ESV certificate. Any acquisition or
// health-test failure latches; the callback then refuses seeds and the
// DRBG fails closed (the FIPS build defines WC_RNG_SEED_CB, so wc_InitRng
// and reseeds return an error with no fallback path).

constexpr int kRctCutoff = 4;
constexpr int kAptWindow = 512;
constexpr int kAptCutoff = 13;
constexpr int kStartupSamples = 1024;
constexpr int kRdseedMaxRetries = 4096;

enum class SeedSource : int { None = 0, CpuRdseed = 1, OsDrbg = 2 };

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
std::atomic<int> g_seedSource{static_cast<int>(SeedSource::None)};
std::atomic<bool> g_seedLatchedFail{false};
std::atomic<uint64_t> g_seedBlocks{0};
std::atomic<uint64_t> g_seedBytes{0};
std::atomic<uint64_t> g_seedFailures{0};
std::atomic<int64_t> g_lastSeedUnix{0};

SeedSource currentSource() {
    return static_cast<SeedSource>(g_seedSource.load());
}

#if VELOCE_X86_64
bool cpuHasRdseed() {
#if defined(_MSC_VER)
    int regs[4] = {0, 0, 0, 0};
    __cpuidex(regs, 7, 0);
    return ((static_cast<unsigned>(regs[1]) >> 18) & 1u) != 0;
#else
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d)) return false;
    return ((b >> 18) & 1u) != 0;
#endif
}

#if defined(__GNUC__)
__attribute__((target("rdseed")))
#endif
bool rdseed64(unsigned long long* value) {
    return _rdseed64_step(value) == 1;
}

// Fill `out` from RDSEED. The instruction reports underflow when the
// conditioner has not accumulated enough entropy; retry with a pause and
// give up (fail closed) after kRdseedMaxRetries consecutive misses.
bool cpuRdseedFill(byte* out, word32 sz) {
    word32 got = 0;
    int misses = 0;
    while (got < sz) {
        unsigned long long value = 0;
        if (!rdseed64(&value)) {
            if (++misses > kRdseedMaxRetries) return false;
            _mm_pause();
            continue;
        }
        misses = 0;
        word32 n = (sz - got) < 8 ? (sz - got) : 8;
        std::memcpy(out + got, &value, n);
        got += n;
    }
    return true;
}
#else
bool cpuHasRdseed() { return false; }
bool cpuRdseedFill(byte*, word32) { return false; }
#endif

bool osDrbgFill(byte* out, word32 sz) {
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

bool acquireSeed(byte* out, word32 sz) {
    switch (currentSource()) {
    case SeedSource::CpuRdseed: return cpuRdseedFill(out, sz);
    case SeedSource::OsDrbg: return osDrbgFill(out, sz);
    case SeedSource::None: break;
    }
    return false;
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

// Startup / on-demand test: a fresh 1024-sample draw through fresh test
// state. The samples are discarded, never used as seed material.
bool startupHealthTest() {
    byte probe[kStartupSamples];
    SeedHealth probeState;
    bool ok = acquireSeed(probe, sizeof(probe)) &&
              healthCheck(probeState, probe, sizeof(probe));
    std::memset(probe, 0, sizeof(probe));
    return ok;
}

// wc_RngSeed_Cb: fill `seed` with `sz` health-tested bytes, 0 on success.
int lightriderSeedCb(OS_Seed* os, byte* seed, word32 sz) {
    (void)os;
    if (g_seedLatchedFail.load()) return -1;
    if (!acquireSeed(seed, sz)) {
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

bool FipsCore::rdseedAvailable() { return cpuHasRdseed(); }

bool FipsCore::setSeedSource(const std::string& name, std::string& err) {
    if (name == "rdseed" || name == "cpu-rdseed") {
        if (!cpuHasRdseed()) {
            err = "entropy source rdseed is not available on this processor "
                  "(no RDSEED); the agent fails closed. Set entropy.source "
                  "to \"os-drbg\" only where an unvalidated OS DRBG chain "
                  "with no security-strength claim is acceptable";
            degraded_ = true;
            lastError_ = err;
            return false;
        }
        g_seedSource.store(static_cast<int>(SeedSource::CpuRdseed));
        return true;
    }
    if (name == "os-drbg") {
        g_seedSource.store(static_cast<int>(SeedSource::OsDrbg));
        return true;
    }
    err = "unknown entropy.source \"" + name +
          "\" (expected \"rdseed\" or \"os-drbg\")";
    degraded_ = true;
    lastError_ = err;
    return false;
}

std::string FipsCore::seedSourceKind() const {
    switch (currentSource()) {
    case SeedSource::CpuRdseed: return "cpu-rdseed";
    case SeedSource::OsDrbg: return "os-drbg";
    case SeedSource::None: break;
    }
    return "none";
}

bool FipsCore::seedSourceIsHardware() const {
    return currentSource() == SeedSource::CpuRdseed;
}

std::string FipsCore::seedSourceDescription() const {
    switch (currentSource()) {
    case SeedSource::CpuRdseed:
        return "lightrider-local (CPU RDSEED hardware entropy + SP 800-90B "
               "RCT/APT health tests)";
    case SeedSource::OsDrbg:
        return "lightrider-local (OS DRBG output via getrandom/"
               "BCryptGenRandom; SP 800-90C RBGC chain, unvalidated; "
               "RCT/APT sanity check only)";
    case SeedSource::None: break;
    }
    return "lightrider-local (no seed source configured)";
}

std::string FipsCore::rbgConstruction() const {
    switch (currentSource()) {
    case SeedSource::CpuRdseed:
        return "SP 800-90B entropy source (RDSEED) seeding the module's "
               "SP 800-90A Hash_DRBG directly";
    case SeedSource::OsDrbg:
        return "SP 800-90C RBGC: operating system DRBG output seeding the "
               "module's SP 800-90A Hash_DRBG";
    case SeedSource::None: break;
    }
    return "none";
}

std::string FipsCore::securityStrengthClaim() const {
    switch (currentSource()) {
    case SeedSource::CpuRdseed:
        return "none formally: no ESV certificate; RDSEED output is rated "
               "full entropy by the processor vendor and health-tested at "
               "H = 8 bits/sample; entropy assessment open";
    case SeedSource::OsDrbg:
        return "none: randomness source is an operating system DRBG not "
               "validated for this operational environment";
    case SeedSource::None: break;
    }
    return "none";
}

std::string FipsCore::healthTestSpec() {
    return "SP 800-90B RCT (cutoff 4) + APT (13/512) at H = 8 bits/sample, "
           "alpha 2^-20; startup 1024 samples + continuous; fail-closed";
}

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
    if (currentSource() == SeedSource::None) {
        degraded_ = true;
        lastError_ = err = "no entropy seed source configured; fail-closed";
        return false;
    }
    // Module power-on self-tests ran at load; verify no error is latched.
    int st = impl_->getStatus();
    if (st != 0) {
        degraded_ = true;
        lastError_ = err =
            "FIPS module status " + std::to_string(st) + " (not approved)";
        return false;
    }
    // SP 800-90B startup health test: 1024 consecutive samples from the
    // selected source through the same RCT/APT checks used on the live
    // seed path. The samples are discarded.
    if (!startupHealthTest()) {
        degraded_ = true;
        lastError_ = err = "startup entropy health test failed (" +
                           seedSourceKind() + "); fail-closed";
        return false;
    }
    // Install the Lightrider seed callback with wc_SetSeed_Cb immediately
    // after startup (spec 5.1 wiring). The module is built with
    // WC_RNG_SEED_CB, so the DRBG refuses to instantiate until a seed
    // source is installed; every block the callback returns has passed
    // the continuous health tests.
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
    if (!startupHealthTest()) {
        degraded_ = true;
        lastError_ = detail = "entropy health test failed (RCT/APT, " +
                              seedSourceKind() + ")";
        return false;
    }
    detail = "RCT + APT passed (on demand, 1024-sample draw from " +
             seedSourceKind() + ")";
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
    if (!loaded_ || !impl_->libVersion) return "";
    const char* v = impl_->libVersion();
    return v ? v : "";
}

} // namespace veloce
