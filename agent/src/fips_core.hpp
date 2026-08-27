// FIPS crypto core interface (spec 5): loads the wolfCrypt FIPS 140-3
// module (cert #4718) as a shared library, verifies the file against the
// recorded build hash before dlopen, surfaces module status and CASTs,
// and is the sole source of DRBG output for the agent. Fail-closed: any
// entropy or self-test failure marks the core degraded and every consumer
// refuses service (spec 5.1).
//
// This header exposes no wolfSSL types; the implementation unit is the
// only FIPS-boundary-aware code in the agent.
#pragma once

#include <cstdint>
#include <string>

namespace veloce {

class FipsCore {
public:
    FipsCore();
    ~FipsCore();
    FipsCore(const FipsCore&) = delete;
    FipsCore& operator=(const FipsCore&) = delete;

    // Verify sha256(libPath) == expectedSha256Hex, dlopen with RTLD_LOCAL,
    // resolve symbols. Returns false and sets err on any mismatch.
    bool load(const std::string& libPath, const std::string& expectedSha256Hex,
              std::string& err);

    // Register the Lightrider seed callback (wc_SetSeed_Cb) and
    // instantiate the DRBG. The module makes no entropy claim (#4718 SP
    // 11.1); every seed block comes from the OS kernel entropy interface
    // and passes RCT/APT verification before delivery. Fail-closed.
    bool start(std::string& err);

    // wolfCrypt_GetStatus_fips(); 0 means the module is in the approved
    // state (power-on self-tests passed, no error latched).
    int moduleStatus();

    // wc_RunAllCast_fips(): run all conditional algorithm self-tests.
    bool runCasts(std::string& err);

    // On-demand health test: draw a fresh sample from the OS kernel
    // entropy source and run the same RCT/APT verification used on the
    // seed path. Does not touch the DRBG.
    bool entropySelfTest(std::string& detail);

    // Seed-path counters for status reporting (spec 6.3 entropy UI).
    static uint64_t seedBlocksVerified();
    static uint64_t seedBytesVerified();
    static uint64_t seedHealthFailures();
    static int64_t lastSeedUnix();

    // FIPS DRBG output. False (and degraded state) on failure.
    bool randomBytes(uint8_t* out, size_t len);

    bool ok() const { return loaded_ && !degraded_; }
    bool degraded() const { return degraded_; }
    const std::string& lastError() const { return lastError_; }
    const std::string& sha256() const { return sha256_; }
    const std::string& path() const { return path_; }
    std::string libVersion() const;

private:
    struct Impl;
    Impl* impl_ = nullptr;
    bool loaded_ = false;
    bool degraded_ = false;
    std::string lastError_;
    std::string sha256_;
    std::string path_;
};

} // namespace veloce
