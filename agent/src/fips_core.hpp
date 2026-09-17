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
#include <vector>

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

    // Select the seed source before start(): "rdseed" (default; x86-64
    // RDSEED hardware entropy, fails closed when the processor lacks it)
    // or "os-drbg" (operating system DRBG output; an SP 800-90C RBGC
    // chain with no security-strength claim, explicit opt-in only).
    bool setSeedSource(const std::string& name, std::string& err);
    static bool rdseedAvailable();

    // Reporting helpers for status, validation, CBOM, and banner output.
    std::string seedSourceKind() const;        // "cpu-rdseed" | "os-drbg" | "none"
    std::string seedSourceDescription() const;
    std::string rbgConstruction() const;
    std::string securityStrengthClaim() const;
    bool seedSourceIsHardware() const;
    static std::string healthTestSpec();

    // Run the SP 800-90B startup health test on the selected source,
    // register the Lightrider seed callback (wc_SetSeed_Cb) and
    // instantiate the DRBG. The module makes no entropy claim (#4718 SP
    // section 2.8); every seed block passes RCT/APT before delivery.
    // Fail-closed.
    bool start(std::string& err);

    // wolfCrypt_GetStatus_fips(); 0 means the module is in the approved
    // state (power-on self-tests passed, no error latched).
    int moduleStatus();

    // wc_RunAllCast_fips(): run all conditional algorithm self-tests.
    bool runCasts(std::string& err);

    // On-demand health test: draw a fresh 1024-sample block from the
    // selected seed source and run the same RCT/APT tests used on the
    // seed path. Does not touch the DRBG.
    bool entropySelfTest(std::string& detail);

    // Seed-path counters for status reporting (spec 6.3 entropy UI).
    static uint64_t seedBlocksVerified();
    static uint64_t seedBytesVerified();
    static uint64_t seedHealthFailures();
    static int64_t lastSeedUnix();

    // FIPS DRBG output. False (and degraded state) on failure.
    bool randomBytes(uint8_t* out, size_t len);

    // Cloud entropy mix-in (spec 6): re-instantiate the DRBG with fresh
    // seed-source entropy from the registered callback and `nonce` as the
    // SP 800-90A instantiation nonce. The nonce is mixed by Hash_df but
    // credited with zero entropy; the seed source remains the sole credit.
    // The module exports no additional-input or reseed entry point, so
    // re-instantiation through wc_InitRngNonce is the mixing mechanism.
    bool reinstantiateWithNonce(const std::vector<uint8_t>& nonce,
                                std::string& err);

    // Resolve an exported symbol of the loaded module (used by the EMS
    // client for the module's TLS 1.3 client, so the cloud fetch uses FIPS
    // cryptography). Null when the module is not loaded.
    void* symbol(const char* name) const;

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
