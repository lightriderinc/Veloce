// PQC provider interface (spec 5.3): ML-KEM-768 and ML-DSA-65 from the
// provider library compiled beside the FIPS boundary. All randomness is
// supplied by the caller from the FIPS DRBG (*WithRandom / *WithSeed APIs);
// the provider never seeds itself. pqc_inside_fips_boundary: false.
//
// This header exposes no wolfSSL types; the implementation unit is
// compiled against the provider build's settings.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace veloce {

// Fills the buffer from the FIPS DRBG; returns false on failure.
using RandFn = std::function<bool(uint8_t*, size_t)>;

class PqcCore {
public:
    PqcCore();
    ~PqcCore();
    PqcCore(const PqcCore&) = delete;
    PqcCore& operator=(const PqcCore&) = delete;

    bool load(const std::string& libPath, const std::string& expectedSha256Hex,
              std::string& err);

    // Pairwise-consistency and negative self-tests (spec 9, PQC gates).
    bool selfTest(const RandFn& rand, std::string& err);

    // ML-KEM-768. Keygen consumes 64 bytes of FIPS DRBG output,
    // encapsulation 32 (FIPS 203 d||z and m).
    bool mlkemKeygen(const RandFn& rand, std::vector<uint8_t>& pub,
                     std::vector<uint8_t>& priv, std::string& err);
    bool mlkemEncapsulate(const RandFn& rand, const std::vector<uint8_t>& pub,
                          std::vector<uint8_t>& ct, std::vector<uint8_t>& ss,
                          std::string& err);
    bool mlkemDecapsulate(const std::vector<uint8_t>& priv,
                          const std::vector<uint8_t>& ct,
                          std::vector<uint8_t>& ss, std::string& err);

    // ML-DSA-65. Keygen and hedged signing consume 32-byte seeds of FIPS
    // DRBG output (FIPS 204 xi and rnd). Signing is verify-after-sign
    // fault-hardened; pub must belong to priv.
    bool mldsaKeygen(const RandFn& rand, std::vector<uint8_t>& pub,
                     std::vector<uint8_t>& priv, std::string& err);
    bool mldsaSign(const RandFn& rand, const std::vector<uint8_t>& priv,
                   const std::vector<uint8_t>& pub,
                   const std::vector<uint8_t>& msg, std::vector<uint8_t>& sig,
                   std::string& err);
    bool mldsaVerify(const std::vector<uint8_t>& pub,
                     const std::vector<uint8_t>& msg,
                     const std::vector<uint8_t>& sig, bool& valid,
                     std::string& err);

    bool ok() const { return loaded_; }
    const std::string& sha256() const { return sha256_; }
    const std::string& path() const { return path_; }

private:
    struct Impl;
    bool mldsaVerifyLocked(const std::vector<uint8_t>& pub,
                           const std::vector<uint8_t>& msg,
                           const std::vector<uint8_t>& sig, bool& valid,
                           std::string& err);
    static void zeroizeVec(std::vector<uint8_t>& v);
    Impl* impl_ = nullptr;
    bool loaded_ = false;
    std::string sha256_;
    std::string path_;
};

} // namespace veloce
