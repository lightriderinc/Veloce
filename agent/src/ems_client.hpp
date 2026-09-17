// Cloud entropy (EMS) client: fetches a signed entropy packet from the
// Lightrider EMS egress over HTTPS and canonicalizes its receipt for
// signature verification (spec 6, cloud entropy mix-in).
//
// Transport: TLS 1.2/1.3 client functions resolved from the loaded FIPS
// module (wolfSSL), so the fetch uses FIPS cryptography and adds no new
// library. Trust anchor: the configured CA file, or the embedded ISRG Root
// X1 certificate (Let's Encrypt) that signs ems.lightriderinc.com.
//
// Verification of the receipt signature and freshness, and the DRBG mix-in
// itself, live in the agent (main.cpp); this unit only moves bytes.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace veloce {

class FipsCore;

struct EmsReceipt {
    std::string requestId;
    std::string applicationId;
    std::string policy;
    std::string poolId;
    std::string signatureAlg;
    std::string drbgAlg;
    std::string auditEventId;
    uint64_t timestampNs = 0;
    int qualityScore = 0;
    bool rctPass = false;
    bool aptPass = false;
    bool rawEntropyStored = true;
    uint32_t outputBytes = 0;
    std::vector<uint8_t> signature;   // decoded from the receipt's hex
    std::string canonical;            // signed message: sorted-key compact
                                      // JSON with "signature" removed
};

struct EmsFetch {
    bool ok = false;
    int httpStatus = 0;
    std::string error;
    std::vector<uint8_t> bytes;       // decoded entropy packet
    EmsReceipt receipt;
};

class EmsClient {
public:
    explicit EmsClient(FipsCore& fips);
    ~EmsClient();
    EmsClient(const EmsClient&) = delete;
    EmsClient& operator=(const EmsClient&) = delete;

    // endpoint: https://host[:port][/base]. caFile: PEM bundle path or
    // empty for the embedded ISRG Root X1 anchor.
    bool configure(const std::string& endpoint, const std::string& caFile,
                   std::string& err);

    // POST /v1/entropy/request. apiKey may be empty (Free tier).
    EmsFetch requestEntropy(uint32_t bytes, const std::string& policy,
                            const std::string& apiKey,
                            const std::string& applicationId,
                            const std::string& clientNonce,
                            int timeoutSeconds);

    const std::string& host() const;

    // Canonical receipt: top-level members sorted by key (byte order),
    // "signature" removed, compact serialization. Operates on the raw JSON
    // text so 64-bit integers are preserved exactly.
    static bool canonicalizeReceipt(const std::string& rawReceiptObject,
                                    std::string& canonical, std::string& err);

    // Split a JSON object's top-level members into (key, raw value) pairs.
    static bool splitObjectMembers(
        const std::string& object,
        std::vector<std::pair<std::string, std::string>>& members,
        std::string& err);

    static bool hexDecode(const std::string& hex, std::vector<uint8_t>& out);

private:
    struct Impl;
    Impl* impl_ = nullptr;
};

} // namespace veloce
