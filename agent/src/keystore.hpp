// In-agent key custody (spec 8): all private keys live here, referenced
// externally only by opaque handles; zeroization on release and shutdown.
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace veloce {

struct KeyEntry {
    std::string algorithm;      // "ML-KEM" | "ML-DSA"
    int parameterSet = 0;       // 768, 65, ...
    std::vector<uint8_t> priv;
    std::vector<uint8_t> pub;
};

inline void zeroize(std::vector<uint8_t>& v) {
    volatile uint8_t* p = v.data();
    for (size_t i = 0; i < v.size(); i++) p[i] = 0;
    v.clear();
}

class KeyStore {
public:
    // rand supplies handle entropy (FIPS DRBG output).
    std::string put(KeyEntry entry, const uint8_t rand[16]) {
        static const char* digits = "0123456789abcdef";
        std::string handle = "vlk-";
        for (int i = 0; i < 16; i++) {
            handle += digits[rand[i] >> 4];
            handle += digits[rand[i] & 15];
        }
        std::lock_guard<std::mutex> lk(m_);
        keys_[handle] = std::move(entry);
        return handle;
    }

    bool get(const std::string& handle, KeyEntry& out) {
        std::lock_guard<std::mutex> lk(m_);
        auto it = keys_.find(handle);
        if (it == keys_.end()) return false;
        out = it->second;
        return true;
    }

    bool release(const std::string& handle) {
        std::lock_guard<std::mutex> lk(m_);
        auto it = keys_.find(handle);
        if (it == keys_.end()) return false;
        zeroize(it->second.priv);
        zeroize(it->second.pub);
        keys_.erase(it);
        return true;
    }

    void releaseAll() {
        std::lock_guard<std::mutex> lk(m_);
        for (auto& kv : keys_) {
            zeroize(kv.second.priv);
            zeroize(kv.second.pub);
        }
        keys_.clear();
    }

    size_t size() {
        std::lock_guard<std::mutex> lk(m_);
        return keys_.size();
    }

private:
    std::mutex m_;
    std::map<std::string, KeyEntry> keys_;
};

} // namespace veloce
