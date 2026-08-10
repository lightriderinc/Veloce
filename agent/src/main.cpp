// Veloce Agent (spec 3, 5, 7, 8): owns the wolfCrypt FIPS module lifecycle,
// entropy, keys, policy profiles, self-tests, CBOM records and diagnostics.
// Python SDK and CLI are thin clients on the authenticated local IPC
// channel (ipc/protocol.md).
#include "fips_core.hpp"
#include "json.hpp"
#include "keystore.hpp"
#include "pqc_core.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <deque>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using vjson::Value;

namespace {

constexpr const char* kAgentVersion = "1.0.0";
constexpr int kProtocolVersion = 1;
constexpr uint32_t kMaxFrame = 1u << 20;

const char* kBanner =
    "  _   _  ____  __     ___    ____  ____\n"
    " | | | || ___| | |   / _ \\  / ___|| ___|\n"
    " | | | || |_   | |  | | | || |    | |_\n"
    " | |_| || __|  | |__| |_| || |___ | __|\n"
    "  \\___/ |____| |____|\\___/  \\____||____|\n";

struct EmsState {
    std::string mode = "disabled"; // "disabled" | "enabled"
    std::string endpoint;
    bool entropyMixin = false;
    std::string lastMixin = "never";
};

struct StartupStatus {
    bool fipsLoaded = false;
    bool castsPassed = false;
    bool entropyOk = false;
    bool drbgOk = false;
    bool pqcLoaded = false;
    bool pqcSelfTestPassed = false;
    std::string detail;
};

struct Agent {
    veloce::FipsCore fips;
    veloce::PqcCore pqc;
    veloce::KeyStore keys;
    StartupStatus startup;
    EmsState ems;
    Value fipsRecord = Value::object();
    Value pqcRecord = Value::object();
    std::string socketPath;
    std::string activePolicy = "LIGHTRIDER_PQC_TRANSITION";
    time_t startedAt = 0;
    std::atomic<bool> stopping{false};
    int listenFd = -1;

    std::mutex errMutex;
    std::deque<std::string> recentErrors;

    void recordError(const std::string& e) {
        std::lock_guard<std::mutex> lk(errMutex);
        recentErrors.push_back(e);
        if (recentErrors.size() > 64) recentErrors.pop_front();
        syslog(LOG_WARNING, "veloce-agent: %s", e.c_str());
    }
    bool approvedMode() {
        return fips.ok() && startup.castsPassed && startup.drbgOk &&
               startup.pqcLoaded && startup.pqcSelfTestPassed;
    }
    veloce::RandFn randFn() {
        return [this](uint8_t* b, size_t n) {
            return fips.randomBytes(b, n);
        };
    }
};

Agent g_agent;

void onSignal(int) {
    g_agent.stopping = true;
    if (g_agent.listenFd >= 0) close(g_agent.listenFd);
}

std::string defaultSocketPath() {
    const char* env = getenv("VELOCE_SOCKET");
    if (env && *env) return env;
    if (geteuid() == 0) return "/run/veloce/agent.sock";
    const char* home = getenv("HOME");
    return std::string(home ? home : "/tmp") + "/.veloce/agent.sock";
}

bool readFile(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::ostringstream ss;
    ss << f.rdbuf();
    out = ss.str();
    return true;
}

Value loadJsonFile(const std::string& path) {
    std::string text;
    if (!readFile(path, text)) return Value::object();
    try {
        return vjson::Parser::parse(text);
    } catch (...) {
        return Value::object();
    }
}

void mkdirParents(const std::string& path) {
    std::string dir = path.substr(0, path.find_last_of('/'));
    std::string cur;
    std::istringstream ss(dir);
    std::string part;
    while (std::getline(ss, part, '/')) {
        if (part.empty()) { cur = "/"; continue; }
        cur += (cur == "/" || cur.empty()) ? part : "/" + part;
        mkdir(cur.c_str(), 0700);
    }
}

// ---------------------------------------------------------------- policies

Value policyProfiles() {
    Value arr = Value::array();
    auto add = [&](const char* name, const char* group, bool fallback,
                   const char* desc) {
        Value p = Value::object();
        p.set("name", name);
        p.set("tls_version", "1.3");
        p.set("group", group);
        p.set("classical_fallback", fallback);
        p.set("description", desc);
        arr.push(std::move(p));
    };
    add("LIGHTRIDER_PQC_TRANSITION", "X25519MLKEM768", true,
        "Hybrid TLS 1.3; classical fallback permitted during migration");
    add("LIGHTRIDER_PQC_STRICT", "X25519MLKEM768", false,
        "Hybrid TLS 1.3 only; no classical-only fallback");
    add("LIGHTRIDER_CLASSICAL_COMPAT", "X25519", true,
        "Classical TLS 1.3 for legacy interop; flagged quantum-vulnerable");
    return arr;
}

// ---------------------------------------------------------- status builders

Value healthValue() {
    Value v = Value::object();
    bool approved = g_agent.approvedMode();
    v.set("state", approved ? "ok" : "degraded");
    v.set("approved_mode", approved);
    v.set("fips_module_status", g_agent.fips.moduleStatus());
    Value entropy = Value::object();
    entropy.set("source", "wolfEntropy (SP 800-90B, ESV)");
    entropy.set("healthy", g_agent.startup.entropyOk && g_agent.fips.ok());
    entropy.set("fail_mode", "fail-closed (nofallback)");
    v.set("entropy", std::move(entropy));
    v.set("drbg", g_agent.startup.drbgOk && g_agent.fips.ok()
                      ? "instantiated (SP 800-90A Hash_DRBG, 256-bit)"
                      : "unavailable");
    v.set("pqc_provider",
          g_agent.startup.pqcSelfTestPassed ? "self-test passed" : "unavailable");
    Value ems = Value::object();
    ems.set("mode", g_agent.ems.mode);
    ems.set("entropy_mixin", g_agent.ems.entropyMixin ? "on" : "off");
    ems.set("last_mixin", g_agent.ems.lastMixin);
    v.set("ems", std::move(ems));
    v.set("uptime_s", static_cast<int64_t>(time(nullptr) - g_agent.startedAt));
    v.set("keys_held", static_cast<int64_t>(g_agent.keys.size()));
    if (!g_agent.fips.lastError().empty())
        v.set("last_error", g_agent.fips.lastError());
    return v;
}

Value versionValue() {
    Value v = Value::object();
    v.set("agent", kAgentVersion);
    v.set("protocol", kProtocolVersion);
    v.set("product", "Veloce PQC SDK");
    v.set("vendor", "Lightrider Inc");
    v.set("fips_module_version",
          g_agent.fipsRecord.getString("fips_module_version", "5.2.1"));
    v.set("fips_certificate",
          g_agent.fipsRecord.getString("fips_certificate", "#4718"));
    std::string wolf = g_agent.fips.libVersion();
    if (!wolf.empty()) v.set("wolfssl_version", wolf);
    v.set("pqc_source_version",
          g_agent.pqcRecord.getString("source_version", ""));
    return v;
}

Value validationStatusValue() {
    Value items = Value::array();

    Value mod = Value::object();
    mod.set("item", "fips_module");
    mod.set("name", "wolfCrypt FIPS 140-3 module");
    mod.set("module_version",
            g_agent.fipsRecord.getString("fips_module_version", "5.2.1"));
    mod.set("certificate",
            g_agent.fipsRecord.getString("fips_certificate", "#4718"));
    mod.set("library", g_agent.fips.path());
    mod.set("sha256", g_agent.fips.sha256());
    mod.set("sha256_verified_before_load", g_agent.startup.fipsLoaded);
    mod.set("status_code", g_agent.fips.moduleStatus());
    mod.set("self_tests",
            g_agent.startup.castsPassed ? "power-on + CASTs passed"
                                        : "failed or not run");
    items.push(std::move(mod));

    Value ent = Value::object();
    ent.set("item", "entropy_source");
    ent.set("name", "wolfEntropy");
    ent.set("esv", "SP 800-90B ESV-certified source; certificate number and "
                   "OE applicability: vendor confirmation pending");
    ent.set("credited", true);
    ent.set("health", g_agent.startup.entropyOk && g_agent.fips.ok()
                          ? "RCT + APT passing"
                          : "failed (fail-closed)");
    items.push(std::move(ent));

    Value pqc = Value::object();
    pqc.set("item", "pqc_provider");
    pqc.set("pqc_inside_fips_boundary", false);
    Value algs = Value::array();
    algs.push("ML-KEM-768 (FIPS 203)");
    algs.push("ML-DSA-65 (FIPS 204)");
    pqc.set("algorithms", std::move(algs));
    pqc.set("validation", "provider startup self-test (PCT + negative tests); "
                          "CAVP/ACVTS algorithm testing planned; migrates "
                          "in-boundary at wolfSSL FIPS v7");
    pqc.set("library", g_agent.pqc.path());
    pqc.set("sha256", g_agent.pqc.sha256());
    pqc.set("self_test",
            g_agent.startup.pqcSelfTestPassed ? "passed" : "failed");
    items.push(std::move(pqc));

    Value mix = Value::object();
    mix.set("item", "cloud_entropy_mixin");
    mix.set("state", g_agent.ems.entropyMixin ? "on" : "off");
    mix.set("credited", false);
    mix.set("note", "SP 800-90A additional input; never the seed; local "
                    "ESV source remains the sole credited source");
    items.push(std::move(mix));

    Value oe = Value::object();
    oe.set("item", "operational_environment");
    oe.set("environment",
           g_agent.fipsRecord.getString("operating_environment", ""));
    oe.set("note", "cert #4718 tested OEs include Windows 11 Pro x86-64 and "
                   "Linux x86-64 distributions; exact OE match: vendor "
                   "confirmation pending");
    items.push(std::move(oe));

    Value v = Value::object();
    v.set("approved_mode", g_agent.approvedMode());
    v.set("items", std::move(items));
    return v;
}

Value cbomRecords() {
    Value v = Value::object();
    v.set("format", "veloce-cbom-records/1");
    v.set("product", "Veloce PQC SDK");
    v.set("product_version", kAgentVersion);
    v.set("generated_unix", static_cast<int64_t>(time(nullptr)));
    Value records = Value::array();
    records.push(g_agent.fipsRecord);
    records.push(g_agent.pqcRecord);
    Value runtime = Value::object();
    runtime.set("component", "veloce-agent-runtime");
    runtime.set("agent_version", kAgentVersion);
    runtime.set("approved_mode", g_agent.approvedMode());
    runtime.set("fips_library_sha256", g_agent.fips.sha256());
    runtime.set("pqc_library_sha256", g_agent.pqc.sha256());
    runtime.set("ems_enabled", g_agent.ems.mode == "enabled");
    runtime.set("cloud_entropy_mixin",
                g_agent.ems.entropyMixin ? "on" : "off");
    runtime.set("active_policy_profile", g_agent.activePolicy);
    records.push(std::move(runtime));
    v.set("records", std::move(records));
    return v;
}

Value cbomCycloneDx() {
    Value bom = Value::object();
    bom.set("bomFormat", "CycloneDX");
    bom.set("specVersion", "1.6");
    bom.set("version", 1);
    Value metadata = Value::object();
    Value tools = Value::array();
    Value tool = Value::object();
    tool.set("vendor", "Lightrider Inc");
    tool.set("name", "Veloce Agent");
    tool.set("version", kAgentVersion);
    tools.push(std::move(tool));
    metadata.set("tools", std::move(tools));
    bom.set("metadata", std::move(metadata));

    Value comps = Value::array();

    Value mod = Value::object();
    mod.set("type", "cryptographic-asset");
    mod.set("name", "wolfCrypt FIPS 140-3 module");
    mod.set("version",
            g_agent.fipsRecord.getString("fips_module_version", "5.2.1"));
    Value modProps = Value::object();
    modProps.set("assetType", "certificate");
    Value modCert = Value::object();
    modCert.set("certificationLevel", "FIPS 140-3");
    modCert.set("certificateNumber",
                g_agent.fipsRecord.getString("fips_certificate", "#4718"));
    modProps.set("certificateProperties", std::move(modCert));
    mod.set("cryptoProperties", std::move(modProps));
    Value modHashes = Value::array();
    Value mh = Value::object();
    mh.set("alg", "SHA-256");
    mh.set("content", g_agent.fips.sha256());
    modHashes.push(std::move(mh));
    mod.set("hashes", std::move(modHashes));
    comps.push(std::move(mod));

    auto algoComp = [&](const char* name, const char* primitive,
                        const char* param, int nist) {
        Value c = Value::object();
        c.set("type", "cryptographic-asset");
        c.set("name", name);
        Value cp = Value::object();
        cp.set("assetType", "algorithm");
        Value ap = Value::object();
        ap.set("primitive", primitive);
        ap.set("parameterSetIdentifier", param);
        ap.set("nistQuantumSecurityLevel", nist);
        cp.set("algorithmProperties", std::move(ap));
        c.set("cryptoProperties", std::move(cp));
        comps.push(std::move(c));
    };
    algoComp("ML-KEM-768", "kem", "768", 3);
    algoComp("ML-DSA-65", "signature", "65", 3);

    Value ent = Value::object();
    ent.set("type", "cryptographic-asset");
    ent.set("name", "wolfEntropy (SP 800-90B ESV source)");
    Value entProps = Value::object();
    entProps.set("assetType", "related-crypto-material");
    ent.set("cryptoProperties", std::move(entProps));
    comps.push(std::move(ent));

    bom.set("components", std::move(comps));
    return bom;
}

// ------------------------------------------------------------------ server

bool sendFrame(int fd, const std::string& payload) {
    uint32_t len = htonl(static_cast<uint32_t>(payload.size()));
    char hdr[4];
    memcpy(hdr, &len, 4);
    std::string out(hdr, 4);
    out += payload;
    size_t off = 0;
    while (off < out.size()) {
        ssize_t n = write(fd, out.data() + off, out.size() - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool recvExact(int fd, void* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, static_cast<char*>(buf) + off, len - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

Value errorValue(const std::string& code, const std::string& message) {
    Value e = Value::object();
    e.set("code", code);
    e.set("message", message);
    return e;
}

// Returns ok flag; fills result or error.
bool dispatch(const std::string& op, const Value& params, Value& result,
              Value& error) {
    auto needApproved = [&]() -> bool {
        if (g_agent.approvedMode()) return true;
        error = errorValue("degraded",
                           "agent is fail-closed (entropy, self-test or "
                           "module failure); crypto services refused");
        return false;
    };
    auto getB64 = [&](const char* key, std::vector<uint8_t>& out) -> bool {
        const Value* v = params.find(key);
        if (!v || !v->isString() || !vjson::b64decode(v->asString(), out)) {
            error = errorValue("bad_request",
                               std::string("missing or invalid base64 "
                                           "parameter: ") + key);
            return false;
        }
        return true;
    };

    if (op == "initialize" || op == "health") {
        result = healthValue();
        if (op == "initialize") result.set("initialized", true);
        return true;
    }
    if (op == "version") {
        result = versionValue();
        return true;
    }
    if (op == "list_policy_profiles") {
        result = Value::object();
        result.set("active", g_agent.activePolicy);
        result.set("profiles", policyProfiles());
        return true;
    }
    if (op == "list_crypto_providers") {
        result = Value::object();
        Value arr = Value::array();
        Value m = Value::object();
        m.set("name", "wolfCrypt FIPS 140-3 module");
        m.set("kind", "fips_module");
        m.set("certificate",
              g_agent.fipsRecord.getString("fips_certificate", "#4718"));
        m.set("library", g_agent.fips.path());
        m.set("sha256", g_agent.fips.sha256());
        arr.push(std::move(m));
        Value p = Value::object();
        p.set("name", "Veloce PQC provider");
        p.set("kind", "pqc_provider");
        p.set("pqc_inside_fips_boundary", false);
        p.set("library", g_agent.pqc.path());
        p.set("sha256", g_agent.pqc.sha256());
        arr.push(std::move(p));
        result.set("providers", std::move(arr));
        return true;
    }
    if (op == "list_entropy_providers") {
        result = Value::object();
        Value arr = Value::array();
        Value w = Value::object();
        w.set("name", "wolfEntropy");
        w.set("type", "software (memory-access timing jitter)");
        w.set("esv_certified", true);
        w.set("credited", true);
        w.set("health", g_agent.startup.entropyOk && g_agent.fips.ok()
                            ? "ok" : "failed");
        arr.push(std::move(w));
        Value c = Value::object();
        c.set("name", "cloud-entropy-mixin");
        c.set("type", "EMS-delivered DRBG additional input");
        c.set("esv_certified", false);
        c.set("credited", false);
        c.set("state", g_agent.ems.entropyMixin ? "on" : "off");
        c.set("last_mixin", g_agent.ems.lastMixin);
        arr.push(std::move(c));
        result.set("providers", std::move(arr));
        return true;
    }
    if (op == "validation_status") {
        result = validationStatusValue();
        return true;
    }
    if (op == "approved_mode_status") {
        result = Value::object();
        result.set("approved", g_agent.approvedMode());
        result.set("fips_module_status", g_agent.fips.moduleStatus());
        result.set("detail", g_agent.approvedMode()
                                 ? "module, entropy, DRBG and PQC self-tests "
                                   "all passing"
                                 : g_agent.fips.lastError().empty()
                                       ? g_agent.startup.detail
                                       : g_agent.fips.lastError());
        return true;
    }
    if (op == "run_fips_self_tests") {
        result = Value::object();
        std::string err;
        bool casts = g_agent.fips.runCasts(err);
        result.set("casts", casts ? "pass" : "fail: " + err);
        if (casts) g_agent.startup.castsPassed = true;
        std::string edetail;
        bool eok = g_agent.fips.entropyOnDemandTest(edetail);
        result.set("entropy_health", eok ? "pass: " + edetail
                                         : "fail: " + edetail);
        std::string perr;
        bool pqc = g_agent.approvedMode()
                       ? g_agent.pqc.selfTest(g_agent.randFn(), perr)
                       : false;
        result.set("pqc_self_test",
                   pqc ? "pass" : "fail: " + (perr.empty() ? "skipped "
                       "(degraded)" : perr));
        result.set("module_status", g_agent.fips.moduleStatus());
        if (!casts || !eok) {
            g_agent.recordError("self-test failure: " + err + " " + edetail);
        }
        return true;
    }
    if (op == "mlkem_generate_keypair") {
        if (!needApproved()) return false;
        int64_t ps = params.getInt("parameter_set", 768);
        if (ps != 768) {
            error = errorValue("bad_request",
                               "V1 supports ML-KEM-768 only (default)");
            return false;
        }
        std::vector<uint8_t> pub, priv;
        std::string err;
        if (!g_agent.pqc.mlkemKeygen(g_agent.randFn(), pub, priv, err)) {
            g_agent.recordError(err);
            error = errorValue("crypto_error", err);
            return false;
        }
        uint8_t hr[16];
        if (!g_agent.fips.randomBytes(hr, sizeof(hr))) {
            error = errorValue("degraded", "DRBG unavailable");
            return false;
        }
        veloce::KeyEntry e;
        e.algorithm = "ML-KEM";
        e.parameterSet = 768;
        e.pub = pub;
        e.priv = std::move(priv);
        std::string handle = g_agent.keys.put(std::move(e), hr);
        result = Value::object();
        result.set("public_key", vjson::b64encode(pub));
        result.set("private_key_handle", handle);
        result.set("parameter_set", 768);
        return true;
    }
    if (op == "mlkem_encapsulate") {
        if (!needApproved()) return false;
        std::vector<uint8_t> pub;
        if (!getB64("public_key", pub)) return false;
        std::vector<uint8_t> ct, ss;
        std::string err;
        if (!g_agent.pqc.mlkemEncapsulate(g_agent.randFn(), pub, ct, ss,
                                          err)) {
            g_agent.recordError(err);
            error = errorValue("crypto_error", err);
            return false;
        }
        result = Value::object();
        result.set("ciphertext", vjson::b64encode(ct));
        result.set("shared_secret", vjson::b64encode(ss));
        veloce::zeroize(ss);
        return true;
    }
    if (op == "mlkem_decapsulate") {
        if (!needApproved()) return false;
        std::string handle = params.getString("private_key_handle");
        veloce::KeyEntry e;
        if (!g_agent.keys.get(handle, e) || e.algorithm != "ML-KEM") {
            error = errorValue("invalid_handle", "unknown ML-KEM key handle");
            return false;
        }
        std::vector<uint8_t> ct;
        if (!getB64("ciphertext", ct)) return false;
        std::vector<uint8_t> ss;
        std::string err;
        bool ok = g_agent.pqc.mlkemDecapsulate(e.priv, ct, ss, err);
        veloce::zeroize(e.priv);
        if (!ok) {
            g_agent.recordError(err);
            error = errorValue("crypto_error", err);
            return false;
        }
        result = Value::object();
        result.set("shared_secret", vjson::b64encode(ss));
        veloce::zeroize(ss);
        return true;
    }
    if (op == "mldsa_generate_keypair") {
        if (!needApproved()) return false;
        int64_t ps = params.getInt("parameter_set", 65);
        if (ps != 65) {
            error = errorValue("bad_request",
                               "V1 supports ML-DSA-65 only (default)");
            return false;
        }
        std::vector<uint8_t> pub, priv;
        std::string err;
        if (!g_agent.pqc.mldsaKeygen(g_agent.randFn(), pub, priv, err)) {
            g_agent.recordError(err);
            error = errorValue("crypto_error", err);
            return false;
        }
        uint8_t hr[16];
        if (!g_agent.fips.randomBytes(hr, sizeof(hr))) {
            error = errorValue("degraded", "DRBG unavailable");
            return false;
        }
        veloce::KeyEntry e;
        e.algorithm = "ML-DSA";
        e.parameterSet = 65;
        e.pub = pub;
        e.priv = std::move(priv);
        std::string handle = g_agent.keys.put(std::move(e), hr);
        result = Value::object();
        result.set("public_key", vjson::b64encode(pub));
        result.set("private_key_handle", handle);
        result.set("parameter_set", 65);
        return true;
    }
    if (op == "mldsa_sign") {
        if (!needApproved()) return false;
        std::string handle = params.getString("private_key_handle");
        veloce::KeyEntry e;
        if (!g_agent.keys.get(handle, e) || e.algorithm != "ML-DSA") {
            error = errorValue("invalid_handle", "unknown ML-DSA key handle");
            return false;
        }
        std::vector<uint8_t> msg;
        if (!getB64("message", msg)) return false;
        std::vector<uint8_t> sig;
        std::string err;
        bool ok = g_agent.pqc.mldsaSign(g_agent.randFn(), e.priv, e.pub, msg,
                                        sig, err);
        veloce::zeroize(e.priv);
        if (!ok) {
            g_agent.recordError(err);
            error = errorValue("crypto_error", err);
            return false;
        }
        result = Value::object();
        result.set("signature", vjson::b64encode(sig));
        return true;
    }
    if (op == "mldsa_verify") {
        if (!needApproved()) return false;
        std::vector<uint8_t> pub, msg, sig;
        if (!getB64("public_key", pub) || !getB64("message", msg) ||
            !getB64("signature", sig))
            return false;
        bool valid = false;
        std::string err;
        if (!g_agent.pqc.mldsaVerify(pub, msg, sig, valid, err)) {
            error = errorValue("crypto_error", err);
            return false;
        }
        result = Value::object();
        result.set("valid", valid);
        return true;
    }
    if (op == "configure_hybrid_tls") {
        std::string policy =
            params.getString("policy", "LIGHTRIDER_PQC_TRANSITION");
        Value profiles = policyProfiles();
        const Value* found = nullptr;
        for (const auto& p : profiles.items()) {
            if (p.getString("name") == policy) { found = &p; break; }
        }
        if (!found) {
            error = errorValue("bad_request", "unknown policy profile: " +
                                                  policy);
            return false;
        }
        g_agent.activePolicy = policy;
        result = Value::object();
        result.set("policy", policy);
        result.set("tls_version", found->getString("tls_version"));
        result.set("group", found->getString("group"));
        result.set("classical_fallback", found->getBool("classical_fallback"));
        result.set("note", "policy stored for the agent TLS data plane and "
                           "sample client/server (examples/)");
        return true;
    }
    if (op == "export_cbom") {
        std::string format = params.getString("format", "records");
        if (format == "records") {
            result = cbomRecords();
        } else if (format == "cyclonedx") {
            result = cbomCycloneDx();
        } else {
            error = errorValue("bad_request",
                               "format must be records or cyclonedx");
            return false;
        }
        return true;
    }
    if (op == "generate_diagnostic_bundle") {
        std::string path = params.getString("path");
        if (path.empty()) {
            path = g_agent.socketPath.substr(
                       0, g_agent.socketPath.find_last_of('/')) +
                   "/diag-" + std::to_string(time(nullptr)) + ".json";
        }
        Value bundle = Value::object();
        bundle.set("product", "Veloce PQC SDK diagnostic bundle");
        bundle.set("generated_unix", static_cast<int64_t>(time(nullptr)));
        bundle.set("version", versionValue());
        bundle.set("health", healthValue());
        bundle.set("validation_status", validationStatusValue());
        Value errs = Value::array();
        {
            std::lock_guard<std::mutex> lk(g_agent.errMutex);
            for (const auto& e : g_agent.recentErrors) errs.push(e);
        }
        bundle.set("recent_errors", std::move(errs));
        bundle.set("redaction",
                   "bundle contains metadata only: no keys, seeds, "
                   "passwords, tokens or customer plaintext");
        std::string text = bundle.dump();
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            error = errorValue("internal",
                               "cannot write bundle: " +
                                   std::string(strerror(errno)));
            return false;
        }
        ssize_t w = write(fd, text.data(), text.size());
        close(fd);
        if (w != static_cast<ssize_t>(text.size())) {
            error = errorValue("internal", "short write to bundle");
            return false;
        }
        result = Value::object();
        result.set("path", path);
        result.set("bytes", static_cast<int64_t>(text.size()));
        return true;
    }
    if (op == "set_entropy_mixin") {
        if (g_agent.ems.mode != "enabled") {
            error = errorValue("ems_disabled",
                               "EMS is disabled; enable ems.mode in the "
                               "agent configuration first (default off, "
                               "zero network traffic)");
            return false;
        }
        const Value* en = params.find("enabled");
        if (!en || !en->isBool()) {
            error = errorValue("bad_request", "enabled (bool) required");
            return false;
        }
        g_agent.ems.entropyMixin = en->asBool();
        if (g_agent.ems.entropyMixin) {
            g_agent.ems.lastMixin =
                "pending: no packet received; local operation unaffected "
                "(fail-safe)";
        }
        result = Value::object();
        result.set("entropy_mixin", g_agent.ems.entropyMixin ? "on" : "off");
        result.set("last_mixin", g_agent.ems.lastMixin);
        return true;
    }
    if (op == "release_key") {
        std::string handle = params.getString("private_key_handle");
        if (!g_agent.keys.release(handle)) {
            error = errorValue("invalid_handle", "unknown key handle");
            return false;
        }
        result = Value::object();
        result.set("released", true);
        return true;
    }
    if (op == "shutdown") {
        result = Value::object();
        result.set("stopping", true);
        g_agent.stopping = true;
        if (g_agent.listenFd >= 0) shutdown(g_agent.listenFd, SHUT_RDWR);
        return true;
    }
    error = errorValue("unknown_op", "unsupported operation: " + op);
    return false;
}

void serveConnection(int fd) {
    while (!g_agent.stopping) {
        uint32_t lenBe = 0;
        if (!recvExact(fd, &lenBe, 4)) break;
        uint32_t len = ntohl(lenBe);
        if (len == 0 || len > kMaxFrame) break;
        std::string payload(len, '\0');
        if (!recvExact(fd, payload.data(), len)) break;

        Value resp = Value::object();
        resp.set("v", kProtocolVersion);
        try {
            Value req = vjson::Parser::parse(payload);
            resp.set("id", req.getInt("id", 0));
            if (req.getInt("v", 0) != kProtocolVersion) {
                resp.set("ok", false);
                resp.set("error",
                         errorValue("bad_request", "unsupported protocol "
                                                   "version"));
                sendFrame(fd, resp.dump());
                break;
            }
            std::string op = req.getString("op");
            const Value* params = req.find("params");
            Value empty = Value::object();
            Value result, errv;
            bool ok = dispatch(op, params ? *params : empty, result, errv);
            resp.set("ok", ok);
            if (ok) resp.set("result", std::move(result));
            else resp.set("error", std::move(errv));
            if (!sendFrame(fd, resp.dump())) break;
        } catch (const std::exception& ex) {
            resp.set("ok", false);
            resp.set("error", errorValue("bad_request",
                                         std::string("parse error: ") +
                                             ex.what()));
            sendFrame(fd, resp.dump());
            break;
        }
    }
    close(fd);
}

bool peerAuthorized(int fd) {
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
        return false;
    return cred.uid == geteuid() || cred.uid == 0;
}

void printBanner(bool quiet) {
    std::string status = std::string("FIPS 140-3 ") +
        g_agent.fipsRecord.getString("fips_certificate", "#4718") +
        " | ESV entropy: " +
        (g_agent.startup.entropyOk && g_agent.fips.ok() ? "OK" : "FAILED") +
        " | approved mode: " + (g_agent.approvedMode() ? "on" : "off");
    std::string line1 = std::string("Lightrider Inc -- Veloce PQC SDK v") +
                        kAgentVersion;
    syslog(LOG_INFO, "%s", line1.c_str());
    syslog(LOG_INFO, "%s", status.c_str());
    bool noBanner = getenv("VELOCE_NO_BANNER") &&
                    std::string(getenv("VELOCE_NO_BANNER")) == "1";
    if (quiet || noBanner || !isatty(STDOUT_FILENO)) return;
    printf("%s%s\n%s\n", kBanner, line1.c_str(), status.c_str());
    fflush(stdout);
}

} // namespace

int main(int argc, char** argv) {
    std::string configPath;
    bool quiet = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--config" && i + 1 < argc) configPath = argv[++i];
        else if (a == "--quiet") quiet = true;
    }
    if (configPath.empty()) {
        const char* env = getenv("VELOCE_CONFIG");
        if (env) configPath = env;
    }
    openlog("veloce-agent", LOG_PID, LOG_DAEMON);

    Value cfg = configPath.empty() ? Value::object()
                                   : loadJsonFile(configPath);
    g_agent.socketPath = cfg.getString("socket", defaultSocketPath());
    std::string fipsLib = cfg.getString("fips_lib");
    std::string fipsRecordPath = cfg.getString("fips_record");
    std::string pqcLib = cfg.getString("pqc_lib");
    std::string pqcRecordPath = cfg.getString("pqc_record");
    if (const Value* ems = cfg.find("ems")) {
        g_agent.ems.mode = ems->getString("mode", "disabled");
        g_agent.ems.endpoint = ems->getString("endpoint", "");
        g_agent.ems.entropyMixin =
            ems->getString("entropy_mixin", "off") == "on";
    }
    g_agent.startedAt = time(nullptr);

    if (!fipsRecordPath.empty())
        g_agent.fipsRecord = loadJsonFile(fipsRecordPath);
    if (!pqcRecordPath.empty())
        g_agent.pqcRecord = loadJsonFile(pqcRecordPath);

    // Startup sequence (spec 5): every failure leaves the agent serving
    // status ops in a fail-closed degraded state.
    std::string err;
    if (fipsLib.empty()) {
        g_agent.startup.detail = "no fips_lib configured";
        g_agent.recordError(g_agent.startup.detail);
    } else if (!g_agent.fips.load(fipsLib,
                                  g_agent.fipsRecord.getString("sha256"),
                                  err)) {
        g_agent.startup.detail = err;
        g_agent.recordError(err);
    } else {
        g_agent.startup.fipsLoaded = true;
        if (!g_agent.fips.start(err)) {
            g_agent.startup.detail = err;
            g_agent.recordError(err);
        } else {
            g_agent.startup.entropyOk = true;
            g_agent.startup.drbgOk = true;
            if (!g_agent.fips.runCasts(err)) {
                g_agent.startup.detail = err;
                g_agent.recordError(err);
            } else {
                g_agent.startup.castsPassed = true;
            }
        }
    }
    if (g_agent.startup.castsPassed) {
        if (pqcLib.empty()) {
            g_agent.startup.detail = "no pqc_lib configured";
            g_agent.recordError(g_agent.startup.detail);
        } else if (!g_agent.pqc.load(pqcLib,
                                     g_agent.pqcRecord.getString("sha256"),
                                     err)) {
            g_agent.startup.detail = err;
            g_agent.recordError(err);
        } else {
            g_agent.startup.pqcLoaded = true;
            if (!g_agent.pqc.selfTest(g_agent.randFn(), err)) {
                g_agent.startup.pqcSelfTestPassed = false;
                g_agent.startup.detail = err;
                g_agent.recordError(err);
            } else {
                g_agent.startup.pqcSelfTestPassed = true;
            }
        }
    }

    printBanner(quiet);

    mkdirParents(g_agent.socketPath);
    unlink(g_agent.socketPath.c_str());
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "veloce-agent: socket: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (g_agent.socketPath.size() >= sizeof(addr.sun_path)) {
        fprintf(stderr, "veloce-agent: socket path too long\n");
        return 1;
    }
    strncpy(addr.sun_path, g_agent.socketPath.c_str(),
            sizeof(addr.sun_path) - 1);
    if (bind(fd, reinterpret_cast<struct sockaddr*>(&addr),
             sizeof(addr)) != 0) {
        fprintf(stderr, "veloce-agent: bind %s: %s\n",
                g_agent.socketPath.c_str(), strerror(errno));
        return 1;
    }
    chmod(g_agent.socketPath.c_str(), 0660);
    if (listen(fd, 16) != 0) {
        fprintf(stderr, "veloce-agent: listen: %s\n", strerror(errno));
        return 1;
    }
    g_agent.listenFd = fd;
    signal(SIGINT, onSignal);
    signal(SIGTERM, onSignal);
    signal(SIGPIPE, SIG_IGN);
    syslog(LOG_INFO, "veloce-agent listening on %s (approved_mode=%s)",
           g_agent.socketPath.c_str(),
           g_agent.approvedMode() ? "on" : "off");

    std::vector<std::thread> workers;
    while (!g_agent.stopping) {
        int cfd = accept(fd, nullptr, nullptr);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (!peerAuthorized(cfd)) {
            g_agent.recordError("rejected unauthorized local peer");
            close(cfd);
            continue;
        }
        workers.emplace_back(serveConnection, cfd);
    }

    for (auto& t : workers)
        if (t.joinable()) t.join();
    g_agent.keys.releaseAll(); // zeroization on shutdown (spec 8)
    unlink(g_agent.socketPath.c_str());
    syslog(LOG_INFO, "veloce-agent stopped");
    closelog();
    return 0;
}
