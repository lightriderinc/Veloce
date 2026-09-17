// EMS client implementation. Compiled against the FIPS build's headers
// (like fips_core.cpp); every TLS function is resolved through
// FipsCore::symbol from the already loaded, hash-verified module.
#include "ems_client.hpp"
#include "fips_core.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
#endif

namespace veloce {

namespace {

// ISRG Root X1 (Let's Encrypt), valid to 2035-06-04. Trust anchor for
// ems.lightriderinc.com when no CA file is configured.
const char kIsrgRootX1[] =
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "-----END CERTIFICATE-----\n";

using FnInit = int (*)(void);
using FnMethod = WOLFSSL_METHOD* (*)(void);
using FnCtxNew = WOLFSSL_CTX* (*)(WOLFSSL_METHOD*);
using FnCtxFree = void (*)(WOLFSSL_CTX*);
using FnCtxLoadLocations = int (*)(WOLFSSL_CTX*, const char*, const char*);
using FnCtxLoadBuffer = int (*)(WOLFSSL_CTX*, const unsigned char*, long, int);
using FnCtxSetVerify = void (*)(WOLFSSL_CTX*, int, VerifyCallback);
using FnSslNew = WOLFSSL* (*)(WOLFSSL_CTX*);
using FnSslFree = void (*)(WOLFSSL*);
using FnSetFd = int (*)(WOLFSSL*, int);
using FnUseSni = int (*)(WOLFSSL*, unsigned char, const void*, unsigned short);
using FnCheckDomain = int (*)(WOLFSSL*, const char*);
using FnConnect = int (*)(WOLFSSL*);
using FnWrite = int (*)(WOLFSSL*, const void*, int);
using FnRead = int (*)(WOLFSSL*, void*, int);
using FnShutdown = int (*)(WOLFSSL*);
using FnGetError = int (*)(WOLFSSL*, int);
using FnErrString = char* (*)(unsigned long, char*);

std::once_flag g_netInit;
void netInitOnce() {
#if defined(_WIN32)
    WSADATA data;
    WSAStartup(MAKEWORD(2, 2), &data);
#endif
}

void closeSocket(SocketHandle s) {
    if (s == kInvalidSocket) return;
#if defined(_WIN32)
    closesocket(s);
#else
    close(s);
#endif
}

// Blocking connect with a timeout; returns kInvalidSocket on failure.
SocketHandle connectTcp(const std::string& host, const std::string& port,
                        int timeoutSeconds, std::string& err) {
    std::call_once(g_netInit, netInitOnce);
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* results = nullptr;
    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &results);
    if (rc != 0 || !results) {
        err = "cannot resolve " + host;
        return kInvalidSocket;
    }
    SocketHandle sock = kInvalidSocket;
    for (struct addrinfo* ai = results; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock == kInvalidSocket) continue;
#if defined(_WIN32)
        DWORD tmo = static_cast<DWORD>(timeoutSeconds * 1000);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tmo), sizeof(tmo));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&tmo), sizeof(tmo));
        if (connect(sock, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0)
            break;
#else
        struct timeval tv;
        tv.tv_sec = timeoutSeconds;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        int c = connect(sock, ai->ai_addr, ai->ai_addrlen);
        bool connected = (c == 0);
        if (!connected && errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock, &wfds);
            struct timeval ctv;
            ctv.tv_sec = timeoutSeconds;
            ctv.tv_usec = 0;
            if (select(sock + 1, nullptr, &wfds, nullptr, &ctv) > 0) {
                int soerr = 0;
                socklen_t len = sizeof(soerr);
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &len);
                connected = (soerr == 0);
            }
        }
        fcntl(sock, F_SETFL, flags);
        if (connected) break;
#endif
        closeSocket(sock);
        sock = kInvalidSocket;
    }
    freeaddrinfo(results);
    if (sock == kInvalidSocket) err = "cannot connect to " + host + ":" + port;
    return sock;
}

bool parseUrl(const std::string& url, std::string& host, std::string& port,
              std::string& basePath, std::string& err) {
    const std::string scheme = "https://";
    if (url.compare(0, scheme.size(), scheme) != 0) {
        err = "EMS endpoint must use https://";
        return false;
    }
    std::string rest = url.substr(scheme.size());
    size_t slash = rest.find('/');
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    basePath = slash == std::string::npos ? "" : rest.substr(slash);
    while (!basePath.empty() && basePath.back() == '/') basePath.pop_back();
    size_t colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(']') == std::string::npos) {
        host = authority.substr(0, colon);
        port = authority.substr(colon + 1);
    } else {
        host = authority;
        port = "443";
    }
    if (host.empty()) {
        err = "EMS endpoint has no host";
        return false;
    }
    return true;
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    return out;
}

std::string toLower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Remove whitespace outside JSON strings.
std::string compactJson(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    bool inString = false;
    bool escaped = false;
    for (char c : text) {
        if (inString) {
            out += c;
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') inString = false;
            continue;
        }
        if (c == '"') { inString = true; out += c; continue; }
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        out += c;
    }
    return out;
}

// Decode the JSON string literal `lit` (with quotes) into `out`.
bool jsonUnescape(const std::string& lit, std::string& out) {
    if (lit.size() < 2 || lit.front() != '"' || lit.back() != '"') return false;
    out.clear();
    for (size_t i = 1; i + 1 < lit.size(); i++) {
        char c = lit[i];
        if (c != '\\') { out += c; continue; }
        if (++i + 1 >= lit.size()) return false;
        switch (lit[i]) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
            if (i + 4 >= lit.size()) return false;
            unsigned code = static_cast<unsigned>(
                std::strtoul(lit.substr(i + 1, 4).c_str(), nullptr, 16));
            i += 4;
            if (code < 0x80) out += static_cast<char>(code);
            else if (code < 0x800) {
                out += static_cast<char>(0xC0 | (code >> 6));
                out += static_cast<char>(0x80 | (code & 0x3F));
            } else {
                out += static_cast<char>(0xE0 | (code >> 12));
                out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
                out += static_cast<char>(0x80 | (code & 0x3F));
            }
            break;
        }
        default: return false;
        }
    }
    return true;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
    return s.substr(a, b - a);
}

} // namespace

struct EmsClient::Impl {
    FipsCore& fips;
    std::string endpoint, host, port, basePath;
    WOLFSSL_CTX* ctx = nullptr;
    FnCtxFree ctxFree = nullptr;
    FnSslNew sslNew = nullptr;
    FnSslFree sslFree = nullptr;
    FnSetFd setFd = nullptr;
    FnUseSni useSni = nullptr;
    FnCheckDomain checkDomain = nullptr;
    FnConnect sslConnect = nullptr;
    FnWrite sslWrite = nullptr;
    FnRead sslRead = nullptr;
    FnShutdown sslShutdown = nullptr;
    FnGetError getError = nullptr;
    FnErrString errString = nullptr;
    std::mutex m;

    explicit Impl(FipsCore& f) : fips(f) {}
    ~Impl() { if (ctx && ctxFree) ctxFree(ctx); }

    std::string tlsError(WOLFSSL* ssl, int rc) {
        if (!getError) return "TLS error";
        int e = getError(ssl, rc);
        char buf[WOLFSSL_MAX_ERROR_SZ];
        std::memset(buf, 0, sizeof(buf));
        if (errString) errString(static_cast<unsigned long>(e), buf);
        return std::string("TLS error ") + std::to_string(e) + " (" + buf + ")";
    }
};

EmsClient::EmsClient(FipsCore& fips) : impl_(new Impl(fips)) {}
EmsClient::~EmsClient() { delete impl_; }

const std::string& EmsClient::host() const { return impl_->host; }

bool EmsClient::configure(const std::string& endpoint, const std::string& caFile,
                          std::string& err) {
    std::lock_guard<std::mutex> lk(impl_->m);
    if (!parseUrl(endpoint, impl_->host, impl_->port, impl_->basePath, err))
        return false;
    impl_->endpoint = endpoint;
    auto sym = [&](const char* name) { return impl_->fips.symbol(name); };
    auto init = reinterpret_cast<FnInit>(sym("wolfSSL_Init"));
    auto method = reinterpret_cast<FnMethod>(sym("wolfSSLv23_client_method"));
    auto ctxNew = reinterpret_cast<FnCtxNew>(sym("wolfSSL_CTX_new"));
    impl_->ctxFree = reinterpret_cast<FnCtxFree>(sym("wolfSSL_CTX_free"));
    auto loadLocations =
        reinterpret_cast<FnCtxLoadLocations>(sym("wolfSSL_CTX_load_verify_locations"));
    auto loadBuffer =
        reinterpret_cast<FnCtxLoadBuffer>(sym("wolfSSL_CTX_load_verify_buffer"));
    auto setVerify = reinterpret_cast<FnCtxSetVerify>(sym("wolfSSL_CTX_set_verify"));
    impl_->sslNew = reinterpret_cast<FnSslNew>(sym("wolfSSL_new"));
    impl_->sslFree = reinterpret_cast<FnSslFree>(sym("wolfSSL_free"));
    impl_->setFd = reinterpret_cast<FnSetFd>(sym("wolfSSL_set_fd"));
    impl_->useSni = reinterpret_cast<FnUseSni>(sym("wolfSSL_UseSNI"));
    impl_->checkDomain = reinterpret_cast<FnCheckDomain>(sym("wolfSSL_check_domain_name"));
    impl_->sslConnect = reinterpret_cast<FnConnect>(sym("wolfSSL_connect"));
    impl_->sslWrite = reinterpret_cast<FnWrite>(sym("wolfSSL_write"));
    impl_->sslRead = reinterpret_cast<FnRead>(sym("wolfSSL_read"));
    impl_->sslShutdown = reinterpret_cast<FnShutdown>(sym("wolfSSL_shutdown"));
    impl_->getError = reinterpret_cast<FnGetError>(sym("wolfSSL_get_error"));
    impl_->errString = reinterpret_cast<FnErrString>(sym("wolfSSL_ERR_error_string"));
    if (!init || !method || !ctxNew || !impl_->ctxFree || !loadLocations ||
        !loadBuffer || !setVerify || !impl_->sslNew || !impl_->sslFree ||
        !impl_->setFd || !impl_->useSni || !impl_->checkDomain ||
        !impl_->sslConnect || !impl_->sslWrite || !impl_->sslRead ||
        !impl_->sslShutdown || !impl_->getError) {
        err = "FIPS module does not export the TLS client functions";
        return false;
    }
    if (init() != WOLFSSL_SUCCESS) {
        err = "wolfSSL_Init failed";
        return false;
    }
    if (impl_->ctx) impl_->ctxFree(impl_->ctx);
    impl_->ctx = ctxNew(method());
    if (!impl_->ctx) {
        err = "cannot create TLS context";
        return false;
    }
    int rc;
    if (!caFile.empty()) {
        rc = loadLocations(impl_->ctx, caFile.c_str(), nullptr);
        if (rc != WOLFSSL_SUCCESS) {
            err = "cannot load EMS CA file " + caFile;
            return false;
        }
    } else {
        rc = loadBuffer(impl_->ctx,
                        reinterpret_cast<const unsigned char*>(kIsrgRootX1),
                        static_cast<long>(sizeof(kIsrgRootX1) - 1),
                        WOLFSSL_FILETYPE_PEM);
        if (rc != WOLFSSL_SUCCESS) {
            err = "cannot load the embedded ISRG Root X1 trust anchor";
            return false;
        }
    }
    setVerify(impl_->ctx, WOLFSSL_VERIFY_PEER, nullptr);
    return true;
}

bool EmsClient::hexDecode(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

bool EmsClient::splitObjectMembers(
    const std::string& objectText,
    std::vector<std::pair<std::string, std::string>>& members,
    std::string& err) {
    members.clear();
    std::string object = trim(objectText);
    if (object.size() < 2 || object.front() != '{' || object.back() != '}') {
        err = "not a JSON object";
        return false;
    }
    size_t i = 1;
    const size_t end = object.size() - 1;
    auto skipWs = [&]() {
        while (i < end && std::isspace(static_cast<unsigned char>(object[i]))) i++;
    };
    skipWs();
    if (i >= end) return true;  // empty object
    while (i < end) {
        skipWs();
        if (object[i] != '"') { err = "expected member key"; return false; }
        size_t keyStart = i++;
        while (i < end && object[i] != '"') {
            if (object[i] == '\\') i++;
            i++;
        }
        if (i >= end) { err = "unterminated key"; return false; }
        std::string keyLit = object.substr(keyStart, i - keyStart + 1);
        i++;
        skipWs();
        if (i >= end || object[i] != ':') { err = "expected ':'"; return false; }
        i++;
        skipWs();
        size_t valueStart = i;
        int depth = 0;
        bool inString = false;
        bool escaped = false;
        for (; i < end; i++) {
            char c = object[i];
            if (inString) {
                if (escaped) escaped = false;
                else if (c == '\\') escaped = true;
                else if (c == '"') inString = false;
                continue;
            }
            if (c == '"') inString = true;
            else if (c == '{' || c == '[') depth++;
            else if (c == '}' || c == ']') depth--;
            else if (c == ',' && depth == 0) break;
        }
        if (depth != 0 || inString) { err = "malformed member value"; return false; }
        std::string key;
        if (!jsonUnescape(keyLit, key)) { err = "malformed member key"; return false; }
        members.emplace_back(key, trim(object.substr(valueStart, i - valueStart)));
        if (i < end && object[i] == ',') i++;
        skipWs();
    }
    return true;
}

bool EmsClient::canonicalizeReceipt(const std::string& rawReceiptObject,
                                    std::string& canonical, std::string& err) {
    std::vector<std::pair<std::string, std::string>> members;
    if (!splitObjectMembers(rawReceiptObject, members, err)) return false;
    members.erase(std::remove_if(members.begin(), members.end(),
                                 [](const std::pair<std::string, std::string>& m) {
                                     return m.first == "signature";
                                 }),
                  members.end());
    std::sort(members.begin(), members.end(),
              [](const std::pair<std::string, std::string>& a,
                 const std::pair<std::string, std::string>& b) {
                  return a.first < b.first;
              });
    canonical = "{";
    for (size_t k = 0; k < members.size(); k++) {
        if (k) canonical += ",";
        canonical += "\"" + jsonEscape(members[k].first) + "\":" +
                     compactJson(members[k].second);
    }
    canonical += "}";
    return true;
}

EmsFetch EmsClient::requestEntropy(uint32_t bytes, const std::string& policy,
                                   const std::string& apiKey,
                                   const std::string& applicationId,
                                   const std::string& clientNonce,
                                   int timeoutSeconds) {
    EmsFetch out;
    std::lock_guard<std::mutex> lk(impl_->m);
    if (!impl_->ctx) {
        out.error = "EMS client not configured";
        return out;
    }
    if (bytes == 0 || bytes > 4096) {
        out.error = "bytes must be 1..4096";
        return out;
    }
    std::string body = "{\"bytes\":" + std::to_string(bytes) +
                       ",\"policy\":\"" + jsonEscape(policy) + "\"" +
                       ",\"application_id\":\"" + jsonEscape(applicationId) + "\"" +
                       ",\"client_nonce\":\"" + jsonEscape(clientNonce) + "\"}";
    std::string request = "POST " + impl_->basePath + "/v1/entropy/request HTTP/1.1\r\n"
                          "Host: " + impl_->host + "\r\n"
                          "User-Agent: veloce-agent\r\n"
                          "Accept: application/json\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: " + std::to_string(body.size()) + "\r\n"
                          "Connection: close\r\n";
    if (!apiKey.empty()) request += "Authorization: Bearer " + apiKey + "\r\n";
    request += "\r\n" + body;

    std::string connErr;
    SocketHandle sock = connectTcp(impl_->host, impl_->port, timeoutSeconds, connErr);
    if (sock == kInvalidSocket) {
        out.error = connErr;
        return out;
    }
    WOLFSSL* ssl = impl_->sslNew(impl_->ctx);
    if (!ssl) {
        closeSocket(sock);
        out.error = "cannot create TLS session";
        return out;
    }
    std::string response;
    bool okTransport = false;
    do {
        impl_->useSni(ssl, WOLFSSL_SNI_HOST_NAME, impl_->host.c_str(),
                      static_cast<unsigned short>(impl_->host.size()));
        if (impl_->checkDomain(ssl, impl_->host.c_str()) != WOLFSSL_SUCCESS) {
            out.error = "cannot set TLS hostname check";
            break;
        }
        if (impl_->setFd(ssl, static_cast<int>(sock)) != WOLFSSL_SUCCESS) {
            out.error = "cannot attach socket to TLS session";
            break;
        }
        int rc = impl_->sslConnect(ssl);
        if (rc != WOLFSSL_SUCCESS) {
            out.error = "TLS handshake with " + impl_->host + " failed: " +
                        impl_->tlsError(ssl, rc);
            break;
        }
        size_t sent = 0;
        while (sent < request.size()) {
            rc = impl_->sslWrite(ssl, request.data() + sent,
                                 static_cast<int>(request.size() - sent));
            if (rc <= 0) break;
            sent += static_cast<size_t>(rc);
        }
        if (sent < request.size()) {
            out.error = "TLS write failed";
            break;
        }
        char buf[4096];
        for (;;) {
            rc = impl_->sslRead(ssl, buf, sizeof(buf));
            if (rc > 0) {
                response.append(buf, static_cast<size_t>(rc));
                if (response.size() > (1u << 20)) break;
                continue;
            }
            break;
        }
        impl_->sslShutdown(ssl);
        okTransport = !response.empty();
        if (!okTransport) out.error = "empty response from " + impl_->host;
    } while (false);
    impl_->sslFree(ssl);
    closeSocket(sock);
    if (!okTransport) return out;

    // HTTP/1.1 response: status line, headers, body (content-length or chunked).
    size_t headerEnd = response.find("\r\n\r\n");
    if (headerEnd == std::string::npos) {
        out.error = "malformed HTTP response";
        return out;
    }
    std::string head = response.substr(0, headerEnd);
    std::string bodyText = response.substr(headerEnd + 4);
    size_t sp = head.find(' ');
    if (sp == std::string::npos) {
        out.error = "malformed HTTP status line";
        return out;
    }
    out.httpStatus = std::atoi(head.c_str() + sp + 1);
    bool chunked = false;
    {
        std::string lower = toLower(head);
        size_t te = lower.find("transfer-encoding:");
        if (te != std::string::npos) {
            size_t eol = lower.find("\r\n", te);
            chunked = lower.substr(te, eol - te).find("chunked") != std::string::npos;
        }
    }
    if (chunked) {
        std::string decoded;
        size_t pos = 0;
        while (pos < bodyText.size()) {
            size_t eol = bodyText.find("\r\n", pos);
            if (eol == std::string::npos) break;
            unsigned long len = std::strtoul(bodyText.substr(pos, eol - pos).c_str(), nullptr, 16);
            pos = eol + 2;
            if (len == 0) break;
            if (pos + len > bodyText.size()) break;
            decoded.append(bodyText, pos, len);
            pos += len + 2;
        }
        bodyText = decoded;
    }
    if (out.httpStatus != 200) {
        out.error = "EMS returned HTTP " + std::to_string(out.httpStatus) + ": " +
                    trim(bodyText).substr(0, 200);
        return out;
    }

    std::vector<std::pair<std::string, std::string>> members;
    std::string err;
    if (!splitObjectMembers(bodyText, members, err)) {
        out.error = "malformed EMS response: " + err;
        return out;
    }
    std::string bytesHexLit, receiptRaw;
    for (const auto& m : members) {
        if (m.first == "bytes_hex") bytesHexLit = m.second;
        else if (m.first == "receipt") receiptRaw = m.second;
    }
    std::string bytesHex;
    if (!jsonUnescape(bytesHexLit, bytesHex) || !hexDecode(bytesHex, out.bytes)) {
        out.error = "EMS response has no valid bytes_hex";
        return out;
    }
    if (receiptRaw.empty()) {
        out.error = "EMS response has no receipt";
        return out;
    }
    if (!canonicalizeReceipt(receiptRaw, out.receipt.canonical, err)) {
        out.error = "cannot canonicalize receipt: " + err;
        return out;
    }
    std::vector<std::pair<std::string, std::string>> fields;
    if (!splitObjectMembers(receiptRaw, fields, err)) {
        out.error = "malformed receipt: " + err;
        return out;
    }
    auto str = [&](const std::string& lit, std::string& dst) {
        return jsonUnescape(lit, dst);
    };
    for (const auto& f : fields) {
        const std::string& k = f.first;
        const std::string& v = f.second;
        if (k == "request_id") str(v, out.receipt.requestId);
        else if (k == "application_id") str(v, out.receipt.applicationId);
        else if (k == "policy") str(v, out.receipt.policy);
        else if (k == "pool_id") str(v, out.receipt.poolId);
        else if (k == "signature_alg") str(v, out.receipt.signatureAlg);
        else if (k == "drbg_alg") str(v, out.receipt.drbgAlg);
        else if (k == "audit_event_id") str(v, out.receipt.auditEventId);
        else if (k == "timestamp_unix_ns") out.receipt.timestampNs = std::strtoull(v.c_str(), nullptr, 10);
        else if (k == "quality_score") out.receipt.qualityScore = std::atoi(v.c_str());
        else if (k == "output_bytes") out.receipt.outputBytes = static_cast<uint32_t>(std::strtoul(v.c_str(), nullptr, 10));
        else if (k == "rct_pass") out.receipt.rctPass = (v == "true");
        else if (k == "apt_pass") out.receipt.aptPass = (v == "true");
        else if (k == "raw_entropy_stored") out.receipt.rawEntropyStored = (v != "false");
        else if (k == "signature") {
            std::string sigHex;
            if (!str(v, sigHex) || !hexDecode(sigHex, out.receipt.signature)) {
                out.error = "receipt signature is not valid hex";
                return out;
            }
        }
    }
    out.ok = true;
    return out;
}

} // namespace veloce
