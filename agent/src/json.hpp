// Minimal JSON value, parser, serializer and base64 codec for the Veloce
// agent IPC channel (ipc/protocol.md). No external dependencies.
#pragma once

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace vjson {

class Value;
using Member = std::pair<std::string, Value>;

class Value {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Value() : type_(Type::Null) {}
    Value(bool b) : type_(Type::Bool), bool_(b) {}
    Value(double n) : type_(Type::Number), num_(n) {}
    Value(int n) : type_(Type::Number), num_(n) {}
    Value(int64_t n) : type_(Type::Number), num_(static_cast<double>(n)) {}
    Value(uint64_t n) : type_(Type::Number), num_(static_cast<double>(n)) {}
    Value(const char* s) : type_(Type::String), str_(s) {}
    Value(std::string s) : type_(Type::String), str_(std::move(s)) {}

    static Value array() { Value v; v.type_ = Type::Array; return v; }
    static Value object() { Value v; v.type_ = Type::Object; return v; }

    Type type() const { return type_; }
    bool isNull() const { return type_ == Type::Null; }
    bool isBool() const { return type_ == Type::Bool; }
    bool isNumber() const { return type_ == Type::Number; }
    bool isString() const { return type_ == Type::String; }
    bool isArray() const { return type_ == Type::Array; }
    bool isObject() const { return type_ == Type::Object; }

    bool asBool(bool dflt = false) const { return isBool() ? bool_ : dflt; }
    double asNumber(double dflt = 0) const { return isNumber() ? num_ : dflt; }
    int64_t asInt(int64_t dflt = 0) const {
        return isNumber() ? static_cast<int64_t>(num_) : dflt;
    }
    const std::string& asString() const {
        static const std::string empty;
        return isString() ? str_ : empty;
    }

    std::vector<Value>& items() { return arr_; }
    const std::vector<Value>& items() const { return arr_; }
    std::vector<Member>& members() { return obj_; }
    const std::vector<Member>& members() const { return obj_; }

    void push(Value v) { arr_.push_back(std::move(v)); }
    Value& set(const std::string& key, Value v) {
        for (auto& m : obj_) {
            if (m.first == key) { m.second = std::move(v); return m.second; }
        }
        obj_.emplace_back(key, std::move(v));
        return obj_.back().second;
    }
    const Value* find(const std::string& key) const {
        for (const auto& m : obj_)
            if (m.first == key) return &m.second;
        return nullptr;
    }
    std::string getString(const std::string& key,
                          const std::string& dflt = "") const {
        const Value* v = find(key);
        return (v && v->isString()) ? v->asString() : dflt;
    }
    int64_t getInt(const std::string& key, int64_t dflt = 0) const {
        const Value* v = find(key);
        return (v && v->isNumber()) ? v->asInt() : dflt;
    }
    bool getBool(const std::string& key, bool dflt = false) const {
        const Value* v = find(key);
        return (v && v->isBool()) ? v->asBool() : dflt;
    }

    std::string dump() const {
        std::string out;
        write(out);
        return out;
    }

private:
    void write(std::string& out) const {
        char buf[64];
        switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += bool_ ? "true" : "false"; break;
        case Type::Number:
            if (num_ == static_cast<int64_t>(num_)) {
                snprintf(buf, sizeof(buf), "%lld",
                         static_cast<long long>(num_));
            } else {
                snprintf(buf, sizeof(buf), "%.17g", num_);
            }
            out += buf;
            break;
        case Type::String: writeString(out, str_); break;
        case Type::Array:
            out += '[';
            for (size_t i = 0; i < arr_.size(); i++) {
                if (i) out += ',';
                arr_[i].write(out);
            }
            out += ']';
            break;
        case Type::Object:
            out += '{';
            for (size_t i = 0; i < obj_.size(); i++) {
                if (i) out += ',';
                writeString(out, obj_[i].first);
                out += ':';
                obj_[i].second.write(out);
            }
            out += '}';
            break;
        }
    }
    static void writeString(std::string& out, const std::string& s) {
        out += '"';
        for (unsigned char c : s) {
            switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
            }
        }
        out += '"';
    }

    Type type_;
    bool bool_ = false;
    double num_ = 0;
    std::string str_;
    std::vector<Value> arr_;
    std::vector<Member> obj_;
};

class ParseError : public std::runtime_error {
public:
    explicit ParseError(const std::string& m) : std::runtime_error(m) {}
};

class Parser {
public:
    static Value parse(const std::string& text) {
        Parser p(text);
        Value v = p.value();
        p.skipWs();
        if (p.pos_ != text.size()) throw ParseError("trailing data");
        return v;
    }

private:
    explicit Parser(const std::string& t) : text_(t) {}

    const std::string& text_;
    size_t pos_ = 0;

    [[noreturn]] void fail(const std::string& why) {
        throw ParseError(why + " at offset " + std::to_string(pos_));
    }
    char peek() {
        if (pos_ >= text_.size()) fail("unexpected end");
        return text_[pos_];
    }
    char next() {
        char c = peek();
        pos_++;
        return c;
    }
    void skipWs() {
        while (pos_ < text_.size()) {
            char c = text_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos_++;
            else break;
        }
    }
    void expect(char c) {
        if (next() != c) fail(std::string("expected '") + c + "'");
    }
    bool consume(char c) {
        skipWs();
        if (pos_ < text_.size() && text_[pos_] == c) { pos_++; return true; }
        return false;
    }

    Value value() {
        skipWs();
        char c = peek();
        switch (c) {
        case '{': return object();
        case '[': return array();
        case '"': return Value(string());
        case 't': literal("true"); return Value(true);
        case 'f': literal("false"); return Value(false);
        case 'n': literal("null"); return Value();
        default: return number();
        }
    }
    void literal(const char* lit) {
        for (const char* p = lit; *p; p++)
            if (next() != *p) fail("bad literal");
    }
    Value object() {
        expect('{');
        Value v = Value::object();
        if (consume('}')) return v;
        while (true) {
            skipWs();
            std::string key = string();
            skipWs();
            expect(':');
            v.set(key, value());
            if (consume(',')) continue;
            skipWs();
            expect('}');
            break;
        }
        return v;
    }
    Value array() {
        expect('[');
        Value v = Value::array();
        if (consume(']')) return v;
        while (true) {
            v.push(value());
            if (consume(',')) continue;
            skipWs();
            expect(']');
            break;
        }
        return v;
    }
    std::string string() {
        expect('"');
        std::string out;
        while (true) {
            char c = next();
            if (c == '"') break;
            if (c == '\\') {
                char e = next();
                switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    unsigned cp = 0;
                    for (int i = 0; i < 4; i++) {
                        char h = next();
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= h - '0';
                        else if (h >= 'a' && h <= 'f') cp |= h - 'a' + 10;
                        else if (h >= 'A' && h <= 'F') cp |= h - 'A' + 10;
                        else fail("bad \\u escape");
                    }
                    // BMP only; encode as UTF-8.
                    if (cp < 0x80) {
                        out += static_cast<char>(cp);
                    } else if (cp < 0x800) {
                        out += static_cast<char>(0xC0 | (cp >> 6));
                        out += static_cast<char>(0x80 | (cp & 0x3F));
                    } else {
                        out += static_cast<char>(0xE0 | (cp >> 12));
                        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                        out += static_cast<char>(0x80 | (cp & 0x3F));
                    }
                    break;
                }
                default: fail("bad escape");
                }
            } else if (static_cast<unsigned char>(c) < 0x20) {
                fail("control char in string");
            } else {
                out += c;
            }
        }
        return out;
    }
    Value number() {
        size_t start = pos_;
        if (peek() == '-') pos_++;
        while (pos_ < text_.size() &&
               (isdigit(static_cast<unsigned char>(text_[pos_])) ||
                text_[pos_] == '.' || text_[pos_] == 'e' ||
                text_[pos_] == 'E' || text_[pos_] == '+' ||
                text_[pos_] == '-'))
            pos_++;
        if (pos_ == start) fail("bad number");
        try {
            return Value(std::stod(text_.substr(start, pos_ - start)));
        } catch (...) {
            fail("bad number");
        }
    }
};

inline std::string b64encode(const uint8_t* data, size_t len) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= len; i += 3) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += tbl[(n >> 6) & 63];
        out += tbl[n & 63];
    }
    if (i + 1 == len) {
        uint32_t n = data[i] << 16;
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += "==";
    } else if (i + 2 == len) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
        out += tbl[(n >> 18) & 63];
        out += tbl[(n >> 12) & 63];
        out += tbl[(n >> 6) & 63];
        out += '=';
    }
    return out;
}

inline std::string b64encode(const std::vector<uint8_t>& v) {
    return b64encode(v.data(), v.size());
}

inline bool b64decode(const std::string& in, std::vector<uint8_t>& out) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    out.clear();
    uint32_t buf = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = val(c);
        if (v < 0) return false;
        buf = (buf << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    return true;
}

} // namespace vjson
