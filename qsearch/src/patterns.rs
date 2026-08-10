// qSearch detection targets (spec 4.4): quantum-vulnerable usage flagged
// RSA / DH / ECDH / ECDSA plus small-key symmetric and weak digests;
// ML-KEM / ML-DSA usage recognized and reported as PQC-ready.

pub struct Pattern {
    pub needle: &'static str,
    pub algorithm: &'static str,
    pub service: &'static str, // cryptographic service (spec 4.3)
    pub classification: &'static str, // quantum-vulnerable | pqc-ready | context
    pub risk: &'static str,    // high | medium | info
}

pub const PATTERNS: &[Pattern] = &[
    // RSA
    Pattern { needle: "RSA_generate_key", algorithm: "RSA", service: "key establishment / digital signature", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "rsa.GenerateKey", algorithm: "RSA", service: "key establishment / digital signature", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "generate_private_key", algorithm: "RSA/EC (library keygen)", service: "key establishment / digital signature", classification: "quantum-vulnerable", risk: "medium" },
    Pattern { needle: "BEGIN RSA PRIVATE KEY", algorithm: "RSA", service: "key material at rest", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "rsa_public_encrypt", algorithm: "RSA", service: "encrypted connection", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "RSA_public_encrypt", algorithm: "RSA", service: "encrypted connection", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "RSA-2048", algorithm: "RSA-2048", service: "key establishment", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "RSA-4096", algorithm: "RSA-4096", service: "key establishment", classification: "quantum-vulnerable", risk: "high" },
    // ECDSA / ECDH / EC curves
    Pattern { needle: "ECDSA_sign", algorithm: "ECDSA", service: "digital signature", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "ecdsa.SignASN1", algorithm: "ECDSA", service: "digital signature", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "ECDH_compute_key", algorithm: "ECDH", service: "key establishment", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "secp256r1", algorithm: "ECDSA/ECDH P-256", service: "key establishment / digital signature", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "prime256v1", algorithm: "ECDSA/ECDH P-256", service: "key establishment / digital signature", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "secp384r1", algorithm: "ECDSA/ECDH P-384", service: "key establishment / digital signature", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "SECP256R1", algorithm: "ECDSA/ECDH P-256", service: "key establishment / digital signature", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "curve25519", algorithm: "X25519", service: "key establishment", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "X25519", algorithm: "X25519", service: "key establishment", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "ed25519", algorithm: "Ed25519", service: "digital signature", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "Ed25519", algorithm: "Ed25519", service: "digital signature", classification: "quantum-vulnerable", risk: "high" },
    // Finite-field DH
    Pattern { needle: "DH_generate_key", algorithm: "DH", service: "key establishment", classification: "quantum-vulnerable", risk: "high" },
    Pattern { needle: "DiffieHellman", algorithm: "DH", service: "key establishment", classification: "quantum-vulnerable", risk: "high" },
    // Legacy symmetric / digests (CNSA hygiene)
    Pattern { needle: "DES_ede3", algorithm: "3DES", service: "encrypted connection", classification: "quantum-vulnerable", risk: "medium" },
    Pattern { needle: "EVP_des_ede3", algorithm: "3DES", service: "encrypted connection", classification: "quantum-vulnerable", risk: "medium" },
    Pattern { needle: "RC4", algorithm: "RC4", service: "encrypted connection", classification: "quantum-vulnerable", risk: "medium" },
    Pattern { needle: "MD5", algorithm: "MD5", service: "digest", classification: "quantum-vulnerable", risk: "medium" },
    // PQC-ready
    Pattern { needle: "ML-KEM", algorithm: "ML-KEM", service: "key establishment", classification: "pqc-ready", risk: "info" },
    Pattern { needle: "MlKem", algorithm: "ML-KEM", service: "key establishment", classification: "pqc-ready", risk: "info" },
    Pattern { needle: "mlkem", algorithm: "ML-KEM", service: "key establishment", classification: "pqc-ready", risk: "info" },
    Pattern { needle: "Kyber", algorithm: "ML-KEM (Kyber)", service: "key establishment", classification: "pqc-ready", risk: "info" },
    Pattern { needle: "ML-DSA", algorithm: "ML-DSA", service: "digital signature", classification: "pqc-ready", risk: "info" },
    Pattern { needle: "MlDsa", algorithm: "ML-DSA", service: "digital signature", classification: "pqc-ready", risk: "info" },
    Pattern { needle: "Dilithium", algorithm: "ML-DSA (Dilithium)", service: "digital signature", classification: "pqc-ready", risk: "info" },
    Pattern { needle: "X25519MLKEM768", algorithm: "X25519MLKEM768 hybrid", service: "key establishment (TLS 1.3 hybrid)", classification: "pqc-ready", risk: "info" },
    // Library context
    Pattern { needle: "openssl/ssl.h", algorithm: "TLS (OpenSSL)", service: "encrypted connection", classification: "context", risk: "medium" },
    Pattern { needle: "import ssl", algorithm: "TLS (Python ssl)", service: "encrypted connection", classification: "context", risk: "medium" },
    Pattern { needle: "from cryptography", algorithm: "pyca/cryptography", service: "library usage", classification: "context", risk: "medium" },
    Pattern { needle: "wolfssl", algorithm: "wolfSSL", service: "library usage", classification: "context", risk: "medium" },
    Pattern { needle: "mbedtls", algorithm: "Mbed TLS", service: "library usage", classification: "context", risk: "medium" },
];

// File extensions scanned as source (spec 4.1 source-code collector).
pub const SOURCE_EXTS: &[&str] = &[
    "c", "h", "cpp", "hpp", "cc", "hh", "rs", "go", "py", "js", "ts", "java",
    "cs", "rb", "php", "swift", "kt", "scala", "m", "mm", "sh", "yaml", "yml",
    "toml", "json", "cfg", "conf", "ini", "tf", "gradle", "cmake", "txt",
    "md", "xml", "properties", "env",
];
