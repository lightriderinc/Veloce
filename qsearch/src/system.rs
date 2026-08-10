// Host collector (spec 4.1: certificate discovery in OS stores, endpoint /
// config review): inventories the crypto modules present on this machine.
//
// Sources, all local and offline:
//   - shared crypto libraries from the dynamic-linker cache (ldconfig -p)
//     and the standard library directories, fingerprinted with SHA-256
//   - kernel crypto algorithms (/proc/crypto) and FIPS mode
//     (/proc/sys/crypto/fips_enabled)
//   - SSH host keys and sshd configuration (/etc/ssh)
//   - the system certificate store (/etc/ssl/certs, /etc/pki)
//   - TLS/crypto policy files (/etc/ssl/openssl.cnf, /etc/crypto-policies)
//   - running processes with crypto libraries mapped (/proc/*/maps)
//
// Full process and config coverage requires root; unreadable entries are
// skipped and counted, never guessed.
use crate::sha256;
use crate::Finding;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// (needle in file name, product, classification, risk)
const LIB_PATTERNS: &[(&str, &str)] = &[
    ("libcrypto", "OpenSSL libcrypto"),
    ("libssl", "OpenSSL libssl"),
    ("libgnutls", "GnuTLS"),
    ("libgcrypt", "libgcrypt"),
    ("libnss3", "Mozilla NSS"),
    ("libnettle", "Nettle"),
    ("libhogweed", "Nettle (public key)"),
    ("libsodium", "libsodium"),
    ("libmbedtls", "Mbed TLS"),
    ("libmbedcrypto", "Mbed TLS (crypto)"),
    ("libwolfssl", "wolfSSL"),
    ("libkrb5", "MIT Kerberos"),
    ("libssh", "libssh"),
    ("libcryptsetup", "cryptsetup (LUKS)"),
    ("libargon2", "Argon2"),
];

fn lib_product(file_name: &str) -> Option<&'static str> {
    LIB_PATTERNS
        .iter()
        .find(|(needle, _)| {
            file_name.starts_with(needle)
                && file_name[needle.len()..].starts_with(['.', '-'])
        })
        .map(|(_, product)| *product)
}

fn file_sha256(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    let mut h = sha256::Sha256::new();
    h.update(&data);
    Some(sha256::hex(&h.finalize()))
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn push(findings: &mut Vec<Finding>, asset: String, algorithm: String,
        service: &str, classification: &str, risk: &str, evidence: String,
        detail: String) {
    findings.push(Finding {
        asset,
        algorithm,
        service: service.to_string(),
        classification: classification.to_string(),
        risk: risk.to_string(),
        evidence,
        detail,
        provenance: "directly observed".to_string(),
        confidence: "high".to_string(),
        last_observed: now(),
    });
}

// --------------------------------------------------------------- libraries

fn collect_libraries(findings: &mut Vec<Finding>) {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    // Dynamic-linker cache first: authoritative list of resolvable libs.
    if let Ok(out) = Command::new("ldconfig").arg("-p").output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(path) = line.rsplit(" => ").next() {
                let path = PathBuf::from(path.trim());
                if let Some(name) =
                    path.file_name().and_then(|n| n.to_str())
                {
                    if lib_product(name).is_some() {
                        if let Ok(real) = fs::canonicalize(&path) {
                            seen.insert(real);
                        } else {
                            seen.insert(path);
                        }
                    }
                }
            }
        }
    }
    // Standard directories as a fallback sweep.
    for dir in ["/lib", "/lib64", "/usr/lib", "/usr/lib64",
                "/usr/local/lib", "/opt/veloce/lib"] {
        collect_lib_dir(Path::new(dir), 0, &mut seen);
    }

    for path in seen {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let product = lib_product(&name).unwrap_or("crypto library");
        let fp = file_sha256(&path).unwrap_or_default();
        push(
            findings,
            path.display().to_string(),
            format!("library: {} ({})", product, name),
            "crypto library provider",
            "context",
            "medium",
            if fp.is_empty() { "unreadable".to_string() }
            else { format!("sha256:{}", fp) },
            format!("shared crypto library installed at {}", path.display()),
        );
    }
}

fn collect_lib_dir(dir: &Path, depth: u32, seen: &mut BTreeSet<PathBuf>) {
    if depth > 3 {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_lib_dir(&path, depth + 1, seen);
        } else if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if lib_product(name).is_some() && name.contains(".so") {
                if let Ok(real) = fs::canonicalize(&path) {
                    seen.insert(real);
                }
            }
        }
    }
}

// ------------------------------------------------------------------ kernel

fn classify_kernel_alg(name: &str) -> Option<(&'static str, &'static str)> {
    // (classification, risk)
    let n = name.to_lowercase();
    if n == "rsa" || n.starts_with("pkcs1") || n.starts_with("ecdsa")
        || n.starts_with("ecdh") || n.starts_with("dh")
        || n.starts_with("curve25519") || n.starts_with("ed25519") {
        Some(("quantum-vulnerable", "high"))
    } else if n.starts_with("des") || n == "arc4" || n.starts_with("md5")
        || n.starts_with("md4") {
        Some(("quantum-vulnerable", "medium"))
    } else {
        None // symmetric/hash primitives: inventoried in detail only
    }
}

fn collect_kernel(findings: &mut Vec<Finding>) {
    if let Ok(fips) = fs::read_to_string("/proc/sys/crypto/fips_enabled") {
        let on = fips.trim() == "1";
        push(
            findings,
            "/proc/sys/crypto/fips_enabled".to_string(),
            format!("kernel FIPS mode: {}", if on { "enabled" }
                    else { "disabled" }),
            "operating environment",
            "context",
            "info",
            format!("value={}", fips.trim()),
            "Linux kernel FIPS mode flag".to_string(),
        );
    }
    let text = match fs::read_to_string("/proc/crypto") {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut count = 0u32;
    for line in text.lines() {
        if let Some(name) = line.strip_prefix("name") {
            let name = name.trim_start_matches([' ', ':']).trim();
            count += 1;
            names.insert(name.to_string());
        }
    }
    for name in &names {
        if let Some((class, risk)) = classify_kernel_alg(name) {
            push(
                findings,
                "/proc/crypto".to_string(),
                format!("kernel algorithm: {}", name),
                "kernel crypto API",
                class,
                risk,
                format!("/proc/crypto name={}", name),
                "algorithm registered with the Linux kernel crypto API"
                    .to_string(),
            );
        }
    }
    push(
        findings,
        "/proc/crypto".to_string(),
        format!("kernel crypto API: {} registered algorithm entries \
                 ({} unique names)", count, names.len()),
        "kernel crypto API",
        "context",
        "info",
        "/proc/crypto".to_string(),
        "full list retained in the kernel; quantum-vulnerable entries \
         reported individually".to_string(),
    );
}

// --------------------------------------------------------------------- ssh

fn collect_ssh(findings: &mut Vec<Finding>) {
    let dir = Path::new("/etc/ssh");
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy()
            .to_string();
        if name.ends_with(".pub") {
            if let Ok(text) = fs::read_to_string(&path) {
                let keytype = text.split_whitespace().next().unwrap_or("");
                let (alg, class, risk) = match keytype {
                    "ssh-rsa" => ("SSH host key: RSA",
                                  "quantum-vulnerable", "high"),
                    t if t.starts_with("ecdsa-sha2") =>
                        ("SSH host key: ECDSA", "quantum-vulnerable", "high"),
                    "ssh-ed25519" => ("SSH host key: Ed25519",
                                      "quantum-vulnerable", "high"),
                    "ssh-dss" => ("SSH host key: DSA",
                                  "quantum-vulnerable", "high"),
                    _ => ("SSH host key: unrecognized type", "context",
                          "medium"),
                };
                push(
                    findings,
                    path.display().to_string(),
                    alg.to_string(),
                    "authentication (SSH host identity)",
                    class,
                    risk,
                    format!("{} ({})", path.display(), keytype),
                    "SSH daemon host key".to_string(),
                );
            }
        }
    }
    // sshd_config algorithm lines, when readable.
    if let Ok(text) = fs::read_to_string("/etc/ssh/sshd_config") {
        for (i, line) in text.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("KexAlgorithms") || t.starts_with("Ciphers")
                || t.starts_with("HostKeyAlgorithms")
                || t.starts_with("MACs") {
                push(
                    findings,
                    "/etc/ssh/sshd_config".to_string(),
                    format!("sshd policy: {}",
                            t.chars().take(120).collect::<String>()),
                    "encrypted connection (SSH)",
                    "context",
                    "medium",
                    format!("/etc/ssh/sshd_config:{}", i + 1),
                    "explicit SSH algorithm policy".to_string(),
                );
            }
        }
    }
}

// ------------------------------------------------------------ cert stores

fn collect_cert_stores(findings: &mut Vec<Finding>) {
    for store in ["/etc/ssl/certs", "/etc/pki/tls/certs"] {
        let dir = Path::new(store);
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut count = 0u32;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                || fs::metadata(&path).map(|m| m.is_file()).unwrap_or(false)
            {
                if let Ok(text) = fs::read_to_string(&path) {
                    if text.contains("-----BEGIN CERTIFICATE-----") {
                        count += 1;
                    }
                }
            }
        }
        if count > 0 {
            push(
                findings,
                store.to_string(),
                format!("OS certificate store: {} certificates", count),
                "authentication (trust anchors)",
                "context",
                "info",
                store.to_string(),
                "system trust store; individual certificates are \
                 predominantly RSA/ECDSA (quantum-vulnerable signatures); \
                 scan with `qsearch scan` for per-certificate fingerprints"
                    .to_string(),
            );
        }
    }
}

// ---------------------------------------------------------------- configs

fn collect_configs(findings: &mut Vec<Finding>) {
    for cfg in ["/etc/ssl/openssl.cnf",
                "/etc/crypto-policies/config",
                "/etc/crypto-policies/state/current"] {
        if let Ok(text) = fs::read_to_string(cfg) {
            let first = text.lines().find(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            }).unwrap_or("").trim();
            push(
                findings,
                cfg.to_string(),
                format!("crypto policy file ({})",
                        if first.is_empty() { "present" } else { first }),
                "endpoint configuration",
                "context",
                "info",
                cfg.to_string(),
                "system-wide TLS/crypto configuration".to_string(),
            );
        }
    }
    if let Ok(out) = Command::new("openssl").arg("version").output() {
        let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !v.is_empty() {
            push(
                findings,
                "openssl (PATH)".to_string(),
                format!("tool: {}", v),
                "crypto library provider",
                "context",
                "info",
                "openssl version".to_string(),
                "OpenSSL command-line tool present".to_string(),
            );
        }
    }
}

// -------------------------------------------------------------- processes

fn collect_processes(findings: &mut Vec<Finding>) {
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };
    let mut denied = 0u32;
    for entry in proc_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let maps = match fs::read_to_string(format!("/proc/{}/maps", name)) {
            Ok(m) => m,
            Err(_) => {
                denied += 1;
                continue;
            }
        };
        let comm = fs::read_to_string(format!("/proc/{}/comm", name))
            .unwrap_or_default().trim().to_string();
        let mut libs: BTreeSet<&'static str> = BTreeSet::new();
        for line in maps.lines() {
            if let Some(pos) = line.find('/') {
                let path = &line[pos..];
                if let Some(fname) = Path::new(path).file_name()
                    .and_then(|n| n.to_str())
                {
                    if let Some(product) = lib_product(fname) {
                        libs.insert(product);
                    }
                }
            }
        }
        if !libs.is_empty() {
            let products: Vec<&str> = libs.into_iter().collect();
            push(
                findings,
                format!("process {} (pid {})", comm, name),
                format!("process crypto usage: {}", products.join(", ")),
                "active cryptography (loaded library)",
                "context",
                "medium",
                format!("/proc/{}/maps", name),
                "crypto libraries mapped into a running process"
                    .to_string(),
            );
        }
    }
    if denied > 0 {
        push(
            findings,
            "/proc".to_string(),
            format!("process scan: {} processes unreadable \
                     (run as root for full coverage)", denied),
            "coverage limitation",
            "context",
            "info",
            "/proc/*/maps".to_string(),
            "blind spot reported explicitly (spec 4.5)".to_string(),
        );
    }
}

pub fn collect(findings: &mut Vec<Finding>) {
    collect_libraries(findings);
    collect_kernel(findings);
    collect_ssh(findings);
    collect_cert_stores(findings);
    collect_configs(findings);
    collect_processes(findings);
}
