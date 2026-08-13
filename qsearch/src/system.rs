// Native host collectors (spec 4.1: certificate discovery in OS stores,
// endpoint/config review): inventory crypto modules present on this machine.
//
// Linux sources, all local and offline:
//   - shared crypto libraries from the dynamic-linker cache (ldconfig -p)
//     and the standard library directories, fingerprinted with SHA-256
//   - kernel crypto algorithms (/proc/crypto) and FIPS mode
//     (/proc/sys/crypto/fips_enabled)
//   - SSH host keys and sshd configuration (/etc/ssh)
//   - the system certificate store (/etc/ssl/certs, /etc/pki)
//   - TLS/crypto policy files (/etc/ssl/openssl.cnf, /etc/crypto-policies)
//   - running processes with crypto libraries mapped (/proc/*/maps)
//
// Windows additionally observes CNG/CryptoAPI libraries, system FIPS policy,
// and the LocalMachine root store. macOS observes Security.framework,
// available dylibs, and the SystemRoot Keychain. Platform blind spots are
// emitted as findings instead of being silently hidden.
use crate::sha256;
use crate::Finding;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::path::PathBuf;
use std::process::Command;

// (needle in file name, product, classification, risk)
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn lib_product(file_name: &str) -> Option<&'static str> {
    LIB_PATTERNS
        .iter()
        .find(|(needle, _)| {
            file_name.starts_with(needle) && file_name[needle.len()..].starts_with(['.', '-'])
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

fn push(
    findings: &mut Vec<Finding>,
    asset: String,
    algorithm: String,
    service: &str,
    classification: &str,
    risk: &str,
    evidence: String,
    detail: String,
) {
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

#[cfg(target_os = "linux")]
fn collect_libraries(findings: &mut Vec<Finding>) {
    let mut seen: BTreeSet<PathBuf> = BTreeSet::new();

    // Dynamic-linker cache first: authoritative list of resolvable libs.
    if let Ok(out) = Command::new("ldconfig").arg("-p").output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(path) = line.rsplit(" => ").next() {
                let path = PathBuf::from(path.trim());
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
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
    for dir in [
        "/lib",
        "/lib64",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/opt/veloce/lib",
    ] {
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
            if fp.is_empty() {
                "unreadable".to_string()
            } else {
                format!("sha256:{}", fp)
            },
            format!("shared crypto library installed at {}", path.display()),
        );
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn classify_kernel_alg(name: &str) -> Option<(&'static str, &'static str)> {
    // (classification, risk)
    let n = name.to_lowercase();
    if n == "rsa"
        || n.starts_with("pkcs1")
        || n.starts_with("ecdsa")
        || n.starts_with("ecdh")
        || n.starts_with("dh")
        || n.starts_with("curve25519")
        || n.starts_with("ed25519")
    {
        Some(("quantum-vulnerable", "high"))
    } else if n.starts_with("des") || n == "arc4" || n.starts_with("md5") || n.starts_with("md4") {
        Some(("quantum-vulnerable", "medium"))
    } else {
        None // symmetric/hash primitives: inventoried in detail only
    }
}

#[cfg(target_os = "linux")]
fn collect_kernel(findings: &mut Vec<Finding>) {
    if let Ok(fips) = fs::read_to_string("/proc/sys/crypto/fips_enabled") {
        let on = fips.trim() == "1";
        push(
            findings,
            "/proc/sys/crypto/fips_enabled".to_string(),
            format!(
                "kernel FIPS mode: {}",
                if on { "enabled" } else { "disabled" }
            ),
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
                "algorithm registered with the Linux kernel crypto API".to_string(),
            );
        }
    }
    push(
        findings,
        "/proc/crypto".to_string(),
        format!(
            "kernel crypto API: {} registered algorithm entries \
                 ({} unique names)",
            count,
            names.len()
        ),
        "kernel crypto API",
        "context",
        "info",
        "/proc/crypto".to_string(),
        "full list retained in the kernel; quantum-vulnerable entries \
         reported individually"
            .to_string(),
    );
}

// --------------------------------------------------------------------- ssh

#[cfg(target_os = "linux")]
fn collect_ssh(findings: &mut Vec<Finding>) {
    let dir = Path::new("/etc/ssh");
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if name.ends_with(".pub") {
            if let Ok(text) = fs::read_to_string(&path) {
                let keytype = text.split_whitespace().next().unwrap_or("");
                let (alg, class, risk) = match keytype {
                    "ssh-rsa" => ("SSH host key: RSA", "quantum-vulnerable", "high"),
                    t if t.starts_with("ecdsa-sha2") => {
                        ("SSH host key: ECDSA", "quantum-vulnerable", "high")
                    }
                    "ssh-ed25519" => ("SSH host key: Ed25519", "quantum-vulnerable", "high"),
                    "ssh-dss" => ("SSH host key: DSA", "quantum-vulnerable", "high"),
                    _ => ("SSH host key: unrecognized type", "context", "medium"),
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
            if t.starts_with("KexAlgorithms")
                || t.starts_with("Ciphers")
                || t.starts_with("HostKeyAlgorithms")
                || t.starts_with("MACs")
            {
                push(
                    findings,
                    "/etc/ssh/sshd_config".to_string(),
                    format!("sshd policy: {}", t.chars().take(120).collect::<String>()),
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

#[cfg(target_os = "linux")]
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
            if path.is_file() || fs::metadata(&path).map(|m| m.is_file()).unwrap_or(false) {
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

#[cfg(target_os = "linux")]
fn collect_configs(findings: &mut Vec<Finding>) {
    for cfg in [
        "/etc/ssl/openssl.cnf",
        "/etc/crypto-policies/config",
        "/etc/crypto-policies/state/current",
    ] {
        if let Ok(text) = fs::read_to_string(cfg) {
            let first = text
                .lines()
                .find(|l| {
                    let t = l.trim();
                    !t.is_empty() && !t.starts_with('#')
                })
                .unwrap_or("")
                .trim();
            push(
                findings,
                cfg.to_string(),
                format!(
                    "crypto policy file ({})",
                    if first.is_empty() { "present" } else { first }
                ),
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

#[cfg(target_os = "linux")]
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
            .unwrap_or_default()
            .trim()
            .to_string();
        let mut libs: BTreeSet<&'static str> = BTreeSet::new();
        for line in maps.lines() {
            if let Some(pos) = line.find('/') {
                let path = &line[pos..];
                if let Some(fname) = Path::new(path).file_name().and_then(|n| n.to_str()) {
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
                "crypto libraries mapped into a running process".to_string(),
            );
        }
    }
    let running_as_root = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|uid| uid.parse::<u32>().ok())
        })
        == Some(0);
    if denied > 0 || !running_as_root {
        push(
            findings,
            "/proc".to_string(),
            format!(
                "process scan: {} processes unreadable; non-root scans \
                     cannot guarantee full process coverage",
                denied
            ),
            "coverage limitation",
            "context",
            "info",
            "/proc/*/maps".to_string(),
            "blind spot reported explicitly (spec 4.5)".to_string(),
        );
    }
}

#[cfg(target_os = "linux")]
pub fn collect(findings: &mut Vec<Finding>) {
    collect_libraries(findings);
    collect_kernel(findings);
    collect_ssh(findings);
    collect_cert_stores(findings);
    collect_configs(findings);
    collect_processes(findings);
}

#[cfg(target_os = "windows")]
fn collect_windows_libraries(findings: &mut Vec<Finding>) {
    let windows = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let system32 = windows.join("System32");
    let libraries = [
        ("bcrypt.dll", "Windows CNG BCrypt provider"),
        ("ncrypt.dll", "Windows CNG NCrypt provider"),
        ("crypt32.dll", "Windows CryptoAPI certificate provider"),
    ];
    for (name, product) in libraries {
        let path = system32.join(name);
        if !path.is_file() {
            continue;
        }
        let fp = file_sha256(&path).unwrap_or_default();
        push(
            findings,
            path.display().to_string(),
            format!("library: {} ({})", product, name),
            "crypto library provider",
            "context",
            "medium",
            if fp.is_empty() {
                "unreadable".to_string()
            } else {
                format!("sha256:{}", fp)
            },
            "Windows system cryptography library".to_string(),
        );
    }
}

#[cfg(target_os = "windows")]
fn collect_windows_policy(findings: &mut Vec<Finding>) {
    let key = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy";
    if let Ok(output) = Command::new("reg.exe")
        .args(["query", key, "/v", "Enabled"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let enabled = text.lines().any(|line| {
                line.contains("Enabled") && (line.contains("0x1") || line.trim_end().ends_with("1"))
            });
            push(
                findings,
                key.to_string(),
                format!(
                    "Windows system FIPS policy: {}",
                    if enabled { "enabled" } else { "disabled" }
                ),
                "operating environment",
                "context",
                "info",
                "registry value Enabled".to_string(),
                "Operating-system policy is not proof that a particular ".to_string()
                    + "application module is in approved mode",
            );
        }
    }
}

#[cfg(target_os = "windows")]
fn collect_windows_cert_store(findings: &mut Vec<Finding>) {
    if let Ok(output) = Command::new("certutil.exe")
        .args(["-store", "Root"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let count = text
                .lines()
                .filter(|line| {
                    line.contains("Cert Hash(sha1)") || line.contains("Cert Hash(sha256)")
                })
                .count();
            push(
                findings,
                "Windows LocalMachine Root certificate store".to_string(),
                format!("OS certificate store: {} observed certificates", count),
                "authentication (trust anchors)",
                "context",
                "info",
                "certutil -store Root".to_string(),
                "Windows trust store; scan exported PEM files for per-certificate ".to_string()
                    + "algorithm findings",
            );
        }
    }
}

#[cfg(target_os = "windows")]
pub fn collect(findings: &mut Vec<Finding>) {
    collect_windows_libraries(findings);
    collect_windows_policy(findings);
    collect_windows_cert_store(findings);
    if findings.is_empty() {
        push(
            findings,
            "Windows host".to_string(),
            "system inventory coverage limitation".to_string(),
            "coverage limitation",
            "context",
            "info",
            "native Windows collectors".to_string(),
            "No readable Windows crypto providers or certificate store were found".to_string(),
        );
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_libraries(findings: &mut Vec<Finding>) {
    let candidates = [
        (
            "/System/Library/Frameworks/Security.framework/Security",
            "Apple Security framework",
        ),
        ("/usr/lib/libcrypto.dylib", "OpenSSL-compatible libcrypto"),
        ("/usr/local/lib/libcrypto.dylib", "OpenSSL libcrypto"),
        (
            "/opt/homebrew/opt/openssl/lib/libcrypto.dylib",
            "Homebrew OpenSSL libcrypto",
        ),
        ("/opt/veloce/lib/libwolfssl.dylib", "wolfSSL"),
    ];
    for (name, product) in candidates {
        let path = Path::new(name);
        if !path.is_file() {
            continue;
        }
        let fp = file_sha256(path).unwrap_or_default();
        push(
            findings,
            path.display().to_string(),
            format!("library: {}", product),
            "crypto library provider",
            "context",
            "medium",
            if fp.is_empty() {
                "unreadable".to_string()
            } else {
                format!("sha256:{}", fp)
            },
            "macOS cryptography library or framework".to_string(),
        );
    }
}

#[cfg(target_os = "macos")]
fn collect_macos_keychain(findings: &mut Vec<Finding>) {
    let keychain = "/System/Library/Keychains/SystemRootCertificates.keychain";
    if let Ok(output) = Command::new("security")
        .args(["find-certificate", "-a", "-Z", keychain])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            let count = text
                .lines()
                .filter(|line| line.contains("SHA-256 hash"))
                .count();
            push(
                findings,
                keychain.to_string(),
                format!("macOS system roots: {} observed certificates", count),
                "authentication (trust anchors)",
                "context",
                "info",
                "security find-certificate -a -Z".to_string(),
                "macOS system trust store; export certificates for ".to_string()
                    + "per-certificate algorithm findings",
            );
        }
    }
}

#[cfg(target_os = "macos")]
pub fn collect(findings: &mut Vec<Finding>) {
    collect_macos_libraries(findings);
    collect_macos_keychain(findings);
    push(
        findings,
        "macOS operating environment".to_string(),
        "application FIPS state requires live Veloce agent evidence".to_string(),
        "coverage limitation",
        "context",
        "info",
        "no macOS kernel FIPS-mode flag".to_string(),
        "Use the Veloce Desktop security dashboard for module hash, self-test, ".to_string()
            + "entropy, and approved-mode status",
    );
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn collect(findings: &mut Vec<Finding>) {
    push(
        findings,
        std::env::consts::OS.to_string(),
        "host collector not implemented for this operating system".to_string(),
        "coverage limitation",
        "context",
        "info",
        "portable source scanner remains available".to_string(),
        "Use qsearch scan <path> for source and certificate discovery".to_string(),
    );
}
