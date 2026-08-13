// Veloce qSearch (spec 4): cryptographic discovery engine. Source-code and
// certificate collectors with Lightrider-owned normalization,
// classification, CBOM generation, risk prioritization and reporting.
// Fully offline; runs outside the FIPS boundary; std-only build.
mod json;
mod patterns;
mod sha256;
mod system;
mod workbook;

use json::J;
use patterns::{PATTERNS, SOURCE_EXTS};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const VERSION: &str = "1.0.0";
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Default)]
struct Stats {
    files_seen: u64,
    files_scanned: u64,
    skipped_large: u64,
    skipped_binary: u64,
}

#[derive(Clone)]
pub struct Finding {
    pub asset: String, // file path, library, or process
    pub algorithm: String,
    pub service: String,
    pub classification: String, // quantum-vulnerable | pqc-ready | context
    pub risk: String,           // high | medium | info
    pub evidence: String,       // file:line or fingerprint
    pub detail: String,
    pub provenance: String, // spec 4.3 provenance label
    pub confidence: String,
    pub last_observed: u64,
}

fn banner(quiet: bool) {
    if quiet || std::env::var("VELOCE_NO_BANNER").as_deref() == Ok("1") {
        return;
    }
    eprintln!("qSearch {} | Lightrider Inc Veloce PQC SDK", VERSION);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut root: Option<PathBuf> = None;
    let mut out_dir = PathBuf::from("qsearch-out");
    let mut merge_cbom: Option<PathBuf> = None;
    let mut quiet = false;
    let mut mode_system = false;
    let mut i = 1;
    if args.len() > 1 && args[1] == "scan" {
        i = 2;
    } else if args.len() > 1 && args[1] == "system" {
        mode_system = true;
        i = 2;
    }
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out_dir = PathBuf::from(&args[i]);
            }
            "--merge-agent-cbom" => {
                i += 1;
                merge_cbom = Some(PathBuf::from(&args[i]));
            }
            "--quiet" | "--json" => quiet = true,
            a if !a.starts_with('-') && root.is_none() => {
                root = Some(PathBuf::from(a));
            }
            _ => {}
        }
        i += 1;
    }
    let root = match (mode_system, root) {
        (true, r) => r.unwrap_or_else(default_system_root),
        (false, Some(r)) => r,
        (false, None) => {
            eprintln!(
                "usage: qsearch scan <path> [--out DIR] \
                 [--merge-agent-cbom FILE] [--quiet]\n       \
                 qsearch system [--out DIR] [--quiet]"
            );
            std::process::exit(2);
        }
    };
    banner(quiet);

    let started = std::time::Instant::now();
    let started_epoch = now();
    let mode = if mode_system { "system" } else { "scan" };
    let mut findings: Vec<Finding> = Vec::new();
    let mut stats = Stats::default();
    if mode_system {
        // Host collector: crypto modules present on this machine
        // (libraries, kernel, SSH, cert stores, configs, processes).
        system::collect(&mut findings);
        stats.files_scanned = findings.len() as u64;
        stats.files_seen = stats.files_scanned;
    } else {
        walk(&root, &mut |path| {
            scan_file(path, &mut findings, &mut stats);
        });
    }
    let files_scanned = stats.files_scanned;

    fs::create_dir_all(&out_dir).expect("cannot create output directory");
    let agent_records = merge_cbom.and_then(|p| fs::read_to_string(p).ok());

    write_json(&out_dir, &findings, files_scanned, &root, &agent_records);
    write_csv(&out_dir, &findings);
    write_cyclonedx(&out_dir, &findings);
    write_m2302(&out_dir, &findings, &root);
    write_summary(&out_dir, &findings, files_scanned, &root);
    workbook::write_discovery_findings(&out_dir, &findings, mode, VERSION, started_epoch);
    workbook::write_scanning_log(
        &out_dir,
        &findings,
        mode,
        VERSION,
        started_epoch,
        &root.display().to_string(),
        files_scanned,
    );
    write_run_log(
        &out_dir,
        &findings,
        &stats,
        mode,
        &root,
        started_epoch,
        started.elapsed(),
        agent_records.is_some(),
    );
    if !quiet {
        print_client_summary(&out_dir, &findings, mode);
    }
}

fn default_system_root() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        return std::env::var("SystemDrive")
            .map(|drive| PathBuf::from(format!("{}\\", drive)))
            .unwrap_or_else(|_| PathBuf::from(r"C:\"));
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/")
    }
}

// Client-facing output: the findings that matter plus the next commands.
// Runtime detail lives in <out>/qsearch-run.log.
fn print_client_summary(out: &Path, findings: &[Finding], mode: &str) {
    let qv = findings
        .iter()
        .filter(|f| f.classification == "quantum-vulnerable")
        .count();
    let high = findings.iter().filter(|f| f.risk == "high").count();
    let ready = findings
        .iter()
        .filter(|f| f.classification == "pqc-ready")
        .count();
    println!(
        "Findings: {} total | {} quantum-vulnerable | {} high risk | \
              {} PQC-ready",
        findings.len(),
        qv,
        high,
        ready
    );

    let mut top: BTreeMap<&str, usize> = BTreeMap::new();
    for f in findings
        .iter()
        .filter(|f| f.classification == "quantum-vulnerable")
    {
        *top.entry(f.algorithm.as_str()).or_default() += 1;
    }
    let mut entries: Vec<(usize, &str)> = top.into_iter().map(|(k, v)| (v, k)).collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    if !entries.is_empty() {
        println!("\nQuantum-vulnerable, by algorithm:");
        for (count, alg) in entries.iter().take(8) {
            println!("  {:5}  {}", count, alg);
        }
    }

    let o = out.display();
    println!("\nReports in {}/:", o);
    println!("  executive-summary.txt            client summary");
    println!(
        "  workbook-discovery-findings.csv  paste into \
              Light_Rider_CBOM_Template_Updated.xlsx, sheet \
              \"Discovery Findings\""
    );
    println!(
        "  workbook-scanning-log.csv        paste into sheet \
              \"Scanning Log\""
    );
    println!(
        "  findings.json / findings.csv / cbom.cdx.json / \
              m2302-inventory.json"
    );
    println!("  qsearch-run.log                  runtime detail");

    println!("\nNext commands:");
    if mode == "system" {
        if findings.iter().any(|f| f.service == "coverage limitation") {
            println!(
                "  sudo qsearch system --out {}    # full process \
                      coverage",
                o
            );
        }
        println!(
            "  qsearch scan /etc/ssl/certs --out certs-out    \
                  # per-certificate fingerprints"
        );
    } else {
        println!(
            "  qsearch system --out host-inventory    # crypto modules \
                  installed on this host"
        );
    }
    let target = if mode == "scan" { " <path>" } else { "" };
    println!(
        "  veloce cbom > agent-cbom.json && qsearch {}{} \
              --merge-agent-cbom agent-cbom.json    # add agent runtime \
              records",
        mode, target
    );
}

fn write_run_log(
    out: &Path,
    findings: &[Finding],
    stats: &Stats,
    mode: &str,
    root: &Path,
    started_epoch: u64,
    elapsed: std::time::Duration,
    merged: bool,
) {
    let mut log = String::new();
    log.push_str(&format!("qsearch {} run log\n", VERSION));
    log.push_str(&format!("mode: {}\n", mode));
    log.push_str(&format!("root: {}\n", root.display()));
    log.push_str(&format!(
        "started_unix: {} ({})\n",
        started_epoch,
        workbook::iso_date(started_epoch)
    ));
    log.push_str(&format!("duration_ms: {}\n", elapsed.as_millis()));
    log.push_str(&format!("files_seen: {}\n", stats.files_seen));
    log.push_str(&format!("files_scanned: {}\n", stats.files_scanned));
    log.push_str(&format!(
        "skipped_over_{}MB: {}\n",
        MAX_FILE_BYTES / (1024 * 1024),
        stats.skipped_large
    ));
    log.push_str(&format!(
        "skipped_binary_or_unreadable: {}\n",
        stats.skipped_binary
    ));
    log.push_str(&format!("findings_total: {}\n", findings.len()));
    for class in ["quantum-vulnerable", "pqc-ready", "context"] {
        log.push_str(&format!(
            "findings_{}: {}\n",
            class.replace('-', "_"),
            findings
                .iter()
                .filter(|f| f.classification == class)
                .count()
        ));
    }
    log.push_str(&format!("agent_records_merged: {}\n", merged));
    log.push_str(
        "outputs: findings.json findings.csv cbom.cdx.json \
                  m2302-inventory.json executive-summary.txt \
                  workbook-discovery-findings.csv workbook-scanning-log.csv\n",
    );
    log.push_str(
        "workbook_reference: \
                  Light_Rider_CBOM_Template_Updated.xlsx\n",
    );
    fs::write(out.join("qsearch-run.log"), log).expect("write qsearch-run.log");
}

fn walk(dir: &Path, f: &mut impl FnMut(&Path)) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if matches!(
                name.as_str(),
                ".git"
                    | "node_modules"
                    | "target"
                    | "__pycache__"
                    | ".venv"
                    | "venv"
                    | ".tox"
                    | "build"
            ) {
                continue;
            }
            walk(&path, f);
        } else if path.is_file() {
            f(&path);
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn mtime(path: &Path) -> u64 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or_else(now)
}

fn scan_file(path: &Path, findings: &mut Vec<Finding>, stats: &mut Stats) {
    stats.files_seen += 1;
    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => {
            stats.skipped_binary += 1;
            return;
        }
    };
    if meta.len() > MAX_FILE_BYTES {
        stats.skipped_large += 1;
        return;
    }
    let ext = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => {
            // binary or unreadable: out of the source collector
            stats.skipped_binary += 1;
            return;
        }
    };
    stats.files_scanned += 1;

    // Certificate collector: any text file containing PEM blocks.
    if text.contains("-----BEGIN CERTIFICATE-----") {
        scan_pem_certs(path, &text, findings);
    }

    if !SOURCE_EXTS.contains(&ext.as_str()) && !matches!(ext.as_str(), "pem" | "crt" | "cer") {
        return;
    }

    let observed = mtime(path);
    for (lineno, line) in text.lines().enumerate() {
        for p in PATTERNS {
            if line.contains(p.needle) {
                findings.push(Finding {
                    asset: path.display().to_string(),
                    algorithm: p.algorithm.to_string(),
                    service: p.service.to_string(),
                    classification: p.classification.to_string(),
                    risk: p.risk.to_string(),
                    evidence: format!("{}:{}", path.display(), lineno + 1),
                    detail: format!(
                        "pattern \"{}\": {}",
                        p.needle,
                        line.trim().chars().take(160).collect::<String>()
                    ),
                    provenance: "statically detected".to_string(),
                    confidence: "medium".to_string(),
                    last_observed: observed,
                });
            }
        }
    }
}

fn b64_decode(input: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits = 0;
    for &c in input.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' || c == b' ' {
            continue;
        }
        buf = (buf << 6) | u32::from(val(c)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

// Known DER-encoded OIDs searched inside certificates (heuristic SPKI /
// signature detection; provenance "directly observed", spec 4.3).
const OIDS: &[(&[u8], &str, &str)] = &[
    (
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
        "RSA",
        "quantum-vulnerable",
    ),
    (
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
        "EC (ECDSA/ECDH)",
        "quantum-vulnerable",
    ),
    (&[0x2b, 0x65, 0x70], "Ed25519", "quantum-vulnerable"),
    (&[0x2b, 0x65, 0x6e], "X25519", "quantum-vulnerable"),
];

fn scan_pem_certs(path: &Path, text: &str, findings: &mut Vec<Finding>) {
    let observed = mtime(path);
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let after = &rest[start + 27..];
        let end = match after.find("-----END CERTIFICATE-----") {
            Some(e) => e,
            None => break,
        };
        let body = &after[..end];
        if let Some(der) = b64_decode(body) {
            let mut sha = sha256::Sha256::new();
            sha.update(&der);
            let fp = sha256::hex(&sha.finalize());
            let mut algs: Vec<&str> = Vec::new();
            let mut class = "context";
            for (oid, name, c) in OIDS {
                if der.windows(oid.len()).any(|w| w == *oid) {
                    algs.push(name);
                    if *c == "quantum-vulnerable" {
                        class = "quantum-vulnerable";
                    }
                }
            }
            let alg = if algs.is_empty() {
                "X.509 certificate (unrecognized key type)".to_string()
            } else {
                algs.join(" + ")
            };
            findings.push(Finding {
                asset: path.display().to_string(),
                algorithm: alg,
                service: "authentication (X.509 certificate)".to_string(),
                classification: class.to_string(),
                risk: if class == "quantum-vulnerable" {
                    "medium"
                } else {
                    "info"
                }
                .to_string(),
                evidence: format!("sha256:{}", fp),
                detail: format!("PEM certificate in {}", path.display()),
                provenance: "directly observed".to_string(),
                confidence: "high".to_string(),
                last_observed: observed,
            });
        }
        rest = &after[end..];
    }
}

fn finding_json(f: &Finding) -> J {
    jobj! {
        "asset" => J::s(&f.asset),
        "algorithm" => J::s(&f.algorithm),
        "cryptographic_service" => J::s(&f.service),
        "classification" => J::s(&f.classification),
        "risk" => J::s(&f.risk),
        "source_of_evidence" => J::s(&f.evidence),
        "detail" => J::s(&f.detail),
        "provenance" => J::s(&f.provenance),
        "confidence" => J::s(&f.confidence),
        "last_observed_unix" => J::Num(f.last_observed as f64),
    }
}

fn write_json(
    out: &Path,
    findings: &[Finding],
    files: u64,
    root: &Path,
    agent_records: &Option<String>,
) {
    let doc = jobj! {
        "format" => J::s("veloce-qsearch-findings/1"),
        "tool" => J::s("qSearch"),
        "tool_version" => J::s(VERSION),
        "vendor" => J::s("Lightrider Inc"),
        "scan_root" => J::s(&root.display().to_string()),
        "generated_unix" => J::Num(now() as f64),
        "files_scanned" => J::Num(files as f64),
        "findings" => J::Arr(findings.iter().map(finding_json).collect()),
        "agent_runtime_records_merged" =>
            J::Bool(agent_records.is_some()),
    };
    let mut text = doc.pretty();
    if let Some(records) = agent_records {
        // Merge the agent self-report verbatim (spec 4.4: SDK runtime
        // validation records merge into the same store).
        let end = text.trim_end().to_string();
        let mut base = end;
        base.pop(); // trailing '}'
        base.push_str(",\n  \"agent_runtime_records\": ");
        base.push_str(records.trim());
        base.push_str("\n}\n");
        text = base;
    }
    fs::write(out.join("findings.json"), text).expect("write findings.json");
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn write_csv(out: &Path, findings: &[Finding]) {
    let mut w = String::from(
        "asset,algorithm,cryptographic_service,classification,risk,\
         source_of_evidence,provenance,confidence,last_observed_unix\n",
    );
    for f in findings {
        w.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            csv_escape(&f.asset),
            csv_escape(&f.algorithm),
            csv_escape(&f.service),
            f.classification,
            f.risk,
            csv_escape(&f.evidence),
            f.provenance,
            f.confidence,
            f.last_observed
        ));
    }
    fs::write(out.join("findings.csv"), w).expect("write findings.csv");
}

fn write_cyclonedx(out: &Path, findings: &[Finding]) {
    // One component per unique algorithm, evidence occurrences attached.
    let mut by_alg: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_alg.entry(f.algorithm.clone()).or_default().push(f);
    }
    let comps: Vec<J> = by_alg
        .iter()
        .map(|(alg, fs)| {
            let occurrences: Vec<J> = fs
                .iter()
                .take(64)
                .map(|f| jobj! { "location" => J::s(&f.evidence) })
                .collect();
            jobj! {
                "type" => J::s("cryptographic-asset"),
                "name" => J::s(alg),
                "cryptoProperties" => jobj! {
                    "assetType" => J::s("algorithm"),
                    "veloce:classification" => J::s(&fs[0].classification),
                    "veloce:risk" => J::s(&fs[0].risk),
                },
                "evidence" => jobj! {
                    "occurrences" => J::Arr(occurrences),
                },
            }
        })
        .collect();
    let bom = jobj! {
        "bomFormat" => J::s("CycloneDX"),
        "specVersion" => J::s("1.6"),
        "version" => J::Num(1.0),
        "metadata" => jobj! {
            "tools" => J::Arr(vec![jobj! {
                "vendor" => J::s("Lightrider Inc"),
                "name" => J::s("qSearch"),
                "version" => J::s(VERSION),
            }]),
        },
        "components" => J::Arr(comps),
    };
    fs::write(out.join("cbom.cdx.json"), bom.pretty()).expect("write cbom.cdx.json");
}

fn write_m2302(out: &Path, findings: &[Finding], root: &Path) {
    // OMB M-23-02 inventory fields: system, algorithm, usage, and whether
    // the asset is quantum-vulnerable.
    let rows: Vec<J> = findings
        .iter()
        .filter(|f| f.classification == "quantum-vulnerable")
        .map(|f| {
            jobj! {
                "information_system" => J::s(&root.display().to_string()),
                "asset" => J::s(&f.asset),
                "cryptographic_algorithm" => J::s(&f.algorithm),
                "usage" => J::s(&f.service),
                "quantum_vulnerable" => J::Bool(true),
                "evidence" => J::s(&f.evidence),
            }
        })
        .collect();
    let doc = jobj! {
        "format" => J::s("veloce-m2302-inventory/1"),
        "generated_unix" => J::Num(now() as f64),
        "entries" => J::Arr(rows),
    };
    fs::write(out.join("m2302-inventory.json"), doc.pretty()).expect("write m2302-inventory.json");
}

fn write_summary(out: &Path, findings: &[Finding], files: u64, root: &Path) {
    let qv = findings
        .iter()
        .filter(|f| f.classification == "quantum-vulnerable")
        .count();
    let ready = findings
        .iter()
        .filter(|f| f.classification == "pqc-ready")
        .count();
    let high = findings.iter().filter(|f| f.risk == "high").count();
    let mut top: BTreeMap<&str, usize> = BTreeMap::new();
    for f in findings
        .iter()
        .filter(|f| f.classification == "quantum-vulnerable")
    {
        *top.entry(f.algorithm.as_str()).or_default() += 1;
    }
    let mut summary = String::new();
    summary.push_str("Veloce qSearch executive summary\n");
    summary.push_str("Lightrider Inc | Veloce PQC SDK\n\n");
    summary.push_str(&format!("Scan root: {}\n", root.display()));
    summary.push_str(&format!("Files scanned: {}\n", files));
    summary.push_str(&format!("Total findings: {}\n", findings.len()));
    summary.push_str(&format!("Quantum-vulnerable findings: {}\n", qv));
    summary.push_str(&format!("High-risk findings: {}\n", high));
    summary.push_str(&format!("PQC-ready findings: {}\n\n", ready));
    summary.push_str("Quantum-vulnerable algorithms by count:\n");
    let mut entries: Vec<(usize, &str)> = top.into_iter().map(|(k, v)| (v, k)).collect();
    entries.sort_by(|a, b| b.0.cmp(&a.0));
    for (count, alg) in entries.iter().take(10) {
        summary.push_str(&format!("  {:5}  {}\n", count, alg));
    }
    summary.push_str(
        "\nOutputs: findings.json (canonical), findings.csv, cbom.cdx.json \
         (CycloneDX 1.6), m2302-inventory.json, \
         workbook-discovery-findings.csv and workbook-scanning-log.csv \
         (Light_Rider_CBOM_Template_Updated.xlsx sheets), \
         executive-summary.txt; runtime detail in qsearch-run.log\n",
    );
    fs::write(out.join("executive-summary.txt"), &summary).expect("write executive-summary.txt");
}
