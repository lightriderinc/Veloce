// Light Rider CBOM workbook export (Appendix B; cbom/field-mapping.md).
//
// Emits CSV rows whose headers match the workbook
// Light_Rider_CBOM_Template_Updated.xlsx exactly, so findings paste
// straight into the "Discovery Findings" and "Scanning Log" sheets.
use crate::Finding;
use std::fs;
use std::path::Path;

// Exact header rows from the workbook (verified against the template).
const DISCOVERY_HEADERS: &str =
    "Finding ID,CBOM Record ID,Mission Thread ID,Discovery Date,\
     Discovery Method,Tool / Capability,Coverage Domain,Asset / Endpoint,\
     Internet or Internal,Observed Crypto Artifact,Algorithm / Protocol,\
     Library / Package,Container Image / Digest,SBOM Reference,\
     Evidence Location,Finding Confidence,Authoritative Record Matched?,\
     Validation Status,Blind Spot / Limitation,False Positive?,\
     Remediation Required?,Assigned Owner,Next Validation Date,\
     Source / Notes";

const SCANLOG_HEADERS: &str =
    "Scan ID,Scan Date,Tool / Method,Scope,Environment,Assets Scanned,\
     New Crypto Findings,Changed Findings,High-Risk Findings,\
     CBOM Records Updated,False Positives,Exceptions,Operator,\
     Evidence Location,Next Scan Date,Notes";

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// Civil date from UNIX epoch seconds (Howard Hinnant's algorithm).
pub fn iso_date(epoch: u64) -> String {
    let days = (epoch / 86400) as i64;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", y, m, d)
}

fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown-host".to_string())
}

pub fn write_discovery_findings(out: &Path, findings: &[Finding],
                                mode: &str, version: &str, now: u64) {
    let date = iso_date(now);
    let coverage = if mode == "system" { "host inventory" }
                   else { "source code and certificates" };
    let mut w = String::from(DISCOVERY_HEADERS);
    w.push('\n');
    for (i, f) in findings.iter().enumerate() {
        let is_blind_spot = f.service == "coverage limitation";
        let library = if f.algorithm.starts_with("library:") {
            f.algorithm.trim_start_matches("library:").trim()
        } else {
            ""
        };
        let remediation = match (f.classification.as_str(), f.risk.as_str()) {
            ("quantum-vulnerable", "high") => "Yes",
            ("quantum-vulnerable", _) => "Review",
            _ => "No",
        };
        let row = [
            format!("FIND-{:05}", i + 1),
            String::new(), // CBOM Record ID: assigned during correlation
            String::new(), // Mission Thread ID: assigned by mission owner
            date.clone(),
            f.provenance.clone(),
            format!("qSearch {} ({} collector)", version, mode),
            coverage.to_string(),
            f.asset.clone(),
            "Internal".to_string(),
            f.detail.clone(),
            f.algorithm.clone(),
            library.to_string(),
            String::new(), // Container Image / Digest
            String::new(), // SBOM Reference
            f.evidence.clone(),
            f.confidence.clone(),
            "No".to_string(), // Authoritative Record Matched?
            "Unvalidated (automated finding)".to_string(),
            if is_blind_spot { f.detail.clone() } else { String::new() },
            String::new(), // False Positive?: set during validation
            remediation.to_string(),
            String::new(), // Assigned Owner
            String::new(), // Next Validation Date: per validation policy
            format!("classification: {}; risk: {}", f.classification,
                    f.risk),
        ];
        let cells: Vec<String> = row.iter().map(|c| csv_escape(c)).collect();
        w.push_str(&cells.join(","));
        w.push('\n');
    }
    fs::write(out.join("workbook-discovery-findings.csv"), w)
        .expect("write workbook-discovery-findings.csv");
}

pub fn write_scanning_log(out: &Path, findings: &[Finding], mode: &str,
                          version: &str, now: u64, scope: &str,
                          assets_scanned: u64) {
    let high = findings.iter().filter(|f| f.risk == "high").count();
    let fp_note = "pending validation";
    let row = [
        format!("SCAN-{}", now),
        iso_date(now),
        format!("qSearch {} ({} collector)", version, mode),
        scope.to_string(),
        format!("{} (linux x86-64)", hostname()),
        assets_scanned.to_string(),
        findings.len().to_string(),
        String::new(), // Changed Findings: needs a prior baseline
        high.to_string(),
        String::new(), // CBOM Records Updated: set during correlation
        fp_note.to_string(),
        String::new(), // Exceptions
        std::env::var("USER").unwrap_or_default(),
        "workbook-discovery-findings.csv + findings.json".to_string(),
        String::new(), // Next Scan Date: per scanning policy
        "reference workbook: Light_Rider_CBOM_Template_Updated.xlsx"
            .to_string(),
    ];
    let cells: Vec<String> = row.iter().map(|c| csv_escape(c)).collect();
    let mut w = String::from(SCANLOG_HEADERS);
    w.push('\n');
    w.push_str(&cells.join(","));
    w.push('\n');
    fs::write(out.join("workbook-scanning-log.csv"), w)
        .expect("write workbook-scanning-log.csv");
}
