// Veloce CLI (spec 7): operator commands over the authenticated local IPC
// channel. Crypto-free thin client; machine-readable output is never
// polluted by the banner (spec 7.3).
use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;

const VERSION: &str = "1.0.0";
const BANNER: &str = r#"
  _   _  ____  __     ___    ____  ____
 | | | || ___| | |   / _ \  / ___|| ___|
 | | | || |_   | |  | | | || |    | |_
 | |_| || __|  | |__| |_| || |___ | __|
  \___/ |____| |____|\___/  \____||____|
"#;

fn socket_path() -> String {
    if let Ok(p) = env::var("VELOCE_SOCKET") {
        return p;
    }
    if let Ok(home) = env::var("HOME") {
        return format!("{}/.veloce/agent.sock", home);
    }
    "/run/veloce/agent.sock".to_string()
}

fn esc(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn call(op: &str, params: &str) -> Result<String, String> {
    let path = socket_path();
    let mut s = UnixStream::connect(&path)
        .map_err(|e| format!("cannot connect to Veloce agent at {}: {}", path, e))?;
    let req = format!(
        "{{\"v\":1,\"id\":1,\"op\":{},\"params\":{}}}",
        esc(op),
        params
    );
    let len = (req.len() as u32).to_be_bytes();
    s.write_all(&len).and_then(|_| s.write_all(req.as_bytes()))
        .map_err(|e| format!("send failed: {}", e))?;
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).map_err(|e| format!("recv failed: {}", e))?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n == 0 || n > (1 << 20) {
        return Err("invalid response frame".to_string());
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).map_err(|e| format!("recv failed: {}", e))?;
    String::from_utf8(buf).map_err(|_| "invalid UTF-8 in response".to_string())
}

// Extracts a scalar field value from a flat JSON fragment (status line only;
// full parsing is left to the SDK).
fn extract<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{}\":", key);
    let idx = json.find(&pat)? + pat.len();
    let rest = &json[idx..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(&stripped[..end])
    } else {
        let end = rest.find([',', '}'])?;
        Some(rest[..end].trim())
    }
}

fn print_banner(quiet: bool, json_mode: bool) {
    if quiet || json_mode
        || env::var("VELOCE_NO_BANNER").as_deref() == Ok("1") {
        return;
    }
    println!("{}", BANNER);
    println!("Lightrider Inc -- Veloce PQC SDK v{}", VERSION);
    match call("health", "{}") {
        Ok(resp) => {
            let approved = extract(&resp, "approved_mode")
                .unwrap_or("unknown");
            let entropy = extract(&resp, "healthy").unwrap_or("unknown");
            println!(
                "FIPS 140-3 #4718 | ESV entropy: {} | approved mode: {}",
                if entropy == "true" { "OK" } else { "FAILED" },
                if approved == "true" { "on" } else { "off" }
            );
        }
        Err(_) => println!("agent unreachable"),
    }
    println!();
}

fn run(op: &str, params: &str) {
    match call(op, params) {
        Ok(resp) => println!("{}", resp),
        Err(e) => {
            eprintln!("veloce: {}", e);
            std::process::exit(1);
        }
    }
}

fn usage() -> ! {
    eprintln!(
        "Veloce CLI {} (Lightrider Inc)\n\
         usage: veloce [--quiet|--json] <command>\n\n\
         commands:\n  \
         status            agent health\n  \
         version           component versions\n  \
         validation        per-item validation status\n  \
         self-test         run FIPS CASTs, entropy health, PQC self-test\n  \
         providers         crypto providers\n  \
         entropy           entropy providers incl. cloud mix-in state\n  \
         policies          policy profiles\n  \
         cbom [cyclonedx]  export CBOM (default: records format)\n  \
         diag              write a redacted diagnostic bundle\n  \
         scan <path>       run qSearch source/cert discovery\n  \
         system-scan       inventory crypto modules on this host\n",
        VERSION
    );
    std::process::exit(2);
}

fn main() {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let quiet = args.iter().any(|a| a == "--quiet");
    let json_mode = args.iter().any(|a| a == "--json");
    args.retain(|a| a != "--quiet" && a != "--json");
    if args.is_empty() {
        usage();
    }
    let is_tty = unsafe { libc_isatty() };
    print_banner(quiet || !is_tty, json_mode);

    match args[0].as_str() {
        "status" => run("health", "{}"),
        "version" => run("version", "{}"),
        "validation" => run("validation_status", "{}"),
        "self-test" => run("run_fips_self_tests", "{}"),
        "providers" => run("list_crypto_providers", "{}"),
        "entropy" => run("list_entropy_providers", "{}"),
        "policies" => run("list_policy_profiles", "{}"),
        "cbom" => {
            let format = args.get(1).map(String::as_str).unwrap_or("records");
            run("export_cbom", &format!("{{\"format\":{}}}", esc(format)));
        }
        "diag" => run("generate_diagnostic_bundle", "{}"),
        "scan" | "system-scan" => {
            let mode = if args[0] == "scan" { "scan" } else { "system" };
            let mut qargs: Vec<String> = vec![mode.to_string()];
            if mode == "scan" {
                let path = args.get(1).cloned().unwrap_or_else(|| {
                    eprintln!("veloce scan: path required");
                    std::process::exit(2);
                });
                qargs.push(path);
            }
            let qsearch = env::var("VELOCE_QSEARCH").unwrap_or_else(|_| {
                env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join("qsearch")))
                    .filter(|p| p.exists())
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "qsearch".to_string())
            });
            let status = Command::new(&qsearch).args(&qargs).status();
            match status {
                Ok(st) => std::process::exit(st.code().unwrap_or(1)),
                Err(e) => {
                    eprintln!("veloce {}: cannot run {}: {}", args[0],
                              qsearch, e);
                    std::process::exit(1);
                }
            }
        }
        _ => usage(),
    }
}

// isatty(1) without a libc crate dependency.
unsafe fn libc_isatty() -> bool {
    extern "C" {
        fn isatty(fd: i32) -> i32;
    }
    isatty(1) == 1
}
