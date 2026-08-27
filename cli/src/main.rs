// Veloce CLI (spec 7): operator commands over the authenticated local IPC
// channel. Crypto-free thin client; machine-readable output is never
// polluted by the banner (spec 7.3).
use std::env;
use std::io::IsTerminal;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(unix)]
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
    s.write_all(&len)
        .and_then(|_| s.write_all(req.as_bytes()))
        .map_err(|e| format!("send failed: {}", e))?;
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr)
        .map_err(|e| format!("recv failed: {}", e))?;
    let n = u32::from_be_bytes(hdr) as usize;
    if n == 0 || n > (1 << 20) {
        return Err("invalid response frame".to_string());
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)
        .map_err(|e| format!("recv failed: {}", e))?;
    String::from_utf8(buf).map_err(|_| "invalid UTF-8 in response".to_string())
}

#[cfg(windows)]
fn pipe_path() -> String {
    env::var("VELOCE_PIPE").unwrap_or_else(|_| r"\\.\pipe\LightRider.PQC.v1".to_string())
}

#[cfg(windows)]
fn call(op: &str, params: &str) -> Result<String, String> {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    type Handle = *mut c_void;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut c_void,
            creation: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn WaitNamedPipeW(name: *const u16, timeout_ms: u32) -> i32;
        fn ReadFile(
            handle: Handle,
            buffer: *mut c_void,
            bytes: u32,
            read: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn WriteFile(
            handle: Handle,
            buffer: *const c_void,
            bytes: u32,
            written: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    struct OwnedHandle(Handle);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn write_all(handle: Handle, data: &[u8]) -> Result<(), String> {
        let mut offset = 0usize;
        while offset < data.len() {
            let mut written = 0u32;
            let remaining = (data.len() - offset).min(u32::MAX as usize) as u32;
            let ok = unsafe {
                WriteFile(
                    handle,
                    data[offset..].as_ptr().cast(),
                    remaining,
                    &mut written,
                    ptr::null_mut(),
                )
            };
            if ok == 0 || written == 0 {
                return Err(format!("named-pipe write failed ({})", unsafe {
                    GetLastError()
                }));
            }
            offset += written as usize;
        }
        Ok(())
    }

    fn read_exact(handle: Handle, data: &mut [u8]) -> Result<(), String> {
        let mut offset = 0usize;
        while offset < data.len() {
            let mut read = 0u32;
            let remaining = (data.len() - offset).min(u32::MAX as usize) as u32;
            let ok = unsafe {
                ReadFile(
                    handle,
                    data[offset..].as_mut_ptr().cast(),
                    remaining,
                    &mut read,
                    ptr::null_mut(),
                )
            };
            if ok == 0 || read == 0 {
                return Err(format!("named-pipe read failed ({})", unsafe {
                    GetLastError()
                }));
            }
            offset += read as usize;
        }
        Ok(())
    }

    let path = pipe_path();
    let wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
    unsafe {
        WaitNamedPipeW(wide.as_ptr(), 3_000);
    }
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(format!(
            "cannot connect to Veloce agent at {} ({})",
            path,
            unsafe { GetLastError() }
        ));
    }
    let handle = OwnedHandle(raw);
    let req = format!(
        "{{\"v\":1,\"id\":1,\"op\":{},\"params\":{}}}",
        esc(op),
        params
    );
    let mut frame = Vec::with_capacity(req.len() + 4);
    frame.extend_from_slice(&(req.len() as u32).to_be_bytes());
    frame.extend_from_slice(req.as_bytes());
    write_all(handle.0, &frame)?;
    let mut header = [0u8; 4];
    read_exact(handle.0, &mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > (1 << 20) {
        return Err("invalid response frame".to_string());
    }
    let mut body = vec![0u8; size];
    read_exact(handle.0, &mut body)?;
    String::from_utf8(body).map_err(|_| "invalid UTF-8 in response".to_string())
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
    if quiet || json_mode || env::var("VELOCE_NO_BANNER").as_deref() == Ok("1") {
        return;
    }
    println!("{}", BANNER);
    println!("Lightrider Inc -- Veloce PQC SDK v{}", VERSION);
    match call("health", "{}") {
        Ok(resp) => {
            let approved = extract(&resp, "approved_mode").unwrap_or("unknown");
            let entropy = extract(&resp, "healthy").unwrap_or("unknown");
            println!(
                "FIPS 140-3 #4718 | entropy: {} | approved mode: {}",
                if entropy == "true" { "verified (local)" } else { "FAILED" },
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
         mixin <on|off>    enable/disable the cloud-entropy mix-in\n  \
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
    let is_tty = std::io::stdout().is_terminal();
    print_banner(quiet || !is_tty, json_mode);

    match args[0].as_str() {
        "status" => run("health", "{}"),
        "version" => run("version", "{}"),
        "validation" => run("validation_status", "{}"),
        "self-test" => run("run_fips_self_tests", "{}"),
        "providers" => run("list_crypto_providers", "{}"),
        "entropy" => run("list_entropy_providers", "{}"),
        "mixin" => {
            let state = args.get(1).map(String::as_str).unwrap_or("");
            let enabled = match state {
                "on" => true,
                "off" => false,
                _ => {
                    eprintln!("veloce mixin: expected on or off");
                    std::process::exit(2);
                }
            };
            run("set_entropy_mixin", &format!("{{\"enabled\":{}}}", enabled));
        }
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
                    .and_then(|p| p.parent().map(|d| d.join(qsearch_name())))
                    .filter(|p| p.exists())
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "qsearch".to_string())
            });
            let status = Command::new(&qsearch).args(&qargs).status();
            match status {
                Ok(st) => std::process::exit(st.code().unwrap_or(1)),
                Err(e) => {
                    eprintln!("veloce {}: cannot run {}: {}", args[0], qsearch, e);
                    std::process::exit(1);
                }
            }
        }
        _ => usage(),
    }
}

fn qsearch_name() -> &'static str {
    if cfg!(windows) {
        "qsearch.exe"
    } else {
        "qsearch"
    }
}
