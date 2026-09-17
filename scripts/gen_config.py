#!/usr/bin/env python3
"""Generate the Veloce agent configuration from the staged build records.

Writes the per-user agent configuration (override with --out) pointing the
agent at the hash-recorded FIPS module and PQC provider under build/lib/.
Library file names come from each build-record.json; a platform glob is the
fallback for records without a library field. EMS defaults to disabled
(spec 6: zero network traffic by default).

Default output and endpoint by platform:
  Linux    ~/.veloce/agent.json                       socket ~/.veloce/agent.sock
  macOS    ~/.veloce/agent.json                       socket ~/.veloce/agent.sock
  Windows  %LOCALAPPDATA%\\Lightrider\\Veloce\\agent.json  pipe \\\\.\\pipe\\LightRider.PQC.v1
"""
import argparse
import glob
import json
import os
import platform
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WINDOWS_PIPE = r"\\.\pipe\LightRider.PQC.v1"


def platform_defaults(platform_name=None):
    platform_name = platform_name or sys.platform
    if platform_name == "darwin":
        return {"fips_glob": "libwolfssl.*.dylib", "pqc_name": "libveloce-pqc.dylib",
                "build_hint": "scripts/build_macos.sh", "endpoint_key": "socket",
                "endpoint": os.path.expanduser("~/.veloce/agent.sock"),
                "out": os.path.expanduser("~/.veloce/agent.json")}
    if platform_name.startswith("win"):
        state = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                             "Lightrider", "Veloce")
        return {"fips_glob": "wolfssl-fips*.dll", "pqc_name": "veloce-pqc.dll",
                "build_hint": "docs/windows.md", "endpoint_key": "pipe",
                "endpoint": WINDOWS_PIPE, "out": os.path.join(state, "agent.json")}
    return {"fips_glob": "libwolfssl.so.*.*.*", "pqc_name": "libveloce-pqc.so",
            "build_hint": "scripts/build_fips.sh", "endpoint_key": "socket",
            "endpoint": os.path.expanduser("~/.veloce/agent.sock"),
            "out": os.path.expanduser("~/.veloce/agent.json")}


def default_entropy_source(machine=None):
    """"rdseed" on x86-64 (hardware seed source); "os-drbg" elsewhere.

    os-drbg is the operating system DRBG output: an SP 800-90C RBGC chain
    with no security-strength claim. The agent reports it as such."""
    machine = (machine or platform.machine()).lower()
    if machine in ("x86_64", "amd64", "x64"):
        return "rdseed"
    return "os-drbg"


def recorded_library(lib_dir, fallback_glob):
    """Resolve the staged library from its build record, else by glob."""
    record_path = os.path.join(lib_dir, "build-record.json")
    try:
        with open(record_path, encoding="utf-8") as handle:
            name = json.load(handle).get("library")
    except (OSError, ValueError, AttributeError):
        name = None
    if isinstance(name, str) and name:
        candidate = os.path.join(lib_dir, name)
        if os.path.exists(candidate):
            return candidate
    libs = sorted(glob.glob(os.path.join(lib_dir, fallback_glob)))
    return libs[0] if libs else None


def main() -> int:
    defaults = platform_defaults()
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=defaults["out"])
    ap.add_argument("--socket", default=None,
                    help="UNIX socket path (Linux/macOS)")
    ap.add_argument("--pipe", default=None,
                    help="named pipe path (Windows)")
    ap.add_argument("--entropy-source", choices=["rdseed", "os-drbg"],
                    default=os.environ.get("VELOCE_ENTROPY_SOURCE")
                    or default_entropy_source(),
                    help="seed source: rdseed (hardware, default on x86-64) "
                         "or os-drbg (unvalidated OS DRBG chain)")
    args = ap.parse_args()

    fips_dir = os.path.join(ROOT, "build", "lib", "fips")
    pqc_dir = os.path.join(ROOT, "build", "lib", "pqc")
    fips_lib = recorded_library(fips_dir, defaults["fips_glob"])
    if fips_lib is None:
        print(f"gen_config: FIPS library not staged; run {defaults['build_hint']}",
              file=sys.stderr)
        return 1
    pqc_lib = recorded_library(pqc_dir, defaults["pqc_name"])
    if pqc_lib is None:
        print(f"gen_config: PQC provider not staged; run {defaults['build_hint']}",
              file=sys.stderr)
        return 1

    if defaults["endpoint_key"] == "pipe":
        endpoint = args.pipe or defaults["endpoint"]
    else:
        endpoint = args.socket or defaults["endpoint"]
    cfg = {
        defaults["endpoint_key"]: endpoint,
        "fips_lib": fips_lib,
        "fips_record": os.path.join(fips_dir, "build-record.json"),
        "pqc_lib": pqc_lib,
        "pqc_record": os.path.join(pqc_dir, "build-record.json"),
        # Cloud EMS: off by default (zero network traffic). Enable with
        # `veloce ems on` then `veloce mixin on`, or edit mode below. The
        # pinned key is GET https://ems.lightriderinc.com/v1/pubkey.
        "ems": {"mode": "disabled", "endpoint": "https://ems.lightriderinc.com",
                "policy": "fastest_available",
                "pubkey_hex": "cdec782a5dccf410739222245344883ca70d9a5788948f83a15cf94da3e355bf",
                "interval_s": 60, "bytes": 64, "entropy_mixin": "off"},
        "entropy": {"source": args.entropy_source},
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
