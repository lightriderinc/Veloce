#!/usr/bin/env python3
"""Generate the Veloce agent configuration from the staged build records.

Writes ~/.veloce/agent.json (override with --out) pointing the agent at the
hash-recorded FIPS module and PQC provider under build/lib/. EMS defaults to
disabled (spec 6: zero network traffic by default).
"""
import argparse
import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.expanduser("~/.veloce/agent.json"))
    ap.add_argument("--socket",
                    default=os.path.expanduser("~/.veloce/agent.sock"))
    args = ap.parse_args()

    fips_dir = os.path.join(ROOT, "build", "lib", "fips")
    pqc_dir = os.path.join(ROOT, "build", "lib", "pqc")
    fips_libs = sorted(glob.glob(os.path.join(fips_dir, "libwolfssl.so.*.*.*")))
    if not fips_libs:
        print("gen_config: FIPS library not staged; run scripts/build_fips.sh",
              file=sys.stderr)
        return 1
    pqc_lib = os.path.join(pqc_dir, "libveloce-pqc.so")
    if not os.path.exists(pqc_lib):
        print("gen_config: PQC provider not staged; run scripts/build_pqc.sh",
              file=sys.stderr)
        return 1

    cfg = {
        "socket": args.socket,
        "fips_lib": fips_libs[0],
        "fips_record": os.path.join(fips_dir, "build-record.json"),
        "pqc_lib": pqc_lib,
        "pqc_record": os.path.join(pqc_dir, "build-record.json"),
        "ems": {"mode": "disabled", "endpoint": "", "entropy_mixin": "off"},
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(cfg, f, indent=2)
    print(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
