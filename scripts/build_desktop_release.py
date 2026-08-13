#!/usr/bin/env python3
"""Build a native Veloce Desktop payload on Windows or macOS.

Run this script on the target operating system. Cross-compiling the UI alone is
not sufficient because qSearch, the CLI, and any FIPS runtime payload must be
native binaries for that platform.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, NoReturn


ROOT = Path(__file__).resolve().parent.parent


def fail(message: str) -> NoReturn:
    raise SystemExit(f"desktop release: {message}")


def run(command: List[str], cwd: Path = ROOT) -> None:
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=cwd, check=False)
    if completed.returncode != 0:
        fail(f"command failed ({completed.returncode}): {' '.join(command)}")


def load_json(path: Path) -> Dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read valid JSON from {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain a JSON object")
    return value


def normalize_arch(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "x86_64": "x86_64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    return aliases.get(normalized, normalized)


def _cpu_arch(cpu_type: int) -> str:
    if cpu_type == 0x01000007:
        return "x86_64"
    if cpu_type == 0x0100000C:
        return "arm64"
    return f"cpu-{cpu_type:#x}"


def binary_architectures(path: Path, target: str) -> set[str]:
    """Read PE or Mach-O headers without executing untrusted release inputs."""
    try:
        with path.open("rb") as handle:
            header = handle.read(4096)
            if target == "windows":
                if len(header) < 64 or header[:2] != b"MZ":
                    fail(f"{path} is not a Windows PE binary")
                pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
                handle.seek(pe_offset)
                pe = handle.read(6)
                if len(pe) != 6 or pe[:4] != b"PE\0\0":
                    fail(f"{path} has an invalid Windows PE header")
                machine = struct.unpack_from("<H", pe, 4)[0]
                machines = {0x8664: "x86_64", 0xAA64: "arm64"}
                return {machines.get(machine, f"machine-{machine:#x}")}

            if len(header) < 8:
                fail(f"{path} has no readable Mach-O header")
            thin_magics = {
                b"\xcf\xfa\xed\xfe": "<",
                b"\xfe\xed\xfa\xcf": ">",
                b"\xce\xfa\xed\xfe": "<",
                b"\xfe\xed\xfa\xce": ">",
            }
            magic = header[:4]
            if magic in thin_magics:
                cpu_type = struct.unpack_from(thin_magics[magic] + "I", header, 4)[0]
                return {_cpu_arch(cpu_type)}

            fat_magics = {
                b"\xca\xfe\xba\xbe": (">", 20),
                b"\xbe\xba\xfe\xca": ("<", 20),
                b"\xca\xfe\xba\xbf": (">", 32),
                b"\xbf\xba\xfe\xca": ("<", 32),
            }
            if magic not in fat_magics:
                fail(f"{path} is not a macOS Mach-O binary")
            endian, entry_size = fat_magics[magic]
            count = struct.unpack_from(endian + "I", header, 4)[0]
            if count == 0 or count > 32 or 8 + count * entry_size > len(header):
                fail(f"{path} has an invalid universal Mach-O header")
            return {
                _cpu_arch(struct.unpack_from(endian + "I", header,
                                             8 + index * entry_size)[0])
                for index in range(count)
            }
    except OSError as exc:
        fail(f"cannot inspect native binary {path}: {exc}")


def _validate_recorded_library(runtime: Path, record: Dict[str, object],
                               record_path: Path, target: str,
                               arch: str) -> None:
    library = record.get("library")
    if not isinstance(library, str) or not library:
        fail(f"{record_path.name} has no library field")
    library_path = runtime / "lib" / library
    if not library_path.is_file():
        fail(f"recorded library is missing: lib/{library}")

    expected_hash = record.get("sha256")
    if not isinstance(expected_hash, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", expected_hash):
        fail(f"{record_path.name} has no valid sha256 field")
    actual_hash = hashlib.sha256(library_path.read_bytes()).hexdigest()
    if actual_hash.lower() != expected_hash.lower():
        fail(f"recorded SHA-256 does not match lib/{library}")

    environment = str(record.get("operating_environment", "")).lower()
    target_matches = ("windows" in environment if target == "windows" else
                      ("macos" in environment or "mac os" in environment or
                       "darwin" in environment))
    arch_aliases = (["x86_64", "x86-64", "amd64"] if arch == "x86_64"
                    else ["arm64", "aarch64"])
    if not target_matches or not any(alias in environment for alias in arch_aliases):
        fail(f"{record_path.name} operating_environment does not match "
             f"the {target}/{arch} release: {environment or 'empty'}")

    architectures = binary_architectures(library_path, target)
    if arch not in architectures:
        fail(f"lib/{library} does not contain {arch} native code "
             f"(found {', '.join(sorted(architectures))})")


def validate_runtime(runtime: Path, target: str, arch: str = "x86_64") -> None:
    arch = normalize_arch(arch)
    suffix = ".exe" if target == "windows" else ""
    agent = runtime / "bin" / f"veloce-agent{suffix}"
    fips_record_path = runtime / "lib" / "wolfcrypt-fips.build-record.json"
    pqc_record_path = runtime / "lib" / "veloce-pqc.build-record.json"
    for required in [agent, fips_record_path, pqc_record_path]:
        if not required.is_file():
            fail(f"full runtime is missing {required.relative_to(runtime)}")
    fips_record = load_json(fips_record_path)
    pqc_record = load_json(pqc_record_path)
    for record, record_path in [(fips_record, fips_record_path),
                                (pqc_record, pqc_record_path)]:
        _validate_recorded_library(runtime, record, record_path, target, arch)
    agent_architectures = binary_architectures(agent, target)
    if arch not in agent_architectures:
        fail(f"bin/{agent.name} does not contain {arch} native code "
             f"(found {', '.join(sorted(agent_architectures))})")


def copy_tree_files(source: Path, destination: Path) -> None:
    for path in source.rglob("*"):
        if path.is_file():
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


def pyinstaller_args(stage: Path, output: Path, work: Path,
                     target: str, arch: str) -> List[str]:
    separator = os.pathsep
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--onedir", "--windowed",
        "--name", "Veloce",
        "--distpath", str(output),
        "--workpath", str(work),
        "--specpath", str(work),
        "--add-data", f"{ROOT / 'desktop' / 'static'}{separator}desktop/static",
        "--add-data", f"{ROOT / 'LICENSE'}{separator}licenses",
        "--add-data", f"{ROOT / 'THIRD_PARTY_NOTICES.md'}{separator}licenses",
    ]
    if target == "macos":
        args.extend([
            "--osx-bundle-identifier", "com.lightrider.veloce",
            "--target-arch", arch,
        ])
    for path in sorted((stage / "bin").glob("*")):
        args.extend(["--add-binary", f"{path}{separator}bin"])
    if (stage / "lib").is_dir():
        for path in sorted((stage / "lib").glob("*")):
            kind = "--add-data" if path.suffix == ".json" else "--add-binary"
            args.extend([kind, f"{path}{separator}lib"])
    args.append(str(ROOT / "desktop" / "veloce_desktop.py"))
    return args


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=["windows", "macos"], required=True)
    parser.add_argument("--arch", choices=["x86_64", "arm64"], required=True)
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--runtime-dir", type=Path,
                        help="native bin/ + lib/ payload for live FIPS operation")
    parser.add_argument("--discovery-only", action="store_true",
                        help="build qSearch UI without a native FIPS agent")
    parser.add_argument("--validate-only", action="store_true",
                        help="validate inputs without compiling or packaging")
    args = parser.parse_args()

    current = platform.system().lower()
    expected = "windows" if args.platform == "windows" else "darwin"
    if current != expected and not args.validate_only:
        fail(f"{args.platform} packages must be built on {expected}; current host is {current}")
    host_arch = normalize_arch(platform.machine())
    if not args.validate_only and host_arch != args.arch:
        fail(f"requested {args.arch} package on a {host_arch} build host; "
             "use a native Python/Rust host for the requested architecture")
    if bool(args.runtime_dir) == bool(args.discovery_only):
        fail("choose exactly one of --runtime-dir or --discovery-only")
    runtime = args.runtime_dir.resolve() if args.runtime_dir else None
    if runtime:
        validate_runtime(runtime, args.platform, args.arch)
    if args.validate_only:
        mode = "full-runtime" if runtime else "discovery-only"
        print(f"desktop release inputs valid: {args.platform}/{args.arch} ({mode})")
        return 0

    executable_suffix = ".exe" if args.platform == "windows" else ""
    run(["cargo", "build", "--release", "--locked"], ROOT / "qsearch")
    run(["cargo", "build", "--release", "--locked"], ROOT / "cli")

    build_root = ROOT / "build" / "desktop" / f"{args.platform}-{args.arch}"
    stage = build_root / "stage"
    output = build_root / "dist"
    work = build_root / "pyinstaller"
    for directory in [stage, output, work]:
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)
    (stage / "bin").mkdir()
    shutil.copy2(ROOT / "qsearch" / "target" / "release" /
                 f"qsearch{executable_suffix}", stage / "bin")
    shutil.copy2(ROOT / "cli" / "target" / "release" /
                 f"veloce{executable_suffix}", stage / "bin")
    if runtime:
        copy_tree_files(runtime, stage)

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        fail("PyInstaller is required: python -m pip install 'pyinstaller>=6'")
    run(pyinstaller_args(stage, output, work, args.platform, args.arch))

    mode = "full-runtime" if runtime else "discovery-only"
    manifest = {
        "product": "Veloce Desktop",
        "version": args.version,
        "platform": args.platform,
        "architecture": args.arch,
        "mode": mode,
        "live_fips_dashboard": runtime is not None,
        "qsearch_ui": True,
        "fips_claim": "Live agent evidence only; no status inferred from metadata",
    }
    manifest_path = build_root / "release-manifest.json"
    manifest_text = json.dumps(manifest, indent=2) + "\n"
    manifest_path.write_text(manifest_text, encoding="utf-8")
    if args.platform == "windows":
        packaged_manifest = output / "Veloce" / "release-manifest.json"
    else:
        packaged_manifest = (output / "Veloce.app" / "Contents" /
                             "Resources" / "release-manifest.json")
    packaged_manifest.parent.mkdir(parents=True, exist_ok=True)
    packaged_manifest.write_text(manifest_text, encoding="utf-8")
    print(f"desktop release payload: {output}")
    print(f"release manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
