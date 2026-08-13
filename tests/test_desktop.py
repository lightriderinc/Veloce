"""Desktop UI model and release-contract tests."""
import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT))

from desktop import veloce_desktop


def _load_release_builder():
    path = ROOT / "scripts" / "build_desktop_release.py"
    spec = importlib.util.spec_from_file_location("build_desktop_release", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_summarize_findings_for_dashboard():
    report = {
        "scan_root": "/project",
        "files_scanned": 12,
        "findings": [
            {"algorithm": "RSA", "classification": "quantum-vulnerable",
             "risk": "high", "asset": "a.py", "source_of_evidence": "a.py:1"},
            {"algorithm": "RSA", "classification": "quantum-vulnerable",
             "risk": "medium", "asset": "b.py", "source_of_evidence": "b.py:2"},
            {"algorithm": "ML-KEM", "classification": "pqc-ready",
             "risk": "info", "asset": "c.py", "source_of_evidence": "c.py:3"},
        ],
    }
    summary = veloce_desktop.summarize_findings(report)
    assert summary["files_scanned"] == 12
    assert summary["counts"] == {
        "total": 3,
        "quantum_vulnerable": 2,
        "high_risk": 1,
        "pqc_ready": 1,
    }
    assert summary["top_algorithms"][0] == {"algorithm": "RSA", "count": 2}


def test_fips_snapshot_never_infers_live_approval(monkeypatch):
    monkeypatch.setattr(veloce_desktop, "find_tool", lambda *_: None)
    monkeypatch.setattr(
        veloce_desktop,
        "load_record",
        lambda name: {"fips_certificate": "#4718", "sha256": "abc"}
        if name.startswith("wolfcrypt") else {"pqc_inside_fips_boundary": False},
    )
    snapshot = veloce_desktop.DesktopService("token").fips_snapshot()
    assert snapshot["live"] is False
    assert snapshot["approved_mode"] is False
    assert snapshot["state"] == "unavailable"
    assert snapshot["fips_record"]["fips_certificate"] == "#4718"


def _pe_x86_64() -> bytes:
    value = bytearray(512)
    value[:2] = b"MZ"
    struct.pack_into("<I", value, 0x3C, 0x80)
    value[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", value, 0x84, 0x8664)
    return bytes(value)


def _macho(arch: str) -> bytes:
    cpu_type = 0x01000007 if arch == "x86_64" else 0x0100000C
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu_type) + bytes(504)


def _write_runtime(root: Path, environment: str, suffix: str,
                   target: str = "windows", arch: str = "x86_64") -> None:
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    native = _pe_x86_64() if target == "windows" else _macho(arch)
    agent = native + b"agent"
    fips = native + b"fips"
    pqc = native + b"pqc"
    (root / "bin" / f"veloce-agent{suffix}").write_bytes(agent)
    (root / "lib" / "wolfcrypt-native.bin").write_bytes(fips)
    (root / "lib" / "veloce-pqc-native.bin").write_bytes(pqc)
    (root / "lib" / "wolfcrypt-fips.build-record.json").write_text(json.dumps({
        "library": "wolfcrypt-native.bin",
        "sha256": hashlib.sha256(fips).hexdigest(),
        "operating_environment": environment,
    }))
    (root / "lib" / "veloce-pqc.build-record.json").write_text(json.dumps({
        "library": "veloce-pqc-native.bin",
        "sha256": hashlib.sha256(pqc).hexdigest(),
        "operating_environment": environment,
    }))


def test_windows_runtime_contract(tmp_path):
    builder = _load_release_builder()
    _write_runtime(tmp_path, "Windows 11 Pro x86_64", ".exe")
    builder.validate_runtime(tmp_path, "windows")


@pytest.mark.parametrize("arch", ["x86_64", "arm64"])
def test_macos_runtime_contract(tmp_path, arch):
    builder = _load_release_builder()
    _write_runtime(tmp_path, f"macOS 15 {arch}", "", "macos", arch)
    builder.validate_runtime(tmp_path, "macos", arch)


def test_runtime_contract_rejects_wrong_operating_environment(tmp_path):
    builder = _load_release_builder()
    _write_runtime(tmp_path, "Linux x86_64", ".exe")
    with pytest.raises(SystemExit, match="does not match"):
        builder.validate_runtime(tmp_path, "windows")


def test_runtime_contract_rejects_hash_mismatch(tmp_path):
    builder = _load_release_builder()
    _write_runtime(tmp_path, "Windows 11 Pro x86_64", ".exe")
    (tmp_path / "lib" / "wolfcrypt-native.bin").write_bytes(_pe_x86_64() + b"changed")
    with pytest.raises(SystemExit, match="SHA-256"):
        builder.validate_runtime(tmp_path, "windows")


def test_runtime_contract_rejects_wrong_native_architecture(tmp_path):
    builder = _load_release_builder()
    _write_runtime(tmp_path, "macOS 15 arm64", "", "macos", "x86_64")
    for record_name in ["wolfcrypt-fips.build-record.json",
                        "veloce-pqc.build-record.json"]:
        record_path = tmp_path / "lib" / record_name
        record = json.loads(record_path.read_text())
        record["operating_environment"] = "macOS 15 arm64"
        record_path.write_text(json.dumps(record))
    with pytest.raises(SystemExit, match="does not contain arm64"):
        builder.validate_runtime(tmp_path, "macos", "arm64")


def test_macos_full_runtime_exports_socket_before_cli(monkeypatch, tmp_path):
    monkeypatch.delenv("VELOCE_SOCKET", raising=False)
    monkeypatch.setattr(veloce_desktop.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(veloce_desktop, "_user_state_dir", lambda *_: tmp_path)
    monkeypatch.setattr(veloce_desktop, "find_tool", lambda *_: tmp_path / "veloce")
    service = veloce_desktop.DesktopService("token")
    monkeypatch.setattr(service, "_release_manifest",
                        lambda: {"mode": "full-runtime"})

    observed = []
    def fake_command(command, timeout=20):
        observed.append((command[-1], veloce_desktop.os.environ.get("VELOCE_SOCKET")))
        if command[-1] == "status":
            return {"approved_mode": True, "state": "ok"}
        return {}

    monkeypatch.setattr(veloce_desktop, "run_json_command", fake_command)
    snapshot = service.fips_snapshot()
    assert snapshot["live"] is True
    assert observed[0] == ("status", str(tmp_path / "agent.sock"))
