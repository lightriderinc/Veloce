"""Gate G3/G4 items (spec 10): IPC hardening, protocol enforcement, EMS
zero-network guarantee, CBOM export and diagnostic redaction."""
import json
import os
import socket
import struct

import pytest


def _raw(sock_path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.settimeout(5)
    return s


def test_protocol_version_enforced(agent):
    s = _raw(agent["socket"])
    req = json.dumps({"v": 99, "id": 1, "op": "health"}).encode()
    s.sendall(struct.pack(">I", len(req)) + req)
    n = struct.unpack(">I", s.recv(4))[0]
    resp = json.loads(s.recv(n))
    assert resp["ok"] is False
    assert resp["error"]["code"] == "bad_request"
    s.close()


def test_oversized_frame_rejected(agent):
    s = _raw(agent["socket"])
    s.sendall(struct.pack(">I", 1 << 25))  # 32 MiB claim
    s.sendall(b"x" * 64)
    # Agent must drop the connection without honoring the frame.
    try:
        data = s.recv(4)
        assert data == b""
    except (ConnectionResetError, socket.timeout, BrokenPipeError):
        pass
    s.close()


def test_malformed_json_answered_with_error(agent):
    s = _raw(agent["socket"])
    req = b"{not json"
    s.sendall(struct.pack(">I", len(req)) + req)
    n = struct.unpack(">I", s.recv(4))[0]
    resp = json.loads(s.recv(n))
    assert resp["ok"] is False
    s.close()


def test_ems_disabled_blocks_mixin(veloce_sdk):
    with pytest.raises(veloce_sdk.VeloceError) as e:
        veloce_sdk.set_entropy_mixin(True)
    assert e.value.code == "ems_disabled"
    providers = veloce_sdk.list_entropy_providers()["providers"]
    mixin = [p for p in providers if p["name"] == "cloud-entropy-mixin"][0]
    assert mixin["state"] == "off"
    assert mixin["credited"] is False


def test_zero_network_traffic_when_ems_disabled(agent):
    """Spec 6: EMS disabled is enforced by a zero-network-traffic test.
    The agent process must hold no INET/INET6 sockets."""
    pid = agent["proc"].pid
    inodes = set()
    fd_dir = f"/proc/{pid}/fd"
    for fd in os.listdir(fd_dir):
        try:
            target = os.readlink(os.path.join(fd_dir, fd))
        except OSError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[8:-1])
    net_inodes = set()
    for table in ("tcp", "tcp6", "udp", "udp6"):
        try:
            with open(f"/proc/net/{table}") as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) > 9:
                        net_inodes.add(parts[9])
        except OSError:
            continue
    assert not (inodes & net_inodes), \
        "agent holds INET sockets while EMS is disabled"


def test_cbom_exports(veloce_sdk):
    records = veloce_sdk.export_cbom(format="records")
    comps = {r.get("component") for r in records["records"]}
    assert "wolfcrypt-fips" in comps
    assert "veloce-pqc-provider" in comps
    assert "veloce-agent-runtime" in comps
    runtime = [r for r in records["records"]
               if r.get("component") == "veloce-agent-runtime"][0]
    assert runtime["ems_enabled"] is False
    assert runtime["cloud_entropy_mixin"] == "off"

    bom = veloce_sdk.export_cbom(format="cyclonedx")
    assert bom["bomFormat"] == "CycloneDX"
    names = {c["name"] for c in bom["components"]}
    assert "ML-KEM-768" in names and "ML-DSA-65" in names


def test_diagnostic_bundle_redaction(veloce_sdk, tmp_path):
    kp = veloce_sdk.mlkem_generate_keypair()
    import base64
    pub_b64 = base64.b64encode(kp.public_key).decode()
    out = str(tmp_path / "diag.json")
    r = veloce_sdk.generate_diagnostic_bundle(path=out)
    assert r["path"] == out
    text = open(out).read()
    bundle = json.loads(text)
    assert "redaction" in bundle
    # No key material of any kind in the bundle.
    assert pub_b64[:32] not in text
    assert kp.private_key_handle not in text
    assert "BEGIN" not in text
