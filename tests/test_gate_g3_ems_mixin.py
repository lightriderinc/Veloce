"""Gate G3 (spec 6): cloud entropy mix-in end to end against a mock EMS.

A local HTTPS server imitates the Lightrider EMS egress: it answers
POST /v1/entropy/request with a random packet and a receipt signed with a
test Ed25519 key using the production canonicalization (sorted keys,
signature removed, compact JSON). A second agent runs with EMS enabled and
the mix-in on, pointed at the mock through a private CA file. The agent
must verify and mix good packets (DRBG re-instantiation with the packet as
nonce, so the seed callback runs again) and reject tampered ones without
leaving the approved state.
"""
import datetime as dt
import hashlib
import http.server
import json
import os
import secrets
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.request

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python"))
from conftest import AGENT_BIN, FIPS_DIR, PQC_DIR, _fips_lib  # noqa: E402

PINNED_PROD_KEY = "cdec782a5dccf410739222245344883ca70d9a5788948f83a15cf94da3e355bf"
TAMPER_AFTER = 2  # valid receipts served before the mock starts tampering


def _self_signed(tmp):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         crl_sign=True, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path = os.path.join(tmp, "mock-ems.pem")
    key_path = os.path.join(tmp, "mock-ems.key")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert_path, key_path


def canonical_receipt(receipt):
    body = {k: v for k, v in receipt.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class MockEms:
    def __init__(self, tmp):
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        self.pubkey_hex = self.signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.cert_path, key_path = _self_signed(tmp)
        self.requests = 0
        self.lock = threading.Lock()
        mock = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # quiet
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                req = json.loads(self.rfile.read(length) or b"{}")
                if self.path != "/v1/entropy/request":
                    self.send_response(404); self.end_headers(); return
                n = int(req.get("bytes", 64))
                packet = secrets.token_bytes(n)
                receipt = {
                    "request_id": f"lr_req_{secrets.token_hex(8)}",
                    "application_id": req.get("application_id", ""),
                    "policy": req.get("policy", ""),
                    "contributing_sources": ["rdseed_local_001", "curby_q_jila_001"],
                    "pool_id": "pool_fastest",
                    "quality_score": 91,
                    "rct_pass": True,
                    "apt_pass": True,
                    "extractor_alg": "SHAKE256",
                    "input_min_entropy_bits": 2048,
                    "output_bytes": n,
                    "drbg_alg": "HMAC-DRBG-SHA-512",
                    "drbg_reseed_id": secrets.token_hex(8),
                    "timestamp_unix_ns": time.time_ns(),
                    "raw_entropy_stored": False,
                    "audit_event_id": f"audit_{secrets.token_hex(6)}",
                    "zone_id": "",
                    "signature_alg": "Ed25519",
                    "signature": "",
                }
                sig = mock.signing_key.sign(canonical_receipt(receipt))
                with mock.lock:
                    mock.requests += 1
                    tamper = mock.requests > TAMPER_AFTER
                if tamper:
                    sig = bytes([sig[0] ^ 0x01]) + sig[1:]
                receipt["signature"] = sig.hex()
                body = json.dumps({"bytes_hex": packet.hex(), "receipt": receipt},
                                  separators=(",", ":")).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_path, key_path)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture(scope="module")
def ems_agent(tmp_path_factory):
    if not os.path.exists(AGENT_BIN):
        pytest.skip("agent not built (make -C agent)")
    lib = _fips_lib()
    if lib is None:
        pytest.skip("FIPS library not staged")
    tmp = str(tmp_path_factory.mktemp("ems"))
    mock = MockEms(tmp)
    sock = os.path.join(tmp, "agent.sock")
    cfg = {
        "socket": sock,
        "fips_lib": lib,
        "fips_record": os.path.join(FIPS_DIR, "build-record.json"),
        "pqc_lib": os.path.join(PQC_DIR, "libveloce-pqc.so"),
        "pqc_record": os.path.join(PQC_DIR, "build-record.json"),
        "entropy": {"source": os.environ.get("VELOCE_ENTROPY_SOURCE", "rdseed")},
        "ems": {
            "mode": "enabled",
            "endpoint": f"https://localhost:{mock.port}",
            "policy": "fastest_available",
            "pubkey_hex": mock.pubkey_hex,
            "ca_file": mock.cert_path,
            "interval_s": 1,
            "bytes": 64,
            "entropy_mixin": "on",
        },
    }
    cfg_path = os.path.join(tmp, "agent.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    log = open(os.path.join(tmp, "agent.log"), "wb")
    proc = subprocess.Popen([AGENT_BIN, "--config", cfg_path, "--quiet"],
                            stdout=log, stderr=log)
    for _ in range(50):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("EMS agent did not create its socket")
    from veloce._client import Client
    client = Client(sock)
    yield {"client": client, "mock": mock, "proc": proc, "log": log.name}
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    mock.stop()


def _cloud(client):
    providers = client.call("list_entropy_providers", {})["providers"]
    return next(p for p in providers if p["name"] == "cloud-entropy-mixin")


def _wait(predicate, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.25)
    return None


def test_mixin_verifies_and_mixes_packets(ems_agent):
    client = ems_agent["client"]
    def mixed_once():
        c = _cloud(client)
        return c if c["packets_mixed"] >= 1 else None
    cloud = _wait(mixed_once)
    assert cloud, f"no packet mixed; last_error={_cloud(client)['last_error']!r}"
    assert cloud["ems_mode"] == "enabled" and cloud["state"] == "on"
    assert cloud["verification_alg"] == "Ed25519"
    assert cloud["last_verification"].startswith("Ed25519 receipt signature verified")
    assert cloud["last_pool"] == "pool_fastest"
    assert cloud["last_quality_score"] == 91
    assert cloud["last_mixin_unix"] > 0
    assert cloud["credited"] is False
    assert "nonce" in cloud["mixing_method"]
    # Mixing re-instantiates the DRBG, so the seed callback ran again and the
    # agent stays in the approved state.
    health = client.call("health", {})
    assert health["approved_mode"] is True
    assert health["ems"]["packets_mixed"] >= 1
    local = next(p for p in client.call("list_entropy_providers", {})["providers"]
                 if p["name"] == "lightrider-local")
    assert local["seed_blocks_verified"] >= 2
    assert local["seed_health_failures"] == 0


def test_tampered_receipts_are_rejected_fail_safe(ems_agent):
    client = ems_agent["client"]
    def rejected_once():
        c = _cloud(client)
        return c if c["packets_rejected"] >= 1 else None
    cloud = _wait(rejected_once, timeout=30)
    assert cloud, f"tampered packet was not rejected; last_error={_cloud(client)['last_error']!r}"
    assert "signature does not verify" in cloud["last_error"]
    assert cloud["packets_mixed"] <= TAMPER_AFTER
    # Local operation is untouched by cloud failures.
    health = client.call("health", {})
    assert health["approved_mode"] is True
    assert health["entropy"]["healthy"] is True


def test_ems_mode_can_be_switched_off_at_runtime(ems_agent):
    client = ems_agent["client"]
    result = client.call("set_ems_mode", {"enabled": False})
    assert result["ems_mode"] == "disabled" and result["entropy_mixin"] == "off"
    cloud = _cloud(client)
    assert cloud["ems_mode"] == "disabled" and cloud["state"] == "off"
    result = client.call("set_ems_mode", {"enabled": True})
    assert result["ems_mode"] == "enabled"


def test_live_ems_publishes_the_pinned_key():
    """The default configuration pins the production receipt key; confirm
    the live service still serves it (skipped offline)."""
    try:
        with urllib.request.urlopen("https://ems.lightriderinc.com/v1/pubkey", timeout=10) as r:
            body = json.loads(r.read())
    except Exception as exc:  # network unavailable in this environment
        pytest.skip(f"live EMS unreachable: {exc}")
    assert body["signature_alg"] == "Ed25519"
    assert body["public_key_hex"] == PINNED_PROD_KEY
