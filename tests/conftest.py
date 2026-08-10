"""Gate battery fixtures: starts a private Veloce agent on a temp socket."""
import json
import os
import shutil
import signal
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "python"))

AGENT_BIN = os.environ.get("VELOCE_AGENT_BIN",
                           os.path.join(ROOT, "build", "bin", "veloce-agent"))
QSEARCH_BIN = os.environ.get("VELOCE_QSEARCH",
                             os.path.join(ROOT, "build", "bin", "qsearch"))
FIPS_DIR = os.path.join(ROOT, "build", "lib", "fips")
PQC_DIR = os.path.join(ROOT, "build", "lib", "pqc")


def _fips_lib():
    import glob
    libs = sorted(glob.glob(os.path.join(FIPS_DIR, "libwolfssl.so.*.*.*")))
    return libs[0] if libs else None


@pytest.fixture(scope="session")
def agent(tmp_path_factory):
    if not os.path.exists(AGENT_BIN):
        pytest.skip("agent not built (make -C agent)")
    lib = _fips_lib()
    if lib is None:
        pytest.skip("FIPS library not staged (scripts/build_fips.sh)")
    tmp = tmp_path_factory.mktemp("veloce")
    sock = str(tmp / "agent.sock")
    cfg = {
        "socket": sock,
        "fips_lib": lib,
        "fips_record": os.path.join(FIPS_DIR, "build-record.json"),
        "pqc_lib": os.path.join(PQC_DIR, "libveloce-pqc.so"),
        "pqc_record": os.path.join(PQC_DIR, "build-record.json"),
        "ems": {"mode": "disabled", "endpoint": "", "entropy_mixin": "off"},
    }
    cfg_path = str(tmp / "agent.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen([AGENT_BIN, "--config", cfg_path, "--quiet"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    for _ in range(50):
        if os.path.exists(sock):
            break
        time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("agent did not create its socket")

    os.environ["VELOCE_SOCKET"] = sock
    import veloce
    veloce._client = None  # reset any cached client
    veloce.initialize(sock)
    yield {"proc": proc, "socket": sock, "config": cfg_path}
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="session")
def veloce_sdk(agent):
    import veloce
    return veloce


@pytest.fixture()
def planted_tree(tmp_path):
    """Controlled sample environment with known crypto (spec 9, qSearch gate)."""
    (tmp_path / "legacy.c").write_text(
        '#include <openssl/ssl.h>\n'
        'RSA_generate_key(2048, 65537, 0, 0);\n'
        'ECDSA_sign(0, digest, 32, sig, &siglen, eckey);\n'
        'DH_generate_key(dh);\n')
    (tmp_path / "app.py").write_text(
        'from cryptography.hazmat.primitives.asymmetric import rsa\n'
        'key = rsa.generate_private_key(public_exponent=65537, '
        'key_size=2048)\n')
    (tmp_path / "modern.rs").write_text(
        '// uses ML-KEM via veloce agent\nlet kp = mlkem_generate_keypair();\n')
    cert = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout",
         "/dev/null", "-out", str(tmp_path / "server.pem"), "-days", "1",
         "-nodes", "-subj", "/CN=gate-test"],
        capture_output=True)
    if cert.returncode != 0:
        (tmp_path / "server.pem").write_text("")  # cert case then skipped
    return tmp_path
