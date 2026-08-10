"""Gate G2 addition: qSearch host collector inventories the crypto modules
present on the machine (spec 4.1 certificate-store and endpoint/config
collectors)."""
import json
import os
import subprocess

import pytest

from conftest import QSEARCH_BIN


@pytest.fixture(scope="module")
def sysscan(tmp_path_factory):
    if not os.path.exists(QSEARCH_BIN):
        pytest.skip("qsearch not built (cargo build --release)")
    out = tmp_path_factory.mktemp("sys")
    r = subprocess.run([QSEARCH_BIN, "system", "--out", str(out), "--quiet"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.load(open(out / "findings.json"))


def test_finds_installed_crypto_libraries(sysscan):
    libs = [f for f in sysscan["findings"]
            if f["algorithm"].startswith("library:")]
    assert libs, "no crypto libraries found on host"
    assert all(f["provenance"] == "directly observed" for f in libs)
    assert any(f["source_of_evidence"].startswith("sha256:") for f in libs)


def test_kernel_crypto_inventoried(sysscan):
    kernel = [f for f in sysscan["findings"]
              if f["asset"] == "/proc/crypto"]
    if not kernel:
        pytest.skip("/proc/crypto not readable on this host")
    qv = [f for f in kernel if f["classification"] == "quantum-vulnerable"]
    assert any("kernel crypto API" in f["algorithm"] for f in kernel)
    assert qv, "expected quantum-vulnerable kernel algorithms (rsa/dh)"


def test_ssh_host_keys_classified(sysscan):
    ssh = [f for f in sysscan["findings"]
           if f["algorithm"].startswith("SSH host key")]
    if not ssh:
        pytest.skip("no readable SSH host keys on this host")
    assert all(f["classification"] == "quantum-vulnerable" for f in ssh
               if "unrecognized" not in f["algorithm"])


def test_coverage_limits_reported_not_hidden(sysscan):
    """Spec 4.5: blind spots are reported explicitly."""
    if os.geteuid() == 0:
        pytest.skip("running as root; no expected blind spot")
    notes = [f for f in sysscan["findings"]
             if f["cryptographic_service"] == "coverage limitation"]
    assert notes, "unreadable-process blind spot not reported"
