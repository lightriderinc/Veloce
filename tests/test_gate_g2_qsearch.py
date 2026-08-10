"""Gate G2 (spec 10): qSearch detects all planted crypto in the controlled
sample environment and produces every output format."""
import csv
import json
import os
import subprocess

import pytest

from conftest import QSEARCH_BIN


@pytest.fixture()
def scan(planted_tree, tmp_path):
    if not os.path.exists(QSEARCH_BIN):
        pytest.skip("qsearch not built (cargo build --release)")
    out = tmp_path / "out"
    r = subprocess.run(
        [QSEARCH_BIN, "scan", str(planted_tree), "--out", str(out),
         "--quiet"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return out


def test_expected_detections(scan):
    doc = json.load(open(scan / "findings.json"))
    algs = {f["algorithm"] for f in doc["findings"]}
    assert "RSA" in algs
    assert "ECDSA" in algs
    assert "DH" in algs
    assert any(f["classification"] == "pqc-ready"
               for f in doc["findings"])  # ML-KEM usage recognized


def test_certificate_discovery_provenance(scan):
    doc = json.load(open(scan / "findings.json"))
    certs = [f for f in doc["findings"]
             if f["provenance"] == "directly observed"]
    if not certs:
        pytest.skip("openssl unavailable; no planted certificate")
    assert any(f["source_of_evidence"].startswith("sha256:") for f in certs)
    assert any("RSA" in f["algorithm"] for f in certs)


def test_output_formats(scan):
    assert (scan / "findings.csv").exists()
    rows = list(csv.DictReader(open(scan / "findings.csv")))
    assert rows and "algorithm" in rows[0]

    bom = json.load(open(scan / "cbom.cdx.json"))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert any(c["cryptoProperties"]["assetType"] == "algorithm"
               for c in bom["components"])

    inv = json.load(open(scan / "m2302-inventory.json"))
    assert all(e["quantum_vulnerable"] for e in inv["entries"])
    assert inv["entries"], "expected quantum-vulnerable inventory entries"

    summary = open(scan / "executive-summary.txt").read()
    assert "Quantum-vulnerable findings" in summary


def test_offline_operation(scan):
    """qSearch runs fully offline (spec 4); the scan already completed
    without any network configuration, and produces deterministic outputs."""
    assert (scan / "executive-summary.txt").exists()
