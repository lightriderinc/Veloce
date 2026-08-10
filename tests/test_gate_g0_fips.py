"""Gate G0 (spec 10): FIPS module built, self-tests green, hashes recorded."""
import glob
import hashlib
import json
import os

from conftest import FIPS_DIR, PQC_DIR, ROOT


def test_fips_build_record_matches_library():
    record = json.load(open(os.path.join(FIPS_DIR, "build-record.json")))
    libs = sorted(glob.glob(os.path.join(FIPS_DIR, "libwolfssl.so.*.*.*")))
    assert libs, "FIPS library not staged"
    digest = hashlib.sha256(open(libs[0], "rb").read()).hexdigest()
    assert digest == record["sha256"]
    assert record["fips_certificate"] == "#4718"
    assert record["fips_module_version"] == "5.2.1"
    assert "--enable-fips=v5" in record["build_flags"]
    assert "wolfEntropy" in record["build_flags"]


def test_testwolfcrypt_green():
    log = os.path.join(ROOT, "build", "fips-src", "testwolfcrypt.log")
    assert os.path.exists(log), "testwolfcrypt.log missing; rerun build_fips"
    text = open(log).read()
    assert "Test complete" in text
    assert "return code: 0" in text
    assert "FAILED" not in text


def test_pqc_build_record_matches_library():
    record = json.load(open(os.path.join(PQC_DIR, "build-record.json")))
    lib = os.path.join(PQC_DIR, "libveloce-pqc.so")
    digest = hashlib.sha256(open(lib, "rb").read()).hexdigest()
    assert digest == record["sha256"]
    assert record["pqc_inside_fips_boundary"] is False
