"""Gate G1 (spec 10): entropy pipeline, fail-closed state machine, PQC ops
through the agent, validation-status API."""
import pytest


def test_health_approved(veloce_sdk):
    h = veloce_sdk.health()
    assert h["state"] == "ok"
    assert h["approved_mode"] is True
    assert h["entropy"]["healthy"] is True
    assert h["fips_module_status"] == 0


def test_version_facts(veloce_sdk):
    v = veloce_sdk.version()
    assert v["fips_certificate"] == "#4718"
    assert v["fips_module_version"] == "5.2.1"
    assert v["vendor"] == "Lightrider Inc"


def test_validation_status_per_item(veloce_sdk):
    vs = veloce_sdk.validation_status()
    assert vs["approved_mode"] is True
    items = {i["item"]: i for i in vs["items"]}
    assert items["fips_module"]["certificate"] == "#4718"
    assert items["fips_module"]["sha256_verified_before_load"] is True
    assert items["pqc_provider"]["pqc_inside_fips_boundary"] is False
    assert items["cloud_entropy_mixin"]["state"] == "off"
    assert items["cloud_entropy_mixin"]["credited"] is False


def test_self_tests(veloce_sdk):
    st = veloce_sdk.run_fips_self_tests()
    assert st["casts"] == "pass"
    assert st["pqc_self_test"] == "pass"
    assert st["module_status"] == 0
    assert st["entropy_health"].startswith("pass")


def test_mlkem_roundtrip(veloce_sdk):
    kp = veloce_sdk.mlkem_generate_keypair()
    assert kp.private_key_handle.startswith("vlk-")
    assert len(kp.public_key) == 1184  # ML-KEM-768 encapsulation key
    ct, ss_send = veloce_sdk.mlkem_encapsulate(kp.public_key)
    assert len(ct) == 1088 and len(ss_send) == 32
    ss_recv = veloce_sdk.mlkem_decapsulate(kp.private_key_handle, ct)
    assert ss_send == ss_recv


def test_mlkem_implicit_rejection(veloce_sdk):
    kp = veloce_sdk.mlkem_generate_keypair()
    ct, ss = veloce_sdk.mlkem_encapsulate(kp.public_key)
    bad = bytearray(ct)
    bad[7] ^= 0x10
    ss2 = veloce_sdk.mlkem_decapsulate(kp.private_key_handle, bytes(bad))
    assert ss2 != ss  # FIPS 203 implicit rejection


def test_mldsa_sign_verify_and_negative(veloce_sdk):
    kp = veloce_sdk.mldsa_generate_keypair()
    msg = b"gate G1 message"
    sig = veloce_sdk.mldsa_sign(kp.private_key_handle, msg)
    assert veloce_sdk.mldsa_verify(kp.public_key, msg, sig) is True
    bad = bytearray(sig)
    bad[11] ^= 0x01
    assert veloce_sdk.mldsa_verify(kp.public_key, msg, bytes(bad)) is False
    assert veloce_sdk.mldsa_verify(kp.public_key, b"other", sig) is False


def test_private_keys_never_cross_ipc(veloce_sdk):
    kp = veloce_sdk.mlkem_generate_keypair()
    raw = veloce_sdk._c().call("mlkem_generate_keypair",
                               {"parameter_set": 768})
    assert set(raw.keys()) == {"public_key", "private_key_handle",
                               "parameter_set"}


def test_release_key_zeroization_contract(veloce_sdk):
    kp = veloce_sdk.mlkem_generate_keypair()
    kp.release()
    ct, _ = veloce_sdk.mlkem_encapsulate(kp.public_key)
    with pytest.raises(veloce_sdk.VeloceError) as e:
        veloce_sdk.mlkem_decapsulate(kp.private_key_handle, ct)
    assert e.value.code == "invalid_handle"


def test_unknown_handle_rejected(veloce_sdk):
    with pytest.raises(veloce_sdk.VeloceError) as e:
        veloce_sdk.mldsa_sign("vlk-doesnotexist", b"x")
    assert e.value.code == "invalid_handle"


def test_policy_profiles_and_hybrid_tls(veloce_sdk):
    profiles = veloce_sdk.list_policy_profiles()
    names = {p["name"] for p in profiles["profiles"]}
    assert "LIGHTRIDER_PQC_TRANSITION" in names
    r = veloce_sdk.configure_hybrid_tls("LIGHTRIDER_PQC_TRANSITION")
    assert r["group"] == "X25519MLKEM768"
    assert r["tls_version"] == "1.3"
    with pytest.raises(veloce_sdk.VeloceError):
        veloce_sdk.configure_hybrid_tls("NOT_A_PROFILE")
