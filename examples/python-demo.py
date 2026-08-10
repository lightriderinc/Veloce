#!/usr/bin/env python3
"""Veloce SDK walkthrough: lifecycle, ML-KEM, ML-DSA, policy, CBOM.

Prerequisite: a running agent (make config && build/bin/veloce-agent).
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

import veloce  # noqa: E402

veloce.initialize()
print(veloce.banner())

print("approved mode:", veloce.approved_mode_status()["approved"])

# ML-KEM-768 key establishment.
kp = veloce.mlkem_generate_keypair()
print("ML-KEM public key bytes:", len(kp.public_key),
      "| handle:", kp.private_key_handle)
ciphertext, secret_sender = veloce.mlkem_encapsulate(kp.public_key)
secret_receiver = veloce.mlkem_decapsulate(kp.private_key_handle, ciphertext)
assert secret_sender == secret_receiver
print("shared secret established:", secret_sender.hex()[:32], "...")

# ML-DSA-65 signatures.
sk = veloce.mldsa_generate_keypair()
message = b"Lightrider Veloce V1"
signature = veloce.mldsa_sign(sk.private_key_handle, message)
print("signature bytes:", len(signature),
      "| verifies:", veloce.mldsa_verify(sk.public_key, message, signature))

# Hybrid TLS policy profile (spec 5.4: policy names, never raw algorithms).
tls = veloce.configure_hybrid_tls("LIGHTRIDER_PQC_TRANSITION")
print("TLS policy:", tls["policy"], "| group:", tls["group"])

# Key custody: release zeroizes agent-side private keys.
kp.release()
sk.release()

# CBOM export for the Light Rider workbook pipeline.
veloce.export_cbom(format="cyclonedx", path="veloce-cbom.cdx.json")
print("CBOM written to veloce-cbom.cdx.json")
