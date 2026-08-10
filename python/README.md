# veloce-pqc

Pure-Python client for the Lightrider Veloce agent. The package contains no
cryptographic code: all operations execute inside the local Veloce agent
(wolfCrypt FIPS 140-3, CMVP cert #4718; ML-KEM-768; ML-DSA-65) over an
authenticated local IPC channel. Private keys never leave the agent; the SDK
holds opaque handles only.

```python
import veloce

veloce.initialize()
print(veloce.banner())

kp = veloce.mlkem_generate_keypair()
ct, ss_sender = veloce.mlkem_encapsulate(kp.public_key)
ss_receiver = veloce.mlkem_decapsulate(kp.private_key_handle, ct)
assert ss_sender == ss_receiver

sk = veloce.mldsa_generate_keypair()
sig = veloce.mldsa_sign(sk.private_key_handle, b"message")
assert veloce.mldsa_verify(sk.public_key, b"message", sig)

print(veloce.validation_status())
veloce.export_cbom(format="cyclonedx", path="cbom.json")
```

Requires a running Veloce agent (see the repository README). Set
`VELOCE_SOCKET` to override the agent socket path.

License: Lightrider Inc commercial license (see LICENSE).
