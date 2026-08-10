# Veloce examples

## python-demo.py

End-to-end SDK walkthrough against a running agent: health, ML-KEM-768
encapsulation, ML-DSA-65 signatures, policy profiles, key release, CBOM
export.

```
python3 scripts/gen_config.py
build/bin/veloce-agent --config ~/.veloce/agent.json &
python3 examples/python-demo.py
```

## tls-client / tls-server (stage S3)

The hybrid TLS 1.3 sample pair (X25519MLKEM768, spec 5.4) requires a full
wolfSSL TLS build with ML-KEM enabled (autotools build of the same release;
the V1 PQC provider library is wolfCrypt-only). The samples land with the S3
gate; the policy control plane (configure_hybrid_tls) is functional now and
is exercised by the gate battery.
