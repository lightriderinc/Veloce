# Veloce IPC protocol v1

Spec traceability: engineering plan section 3 (authenticated local IPC) and
section 8 (IPC hardening).

## Transport

- Linux: UNIX domain stream socket. Default path: `/run/veloce/agent.sock`
  when the agent runs as root, else `$XDG_RUNTIME_DIR/veloce/agent.sock`,
  else `~/.veloce/agent.sock`. Socket mode 0660. The agent verifies the peer
  with `SO_PEERCRED`: connections are accepted only from the agent's own UID
  or from root.
- Windows: named pipe `\\.\pipe\LightRider.PQC.v1` with an explicit ACL
  (service identity, authorized local user, local admins; deny
  anonymous/remote/unauthenticated). Remote pipe clients are rejected.
- macOS: UNIX domain stream socket under the current user's Veloce application
  state directory. The agent verifies the peer with `getpeereid`; connections
  are accepted only from the agent's own UID or root.

## Framing

Length-prefixed, versioned. Each message is:

| Bytes | Content |
|---|---|
| 0..3 | Payload length, unsigned 32-bit big-endian. Maximum 1048576 (1 MiB). |
| 4..  | Payload: UTF-8 JSON, exactly `length` bytes. |

A frame longer than the maximum, an unparsable payload, or a protocol
version other than 1 closes the connection after an error response when one
can be sent.

## Messages

Request:

```json
{ "v": 1, "id": 7, "op": "mlkem_generate_keypair", "params": { "parameter_set": 768 } }
```

Response (success):

```json
{ "v": 1, "id": 7, "ok": true, "result": { "public_key": "<base64>", "private_key_handle": "vlk-..." } }
```

Response (error):

```json
{ "v": 1, "id": 7, "ok": false, "error": { "code": "degraded", "message": "..." } }
```

Error codes: `bad_request`, `unknown_op`, `degraded`, `crypto_error`,
`invalid_handle`, `ems_disabled`, `internal`.

## Data rules (spec 8)

- All binary values are base64 strings.
- Private keys never cross the channel; key-producing ops return a
  `private_key_handle` (`vlk-` prefix) plus the public key.
- No raw entropy, DRBG state, or plaintext diagnostics on the channel.

## Operations

The 17 public API functions map 1:1 onto ops, plus the approved V1
extension `set_entropy_mixin`, plus two housekeeping ops:

| Op | Params | Result (summary) |
|---|---|---|
| `initialize` | | status snapshot |
| `health` | | state, fips_status, entropy, ems, uptime |
| `version` | | agent, protocol, module, certificates |
| `list_policy_profiles` | | profiles[] |
| `list_crypto_providers` | | providers[] with validation facts |
| `list_entropy_providers` | | providers[] incl. cloud mix-in state |
| `validation_status` | | per-item validation records |
| `mlkem_generate_keypair` | parameter_set (768) | public_key, private_key_handle |
| `mlkem_encapsulate` | public_key | ciphertext, shared_secret |
| `mlkem_decapsulate` | private_key_handle, ciphertext | shared_secret |
| `mldsa_generate_keypair` | parameter_set (65) | public_key, private_key_handle |
| `mldsa_sign` | private_key_handle, message | signature |
| `mldsa_verify` | public_key, message, signature | valid |
| `configure_hybrid_tls` | policy | policy, tls_version, group |
| `run_fips_self_tests` | | per-test results |
| `approved_mode_status` | | approved, details |
| `export_cbom` | format ("records" or "cyclonedx") | CBOM document |
| `generate_diagnostic_bundle` | path (optional) | path, summary |
| `set_entropy_mixin` | enabled (bool) | mixin state |
| `release_key` | private_key_handle | released |
| `shutdown` | | acknowledges, then agent exits (local admin use) |

`mldsa_generate_keypair` is an implementation addition: the guidance fixes
17 functions and names `mldsa_sign`/`mldsa_verify` but no ML-DSA key
generation; the op is required for those two to be exercisable and is
flagged for guidance reconciliation.
