# Veloce two-server manual test

This procedure tests the current Linux Veloce client bundle on two Hostinger
servers. Build Veloce once on a Lightrider-controlled release machine, then
send the same object-code archive to both servers. The client servers do not
need a GitHub checkout, compiler, or licensed wolfSSL source bundle.

The current release is publicly downloadable and free to use under the
included Lightrider commercial license. It is not OSI open source. Future
managed services, support, updates, or client releases may require a paid
subscription.

| Role | Host | Address |
|---|---|---|
| A: signer / ML-KEM sender | `srv811871.hstgr.cloud` | `168.231.75.64` |
| B: verifier / ML-KEM recipient | `srv862034.hstgr.cloud` | `93.127.215.63` |

The Veloce agent remains local to each host. Do not expose its Unix socket to
the network. These examples establish a shared secret and verify a signature;
they are not a complete application encryption protocol.

## 1. Configure workstation SSH aliases

On the administrator workstation, add entries like these to `~/.ssh/config`.
Replace `HOSTINGER_USER` and the identity-file paths with the actual values.

```text
Host lr168
    HostName 168.231.75.64
    User HOSTINGER_USER
    IdentityFile ~/.ssh/hostinger_168
    IdentitiesOnly yes

Host lr93
    HostName 93.127.215.63
    User HOSTINGER_USER
    IdentityFile ~/.ssh/hostinger_93
    IdentitiesOnly yes
```

Confirm access without changing either server:

```bash
ssh lr168 'hostname; uname -a'
ssh lr93 'hostname; uname -a'
```

No GitHub deploy key is required on either client server.

## 2. Build the client bundle once

Run this section only on the trusted Lightrider release machine that has the
private Veloce repository and authorized wolfSSL bundle. Do not run it on the
two client servers.

```bash
cd "$HOME/src/Veloce"
bash scripts/setup_bundle.sh /secure/path/wolfssl-5.9.2-commercial-fips-linuxv5.2.1
bash scripts/run_gates.sh
VELOCE_INCLUDE_PYTHON_SDK=1 bash scripts/make_release.sh
(cd build/dist && sha256sum -c SHA256SUMS)
```

The gates must end with `ALL GATES GREEN`. The release command creates:

```text
build/dist/veloce-1.0.0-linux-x86_64.tar.gz
build/dist/SHA256SUMS
```

The tarball contains the agent, CLI, qSearch, the versioned wolfCrypt FIPS
shared object, the PQC provider, build records, Python SDK wheel, and this
two-server demonstration. It does not contain wolfSSL source, Veloce native
implementation source, Git history, build trees, or internal plans.

This procedure requires the full bundle with the Python SDK. An archive made
with `VELOCE_INCLUDE_PYTHON_SDK=0` cannot run the two-server Python example.

Only distribute the tarball and its checksum. Never copy `vendor/wolfssl`,
`build/fips-src`, `build/pqc-src`, private keys, or `~/.veloce` state to a
client server. If using Zenodo, download the versioned Linux binary artifact,
not a GitHub-generated source archive.

## 3. Copy and verify the same archive on both servers

On each server, install only the runtime prerequisites:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates python3 python3-venv
install -d -m 700 "$HOME/veloce-delivery"
```

From the administrator workstation, copy the two release files. Adjust the
local path to wherever the approved release artifacts were downloaded.

```bash
release_dir="$HOME/Downloads/veloce-1.0.0"
scp "$release_dir/veloce-1.0.0-linux-x86_64.tar.gz" \
    "$release_dir/SHA256SUMS" lr168:veloce-delivery/
scp "$release_dir/veloce-1.0.0-linux-x86_64.tar.gz" \
    "$release_dir/SHA256SUMS" lr93:veloce-delivery/
```

Run on both servers:

```bash
cd "$HOME/veloce-delivery"
sed -n '/  veloce-1\.0\.0-linux-x86_64\.tar\.gz$/p' SHA256SUMS \
    | sha256sum -c -

install -d -m 700 "$HOME/veloce"
tar -xzf veloce-1.0.0-linux-x86_64.tar.gz -C "$HOME/veloce"

export VELOCE_ROOT="$HOME/veloce/veloce-1.0.0-linux-x86_64"
test -x "$VELOCE_ROOT/bin/veloce-fire-up"
test -f "$VELOCE_ROOT/lib/libwolfssl.so.45.0.0"
test -f "$VELOCE_ROOT/lib/libveloce-pqc.so"
test -f "$VELOCE_ROOT"/veloce_pqc-*.whl
test -f "$VELOCE_ROOT/examples/two-server/two_party_demo.py"
```

The checksum must report `OK`. The two servers must use the identical
versioned archive; compare `sha256sum` output if there is any doubt.

## 4. Install the SDK and fire up Veloce

Run on both servers:

```bash
export VELOCE_ROOT="$HOME/veloce/veloce-1.0.0-linux-x86_64"
export VELOCE_VENV="$HOME/.venvs/veloce-1.0.0"

python3 -m venv "$VELOCE_VENV"
"$VELOCE_VENV/bin/python" -m pip install --no-index \
    "$VELOCE_ROOT"/veloce_pqc-*.whl

"$VELOCE_ROOT/bin/veloce-fire-up"
```

`veloce-fire-up` generates `~/.veloce/agent.json` with absolute library paths
for this extracted bundle, starts the local agent, and runs status plus
self-test. It is safe to run again when the recorded agent is already alive.

Expected results: status reports `"state":"ok"`,
`"approved_mode":true`, FIPS module status `0`, and healthy entropy.
Self-test reports passing CAST, entropy, and PQC tests. The PID is stored in
`~/.veloce/agent.pid` and diagnostic output in `~/.veloce/agent.log`.

Do not open a firewall port for Veloce. The agent communicates through
`~/.veloce/agent.sock` on its own server.

For each later SSH login, restore these convenience variables before running
the example commands:

```bash
export VELOCE_ROOT="$HOME/veloce/veloce-1.0.0-linux-x86_64"
export VELOCE_PYTHON="$HOME/.venvs/veloce-1.0.0/bin/python"
```

## 5. Setup failure guide

- `cd: .../Veloce: No such file or directory`: that path belongs to the
  release-machine source checkout. On a client, use the extracted
  `$HOME/veloce/veloce-1.0.0-linux-x86_64` directory.
- `BUNDLE STILL MISSING` or `licensed bundle not found`: do not provision the
  wolfSSL source on the client. Obtain the approved client tarball containing
  `lib/libwolfssl.so.45.0.0`.
- Missing `veloce_pqc-*.whl` or `two_party_demo.py`: the SDK-free archive was
  delivered. Rebuild or obtain the full archive with
  `VELOCE_INCLUDE_PYTHON_SDK=1`.
- `No module named veloce`: use `$VELOCE_PYTHON`, or reinstall the included
  wheel into the named virtual environment.
- `cannot connect ... agent.sock` with `No such file or directory`: the agent
  did not create its socket. Check `cat ~/.veloce/agent.pid` and
  `tail -n 100 ~/.veloce/agent.log`, then rerun
  `"$VELOCE_ROOT/bin/veloce-fire-up"`.
- `cannot connect ... agent.sock` with `Connection refused`: the socket is
  stale and its agent is dead. `"$VELOCE_ROOT/bin/veloce-fire-up"` removes
  stale local PID/socket files before starting the replacement.
- `Connection to ... closed` immediately after a command guarded by
  `set -e`: an earlier test command failed and terminated that remote shell.
  Reconnect, omit `set -e` while diagnosing, and run each `test -f` command
  individually to identify the missing path. Do not put `set -e` in an SSH
  login startup file.
- `Permission denied`: confirm the archive checksum and inspect
  `ls -l "$VELOCE_ROOT/bin"`; do not run the release as root merely to bypass
  an incorrect extraction.
- `No space left on device`: stop startup commands and recover disk space
  before extracting again. Do not treat a partial extraction as usable.

## 6. Test an ML-DSA signature

On host A (`lr168`):

```bash
export VELOCE_ROOT="$HOME/veloce/veloce-1.0.0-linux-x86_64"
export VELOCE_PYTHON="$HOME/.venvs/veloce-1.0.0/bin/python"
printf '%s\n' 'Lightrider two-server signature test' >/tmp/lr-message.txt
"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    sign-create \
    --message-file /tmp/lr-message.txt \
    --out /tmp/lr-signed.json
```

Use the administrator workstation as the transfer point:

```bash
scp lr168:/tmp/lr-signed.json /tmp/lr-signed.json
scp /tmp/lr-signed.json lr93:/tmp/lr-signed.json
```

On host B (`lr93`):

```bash
export VELOCE_ROOT="$HOME/veloce/veloce-1.0.0-linux-x86_64"
export VELOCE_PYTHON="$HOME/.venvs/veloce-1.0.0/bin/python"
"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    verify --input /tmp/lr-signed.json
```

Expected result: `signature valid: True`. For a negative test, alter the
message or signature in a copy of the JSON document and confirm verification
fails.

This proves signature interoperability. Production identity still requires a
trusted binding between host A and its ML-DSA public key.

## 7. Test ML-KEM shared-secret establishment

Host B is the recipient and owns the private key. On host B:

```bash
export VELOCE_ROOT="$HOME/veloce/veloce-1.0.0-linux-x86_64"
export VELOCE_PYTHON="$HOME/.venvs/veloce-1.0.0/bin/python"
"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    kem-init \
    --public-out /tmp/lr-bob-public.json \
    --private-state /tmp/lr-bob-private.json
```

The private-state document contains an agent capability handle. It remains on
host B with mode `0600`. Do not restart host B's agent until `kem-finish`
completes.

Move only the public document to host A through the workstation:

```bash
scp lr93:/tmp/lr-bob-public.json /tmp/lr-bob-public.json
scp /tmp/lr-bob-public.json lr168:/tmp/lr-bob-public.json
```

On host A:

```bash
export VELOCE_ROOT="$HOME/veloce/veloce-1.0.0-linux-x86_64"
export VELOCE_PYTHON="$HOME/.venvs/veloce-1.0.0/bin/python"
"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    kem-encapsulate \
    --public-input /tmp/lr-bob-public.json \
    --response-out /tmp/lr-kem-response.json
```

Move the encapsulation response to host B:

```bash
scp lr168:/tmp/lr-kem-response.json /tmp/lr-kem-response.json
scp /tmp/lr-kem-response.json lr93:/tmp/lr-kem-response.json
```

On host B:

```bash
export VELOCE_ROOT="$HOME/veloce/veloce-1.0.0-linux-x86_64"
export VELOCE_PYTHON="$HOME/.venvs/veloce-1.0.0/bin/python"
"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    kem-finish \
    --private-state /tmp/lr-bob-private.json \
    --response-input /tmp/lr-kem-response.json
```

Expected result: `shared secrets match: True`. The script compares SHA-256
fingerprints; it never transfers or prints the shared secret. `kem-finish`
releases the recipient's agent-held private key after the test.

ML-KEM does not encrypt an application message. A production protocol still
needs an approved KDF, authenticated encryption, transcript binding, replay
protection, peer authentication, and persistent key lifecycle. Prefer a
reviewed hybrid-TLS integration rather than inventing that protocol.

## 8. Collect evidence and stop the manual agents

On each host:

```bash
export VELOCE_ROOT="$HOME/veloce/veloce-1.0.0-linux-x86_64"
cd "$HOME/veloce-delivery"
sed -n '/  veloce-1\.0\.0-linux-x86_64\.tar\.gz$/p' SHA256SUMS \
    | sha256sum -c -

"$VELOCE_ROOT/bin/veloce" --json validation
"$VELOCE_ROOT/bin/veloce" --json cbom cyclonedx \
    >"$HOME/veloce-agent-cbom.json"
cat "$VELOCE_ROOT/lib/wolfcrypt-fips.build-record.json"
cat "$VELOCE_ROOT/lib/veloce-pqc.build-record.json"
tail -n 100 "$HOME/.veloce/agent.log"

agent_pid="$(cat "$HOME/.veloce/agent.pid")"
if kill -0 "$agent_pid" 2>/dev/null; then
    kill "$agent_pid"
fi
```

On host B, remove the obsolete private capability-handle document only after
`kem-finish` has released the agent-held key:

```bash
rm -f /tmp/lr-bob-private.json
```

For a later Veloce release, stop the old agent before starting the newly
extracted version. Do not overwrite libraries in a directory used by a
running agent; extract each release into its own versioned directory.
