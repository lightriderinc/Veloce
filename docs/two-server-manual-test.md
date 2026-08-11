# Veloce two-server release test

This procedure assumes you have exactly two Linux x86-64 servers and a Veloce
binary release. Upload the same release archive and `SHA256SUMS` file to both
servers, start Veloce locally on each server, and test ML-DSA and ML-KEM between
them.

Do not clone the Veloce repository on either server. A repository checkout or
a GitHub-generated source archive does not contain the licensed runtime
libraries. Use the versioned Linux binary release named like
`veloce-1.0.0-linux-x86_64.tar.gz`.

The release must include the Python SDK. An archive built with
`VELOCE_INCLUDE_PYTHON_SDK=0` cannot run this test.

| Role | Host | Address |
|---|---|---|
| A: signer / ML-KEM sender | `srv811871.hstgr.cloud` | `168.231.75.64` |
| B: verifier / ML-KEM recipient | `srv862034.hstgr.cloud` | `93.127.215.63` |

The Veloce agent remains local to each server. Do not expose its Unix socket or
open a network port for it. Only the JSON test files move between the servers.

## 1. Upload the release to both servers

On the computer holding the downloaded release, set the SSH user and the path
to the two release files:

```bash
export SERVER_USER="YOUR_SSH_USER"
export RELEASE_DIR="$HOME/Downloads/veloce-1.0.0"
export RELEASE_ARCHIVE="veloce-1.0.0-linux-x86_64.tar.gz"

ssh "$SERVER_USER@168.231.75.64" \
    'install -d -m 700 "$HOME/veloce-delivery"'
scp "$RELEASE_DIR/$RELEASE_ARCHIVE" "$RELEASE_DIR/SHA256SUMS" \
    "$SERVER_USER@168.231.75.64:veloce-delivery/"

ssh "$SERVER_USER@93.127.215.63" \
    'install -d -m 700 "$HOME/veloce-delivery"'
scp "$RELEASE_DIR/$RELEASE_ARCHIVE" "$RELEASE_DIR/SHA256SUMS" \
    "$SERVER_USER@93.127.215.63:veloce-delivery/"
```

If your hosting control panel provides file upload, upload both files to
`$HOME/veloce-delivery` on each server instead. Do not rename the archive
without also updating its entry in `SHA256SUMS`.

From this point onward, work in two SSH terminals: one connected to server A
and one connected to server B.

## 2. Install and start the release on each server

Run this complete block on server A and then on server B:

```bash
export VELOCE_VERSION="1.0.0"
export VELOCE_ARCHIVE="veloce-${VELOCE_VERSION}-linux-x86_64.tar.gz"
export VELOCE_DELIVERY="$HOME/veloce-delivery"
export VELOCE_ROOT="$HOME/veloce/veloce-${VELOCE_VERSION}-linux-x86_64"
export VELOCE_VENV="$HOME/.venvs/veloce-${VELOCE_VERSION}"

sudo apt-get update
sudo apt-get install -y ca-certificates python3 python3-venv

test -f "$VELOCE_DELIVERY/$VELOCE_ARCHIVE" || {
    echo "STOP: $VELOCE_ARCHIVE was not uploaded" >&2
    exit 1
}
test -f "$VELOCE_DELIVERY/SHA256SUMS" || {
    echo "STOP: SHA256SUMS was not uploaded" >&2
    exit 1
}

checksum_line="$(awk -v name="$VELOCE_ARCHIVE" \
    '$2 == name {print; exit}' "$VELOCE_DELIVERY/SHA256SUMS")"
test -n "$checksum_line" || {
    echo "STOP: SHA256SUMS has no entry for $VELOCE_ARCHIVE" >&2
    exit 1
}
printf '%s\n' "$checksum_line" \
    | (cd "$VELOCE_DELIVERY" && sha256sum -c -) || exit 1

install -d -m 700 "$HOME/veloce"
tar -xzf "$VELOCE_DELIVERY/$VELOCE_ARCHIVE" -C "$HOME/veloce"

test -x "$VELOCE_ROOT/bin/veloce-fire-up" || {
    echo "STOP: the uploaded file is not the complete Veloce binary release" >&2
    exit 1
}
test -f "$VELOCE_ROOT/examples/two-server/two_party_demo.py" || {
    echo "STOP: the release does not contain the two-server demo" >&2
    exit 1
}
compgen -G "$VELOCE_ROOT/veloce_pqc-*.whl" >/dev/null || {
    echo "STOP: the release does not contain the Python SDK wheel" >&2
    exit 1
}

python3 -m venv "$VELOCE_VENV"
"$VELOCE_VENV/bin/python" -m pip install --no-index --force-reinstall \
    "$VELOCE_ROOT"/veloce_pqc-*.whl

printf 'export VELOCE_ROOT=%q\nexport VELOCE_PYTHON=%q\n' \
    "$VELOCE_ROOT" "$VELOCE_VENV/bin/python" \
    >"$HOME/.veloce-test-env"
chmod 600 "$HOME/.veloce-test-env"

"$VELOCE_ROOT/bin/veloce-fire-up"
```

The checksum must report `OK`. Startup must report a healthy status and passing
self-tests, including `"state":"ok"`, `"approved_mode":true`, FIPS module
status `0`, healthy entropy, and passing PQC tests.

For a later SSH login, restore the two convenience variables with:

```bash
source "$HOME/.veloce-test-env"
```

## 3. How test files move between the servers

The cryptographic agent does not communicate over the network. The demo only
needs to move a few public JSON documents. Use the same local computer that
uploaded the release as the transfer point; the two servers do not need SSH
access to each other.

Keep a local terminal open and set the SSH user there:

```bash
export SERVER_USER="YOUR_SSH_USER"
```

Each transfer below uses two `scp` commands: download from one server to the
local computer, then upload to the other server.

## 4. Test an ML-DSA signature

On server A, create a signed document:

```bash
source "$HOME/.veloce-test-env"

printf '%s\n' 'Lightrider two-server signature test' \
    > /tmp/veloce-message.txt
"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    sign-create \
    --message-file /tmp/veloce-message.txt \
    --out /tmp/veloce-signed.json
```

On the local computer, move the signed document from server A to server B:

```bash
scp "$SERVER_USER@168.231.75.64:/tmp/veloce-signed.json" \
    /tmp/veloce-signed.json
scp /tmp/veloce-signed.json \
    "$SERVER_USER@93.127.215.63:/tmp/veloce-signed.json"
```

On server B, verify it:

```bash
source "$HOME/.veloce-test-env"
"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    verify --input /tmp/veloce-signed.json
```

Expected result:

```text
signature valid: True
```

This proves signature interoperability. Production identity still requires a
trusted binding between server A and its ML-DSA public key.

## 5. Test ML-KEM shared-secret establishment

Server B is the recipient and owns the private key. On server B, create its
public document and private agent handle:

```bash
source "$HOME/.veloce-test-env"

"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    kem-init \
    --public-out /tmp/veloce-b-public.json \
    --private-state /tmp/veloce-b-private.json
```

On the local computer, copy only the public document to server A:

```bash
scp "$SERVER_USER@93.127.215.63:/tmp/veloce-b-public.json" \
    /tmp/veloce-b-public.json
scp /tmp/veloce-b-public.json \
    "$SERVER_USER@168.231.75.64:/tmp/veloce-b-public.json"
```

Do not copy `/tmp/veloce-b-private.json` off server B. Do not restart server
B's Veloce agent until `kem-finish` completes because the private key is held
by that agent.

On server A, encapsulate a shared secret:

```bash
source "$HOME/.veloce-test-env"

"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    kem-encapsulate \
    --public-input /tmp/veloce-b-public.json \
    --response-out /tmp/veloce-kem-response.json
```

On the local computer, copy the response to server B:

```bash
scp "$SERVER_USER@168.231.75.64:/tmp/veloce-kem-response.json" \
    /tmp/veloce-kem-response.json
scp /tmp/veloce-kem-response.json \
    "$SERVER_USER@93.127.215.63:/tmp/veloce-kem-response.json"
```

On server B, finish the exchange:

```bash
source "$HOME/.veloce-test-env"
"$VELOCE_PYTHON" "$VELOCE_ROOT/examples/two-server/two_party_demo.py" \
    kem-finish \
    --private-state /tmp/veloce-b-private.json \
    --response-input /tmp/veloce-kem-response.json
```

Expected result:

```text
shared secrets match: True
```

The demo compares SHA-256 fingerprints; it never transfers or prints the
shared secret. ML-KEM alone does not encrypt application data. A production
protocol also needs an approved KDF, authenticated encryption, transcript
binding, replay protection, peer authentication, and key lifecycle controls.

## 6. Record results and stop the test agents

Run on both servers:

```bash
source "$HOME/.veloce-test-env"

"$VELOCE_ROOT/bin/veloce" --json validation
"$VELOCE_ROOT/bin/veloce" --json cbom cyclonedx \
    >"$HOME/veloce-agent-cbom.json"
tail -n 100 "$HOME/.veloce/agent.log"

if test -s "$HOME/.veloce/agent.pid"; then
    agent_pid="$(cat "$HOME/.veloce/agent.pid")"
    if kill -0 "$agent_pid" 2>/dev/null; then
        kill "$agent_pid"
    fi
fi
```

After `kem-finish` succeeds, remove the temporary private handle document on
server B:

```bash
rm -f /tmp/veloce-b-private.json
```

## Troubleshooting

- `No such file or directory` for the archive or `SHA256SUMS`: upload both
  release files to `$HOME/veloce-delivery` on that server.
- Checksum failure: do not continue. Upload the archive and checksum again
  from the same release.
- Missing `veloce_pqc-*.whl` or `two_party_demo.py`: you uploaded a source
  archive or an SDK-free runtime. Upload the full Linux binary release.
- `No module named veloce`: run the example with `$VELOCE_PYTHON`, not the
  system `python3`, or repeat the wheel installation.
- `cannot connect ... agent.sock`: inspect
  `tail -n 100 "$HOME/.veloce/agent.log"` and rerun
  `"$VELOCE_ROOT/bin/veloce-fire-up"`.
- `scp: Permission denied`: on the local computer, verify `SERVER_USER` and
  the SSH credentials used when uploading the release. This is an SSH transfer
  problem, not a Veloce agent problem.
- `shared secrets match: False`: repeat the ML-KEM test from `kem-init` and
  ensure the public document and response came from the current run.
