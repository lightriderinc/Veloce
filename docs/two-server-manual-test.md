# Veloce two-server manual test

This procedure tests the current Linux Veloce agent on two Hostinger hosts.
It uses GitHub to synchronize the tracked Veloce code and SSH/SCP to move only
the public exchange artifacts between the hosts.

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

## 2. Give each server read-only GitHub access

The Veloce repository must remain private. On each server, create a unique
read-only deploy key:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/veloce_github -C "veloce-hostinger-readonly"
cat ~/.ssh/veloce_github.pub
```

In GitHub, open the private `lightriderinc/Veloce` repository, then
**Settings > Deploy keys > Add deploy key**. Add each server's public key as a
separate key and leave **Allow write access** disabled.

On each server, add this host entry to `~/.ssh/config`:

```text
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/veloce_github
    IdentitiesOnly yes
```

Then verify:

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/config ~/.ssh/veloce_github
ssh -T git@github.com
```

Do not put GitHub tokens, private SSH keys, the licensed wolfSSL bundle, or
generated private-state files in the repository.

## 3. Install prerequisites and clone the same revision

Run on both hosts:

```bash
df -h /
sudo apt-get update
sudo apt-get install -y git build-essential autoconf automake libtool \
    libtool-bin pkg-config rsync curl lsof python3 python3-pip cargo
mkdir -p ~/src
cd ~/src
git clone git@github.com:lightriderinc/Veloce.git
cd Veloce
git switch main
git pull --ff-only
git rev-parse HEAD
```

The two `git rev-parse HEAD` values must be identical. For later updates, use
`git status --short`, then `git pull --ff-only`; do not discard local changes.

Each host should have at least 5 GiB free before building. If `df -h /` shows
no available space, stop here. A full filesystem can prevent Git from updating
its index, prevent the build from copying the FIPS source, and prevent the
agent from creating its log or socket. Diagnose the space discrepancy before
deleting anything:

```bash
sudo lsof +L1
sudo du -xhd1 / 2>/dev/null | sort -h
```

Deleted-but-open files must be released by restarting or stopping their owning
process; deleting unrelated repository files will not recover that space.

## 4. Provision the licensed wolfSSL bundle separately

The commercial wolfSSL source is intentionally ignored by Git. Securely copy
the authorized bundle from the Lightrider-controlled source to each host over
SSH or an approved private artifact channel. Never upload it to GitHub.

Keep the original authorized archive long enough to record its SHA-256, then
unpack it. On each host, set `veloce_bundle` to the actual extracted directory.
The first example is the normal layout; the commented example shows a bundle
already provisioned elsewhere on the same host:

```bash
(
set -euo pipefail
cd ~/src/Veloce
veloce_bundle="$PWD/wolfssl-5.9.2-commercial-fips-linuxv5.2.1"
# veloce_bundle="/home/HOSTINGER_USER/Veloce/wolfssl-5.9.2-commercial-fips-linuxv5.2.1"

test -x "$veloce_bundle/configure"
test -f "$veloce_bundle/IDE/WIN10/wolfssl-fips.sln"
mkdir -p vendor
test ! -e vendor/wolfssl
test ! -L vendor/wolfssl
ln -s "$veloce_bundle" vendor/wolfssl
test -x vendor/wolfssl/configure
test -f vendor/wolfssl/IDE/WIN10/wolfssl-fips.sln
)
```

If either absence check fails, inspect the existing path with
`ls -l vendor/wolfssl`; do not overwrite it until its target is confirmed.
Record and compare the original source-archive SHA-256 on both hosts before
building. `vendor/` is Git-ignored and must remain untracked.

## 5. Build, test, and start one local agent per host

First, run the release gates on both hosts:

```bash
cd ~/src/Veloce
df -h /
test -x vendor/wolfssl/configure
bash scripts/run_gates.sh
```

Stop on that host unless the final line is exactly `ALL GATES GREEN`. Do not
run the configuration, agent, status, or self-test commands after a failed
gate: the required libraries and binaries may not exist.

After the gates pass, run this startup block on both hosts. The subshell exits
on the first error, creates the private state directory before redirecting the
log, records the correct PID, and confirms that the process survived startup:

```bash
(
set -euo pipefail
cd ~/src/Veloce
umask 077

install -d -m 700 "$HOME/.veloce"
test -x build/bin/veloce-agent
test -x build/bin/veloce
python3 scripts/gen_config.py

if [ -s "$HOME/.veloce/agent.pid" ] \
        && kill -0 "$(cat "$HOME/.veloce/agent.pid")" 2>/dev/null; then
    echo "Veloce agent is already running" >&2
    exit 1
fi

nohup build/bin/veloce-agent \
    --config "$HOME/.veloce/agent.json" --quiet \
    >"$HOME/.veloce/agent.log" 2>&1 &
agent_pid=$!
printf '%s\n' "$agent_pid" >"$HOME/.veloce/agent.pid"
sleep 2

if ! kill -0 "$agent_pid" 2>/dev/null; then
    echo "Veloce agent exited during startup" >&2
    tail -n 100 "$HOME/.veloce/agent.log" >&2
    exit 1
fi

build/bin/veloce --json status
build/bin/veloce --json self-test
)
```

Do not open a firewall port for Veloce. The agent communicates through
`~/.veloce/agent.sock` on its own host. Keep the shell setting below for the
remaining commands:

```bash
cd ~/src/Veloce
export PYTHONPATH="$PWD/python"
```

### Setup failure guide

- `licensed bundle not found at vendor/wolfssl`: the bundle is absent, the
  symlink is missing/broken, or its target lacks an executable `configure`.
- `FIPS library not staged`: gate G0 did not complete; fix its first error and
  rerun the gates instead of rerunning `gen_config.py` alone.
- `~/.veloce/agent.log: No such file or directory`: the earlier configuration
  step failed before creating `~/.veloce`; do not attempt agent startup.
- `build/bin/veloce: No such file or directory`: the build stopped before the
  Rust CLI was staged, or `cargo` was unavailable.
- `No space left on device`: stop all build/start commands and recover disk
  space first; partial build artifacts are not evidence of a passed gate.

## 6. Test an ML-DSA signature

On host A (`lr168`):

```bash
cd ~/src/Veloce
export PYTHONPATH="$PWD/python"
printf '%s\n' 'Lightrider two-server signature test' >/tmp/lr-message.txt
python3 examples/two-server/two_party_demo.py sign-create \
    --message-file /tmp/lr-message.txt \
    --out /tmp/lr-signed.json
```

Use the workstation as the transfer point:

```bash
scp lr168:/tmp/lr-signed.json /tmp/lr-signed.json
scp /tmp/lr-signed.json lr93:/tmp/lr-signed.json
```

On host B (`lr93`):

```bash
cd ~/src/Veloce
export PYTHONPATH="$PWD/python"
python3 examples/two-server/two_party_demo.py verify \
    --input /tmp/lr-signed.json
```

Expected result: `signature valid: True`. For a negative test, edit the
base64-encoded message or signature in a copy of the JSON file and confirm
that verification fails.

This proves signature interoperability. Production identity still requires a
trusted binding between host A and its ML-DSA public key.

## 7. Test ML-KEM shared-secret establishment

Host B is the recipient and owns the private key. On host B:

```bash
cd ~/src/Veloce
export PYTHONPATH="$PWD/python"
python3 examples/two-server/two_party_demo.py kem-init \
    --public-out /tmp/lr-bob-public.json \
    --private-state /tmp/lr-bob-private.json
```

The private-state file contains an agent capability handle. It must remain on
host B, mode `0600`. Do not restart host B's agent until `kem-finish` completes.

Move only the public file to host A through the workstation:

```bash
scp lr93:/tmp/lr-bob-public.json /tmp/lr-bob-public.json
scp /tmp/lr-bob-public.json lr168:/tmp/lr-bob-public.json
```

On host A:

```bash
cd ~/src/Veloce
export PYTHONPATH="$PWD/python"
python3 examples/two-server/two_party_demo.py kem-encapsulate \
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
cd ~/src/Veloce
export PYTHONPATH="$PWD/python"
python3 examples/two-server/two_party_demo.py kem-finish \
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
cd ~/src/Veloce
git rev-parse HEAD
build/bin/veloce --json validation
build/bin/veloce --json cbom cyclonedx >~/veloce-agent-cbom.json
tail -n 100 "$HOME/.veloce/agent.log"

agent_pid="$(cat "$HOME/.veloce/agent.pid")"
if kill -0 "$agent_pid" 2>/dev/null; then
    kill "$agent_pid"
fi
```

On host B, remove the now-obsolete private capability-handle file after
`kem-finish` has released the agent-held key:

```bash
rm -f /tmp/lr-bob-private.json
```

Record the commit hash, OS version, CPU model, gate output, validation output,
and the two test results. Do not collect private handles, shared secrets,
licensed sources, tokens, or private SSH keys as evidence.
