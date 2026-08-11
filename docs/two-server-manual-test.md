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

## 3. Install prerequisites and clone Veloce

Run on both hosts:

```bash
df -h /
sudo apt-get update
sudo apt-get install -y git build-essential autoconf automake libtool \
    libtool-bin pkg-config rsync curl lsof python3 python3-pip cargo
mkdir -p ~/src
cd ~/src
git clone git@github.com:lightriderinc/Veloce.git
cd "$HOME/src/Veloce"
git switch main
git pull --ff-only
pwd
git rev-parse HEAD
```

`pwd` must print the current user's home path followed by `/src/Veloce`.
Never continue after a failed `cd`: subsequent relative `build/bin/...`
commands would run from the wrong directory.

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

**A Git clone alone cannot run Veloce.** The clone intentionally contains
neither the licensed wolfSSL source nor prebuilt files under `build/`. Each
server needs its own authorized bundle before `scripts/run_gates.sh` can build
the FIPS library, PQC provider, agent, and CLI.

Keep the original authorized archive long enough to record its SHA-256, then
unpack the directory at this standard private location on each server:

```text
~/veloce-private/wolfssl-5.9.2-commercial-fips-linuxv5.2.1
```

Then run from the clone:

```bash
cd "$HOME/src/Veloce"
bash scripts/setup_bundle.sh
```

If the authorized bundle is already unpacked elsewhere, pass its directory:

```bash
bash scripts/setup_bundle.sh /absolute/path/wolfssl-5.9.2-commercial-fips-linuxv5.2.1
```

The script also searches the current user's home directory, safely repairs a
broken `vendor/wolfssl` symlink, and succeeds with `setup_bundle: ready (...)`.
If the licensed directory is absent, it prints the exact standard location and
stops without changing the SSH login shell.

Record and compare the original source-archive SHA-256 on both hosts before
building. `vendor/` is Git-ignored and must remain untracked.

## 5. Build and fire up Veloce on each server

After `setup_bundle: ready`, fire up Veloce with one command on each server:

```bash
cd "$HOME/src/Veloce"
bash scripts/fire_up.sh
```

`fire_up.sh` checks free space and the bundle, runs every release gate,
regenerates `~/.veloce/agent.json` for this exact clone, removes only stale
PID/socket files, starts the agent, and runs status plus self-test. It never
continues from a failed gate.

Expected results: status reports `"state":"ok"`, `"approved_mode":true`,
and healthy entropy; self-test reports passing CAST, entropy, and PQC tests.
The PID is stored in `~/.veloce/agent.pid` and diagnostic output in
`~/.veloce/agent.log`.

Do not open a firewall port for Veloce. The agent communicates through
`~/.veloce/agent.sock` on its own host. Keep the shell setting below for the
remaining commands:

```bash
cd ~/src/Veloce
export PYTHONPATH="$PWD/python"
```

### Setup failure guide

- `cd: .../src/Veloce: No such file or directory`: the clone is missing or is
  at a different path. Locate it and do not continue with relative commands.
- `licensed bundle not found at vendor/wolfssl`: the bundle is absent, the
  symlink is missing/broken, or its target lacks `configure`.
- `FIPS library not staged`: gate G0 did not complete; fix its first error and
  rerun the gates instead of rerunning `gen_config.py` alone.
- `~/.veloce/agent.log: No such file or directory`: the earlier configuration
  step failed before creating `~/.veloce`; do not attempt agent startup.
- `build/bin/veloce: No such file or directory`: the build stopped before the
  Rust CLI was staged, or `cargo` was unavailable.
- `cannot connect ... agent.sock` with `No such file or directory`: no agent
  created the socket; check the PID and `tail -n 100 ~/.veloce/agent.log`.
- `cannot connect ... agent.sock` with `Connection refused`: the socket is
  stale and its agent is dead; rerun the guarded startup block.
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
