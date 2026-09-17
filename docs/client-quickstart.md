# Veloce Linux client quickstart

This archive is ready to run after extraction. It already contains the
Veloce binaries, the wolfCrypt FIPS module as licensed object code, and the
PQC provider. A Git clone, compiler, and wolfSSL source bundle are not
required on the client host.

## Start and verify Veloce

From the extracted archive directory:

```bash
bin/veloce-fire-up
```

The launcher writes private runtime state to `~/.veloce`, starts the local
agent, and runs both status and self-test checks. A successful start ends
with `veloce-fire-up: running as PID ...`.

The launcher can be run again safely. It reuses the running agent recorded
in `~/.veloce/agent.pid` and repeats the checks.

The agent seeds its FIPS DRBG from the processor's RDSEED instruction and
fails closed when the CPU or virtual machine does not expose it
(`veloce status` then reports the entropy source as unavailable). On such
hosts, `VELOCE_ENTROPY_SOURCE=os-drbg bin/veloce-fire-up` selects operating
system DRBG output instead; the agent reports that source as an unvalidated
SP 800-90C chain with no security-strength claim.

Useful commands:

```bash
bin/veloce --json status
bin/veloce --json self-test
bin/veloce validation
bin/veloce cbom cyclonedx
bin/veloce scan /path/to/codebase
```

Runtime files:

- `~/.veloce/agent.json`: generated configuration with absolute paths into
  this extracted archive
- `~/.veloce/agent.sock`: local SDK/CLI socket
- `~/.veloce/agent.pid`: agent process ID
- `~/.veloce/agent.log`: startup and runtime log

To stop the user-launched agent:

```bash
kill "$(cat "$HOME/.veloce/agent.pid")"
```

## Optional cloud entropy (Lightrider EMS)

Cloud entropy is off by default and the agent opens no network connection.
To turn it on:

```bash
bin/veloce ems on
bin/veloce mixin on
bin/veloce entropy      # cloud-entropy-mixin: packets_mixed, last_mixin, last_error
```

The agent fetches a signed 64-byte packet every 60 seconds from
`https://ems.lightriderinc.com`, verifies the receipt against the pinned
service key, and mixes it into the FIPS generator as extra input. The
hardware source remains the only credited entropy, so the FIPS position is
unchanged; if the cloud is unreachable the agent keeps running locally. The
Free tier needs no key. For the higher-quality pools, add `"api_key"` and
set `"policy"` to `highest_quality` or `quantum_verified` in the `ems`
block of `~/.veloce/agent.json`, then restart the agent.

## Optional Python SDK

The Python API is optional. Install the wheel shipped in this archive, then
run the demonstration:

```bash
python3 -m pip install ./veloce_pqc-*.whl
python3 examples/python-demo.py
```

The SDK contains no cryptography in-process; it talks to the local Veloce
agent over the Unix socket. The wheel is pure Python and is therefore
inspectable. Release owners can produce an SDK-free runtime archive without
the wheel and Python example when the client does not need this API:

```bash
VELOCE_INCLUDE_PYTHON_SDK=0 bash scripts/make_release.sh
```

The SDK-free archive retains the small readable `bin/veloce-fire-up`
bootstrap script. It contains configuration/startup glue, not cryptographic
or Veloce implementation source.

## Runtime boundary

The client archive contains the versioned `libwolfssl.so` FIPS object,
`libveloce-pqc.so`, their build records, and the Veloce executables. It does
not contain the licensed wolfSSL source tree, Veloce native implementation
source, Git history, build trees, or internal plans.

Standard Linux runtime components such as glibc, libstdc++, and libgcc must
be available. Python 3 is required by `bin/veloce-fire-up` and by the
optional SDK.
