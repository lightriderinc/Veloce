# Veloce quickstart

## Build and test everything (Linux x86-64)

```
bash scripts/run_gates.sh
```

The script builds the wolfCrypt FIPS module from the licensed bundle
(vendor/wolfssl), builds the PQC provider, the agent, qSearch and the CLI,
generates ~/.veloce/agent.json, and runs the release-gate battery (spec 9).
Expected result: `ALL GATES GREEN`.

## Run the agent and use Veloce

```
python3 scripts/gen_config.py
build/bin/veloce-agent --config ~/.veloce/agent.json &
```

Python SDK (pure Python, no crypto in-process):

```python
import sys; sys.path.insert(0, "python")   # or: pip install build/dist/*.whl
import veloce

veloce.initialize()
kp = veloce.mlkem_generate_keypair()               # ML-KEM-768
ct, ss = veloce.mlkem_encapsulate(kp.public_key)
assert veloce.mlkem_decapsulate(kp.private_key_handle, ct) == ss

sk = veloce.mldsa_generate_keypair()               # ML-DSA-65
sig = veloce.mldsa_sign(sk.private_key_handle, b"msg")
assert veloce.mldsa_verify(sk.public_key, b"msg", sig)

veloce.export_cbom(format="cyclonedx", path="cbom.cdx.json")
```

CLI:

```
build/bin/veloce status
build/bin/veloce validation
build/bin/veloce self-test
build/bin/veloce cbom cyclonedx
build/bin/veloce scan /path/to/codebase
```

qSearch directly:

```
build/bin/qsearch scan /path/to/codebase --out qsearch-out
build/bin/qsearch system --out host-inventory
```

`scan` walks a source tree (patterns + PEM certificates). `system`
inventories the crypto modules present on the host: installed crypto
libraries from the dynamic-linker cache and library directories (SHA-256
fingerprinted), kernel crypto API algorithms (/proc/crypto) and FIPS mode,
SSH host keys and sshd algorithm policy, the OS certificate store, TLS
policy files, and running processes with crypto libraries mapped. Run as
root for full process and config coverage; unreadable entries are reported
as explicit blind spots, never guessed.

Console output is the client-facing summary (finding counts, top
quantum-vulnerable algorithms, next commands); runtime detail is written to
`<out>/qsearch-run.log`. Report files for both modes: findings.json
(canonical, pretty-printed), findings.csv, cbom.cdx.json (CycloneDX 1.6),
m2302-inventory.json, executive-summary.txt, and the workbook exports
workbook-discovery-findings.csv and workbook-scanning-log.csv, whose
columns match Light_Rider_CBOM_Template_Updated.xlsx ("Discovery Findings"
and "Scanning Log" sheets) for direct paste-in.

## Using wolfSSL directly (C, without the agent)

The agent is the supported path (key custody, fail-closed entropy, CBOM).
For native C integration or bring-up work, link the same libraries the
agent loads.

FIPS module (classical algorithms + DRBG, cert #4718):

```c
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/fips_test.h>

int main(void) {
    /* Required wiring (spec 5.1): install the Lightrider seed callback
     * before instantiating the DRBG. The module is built with
     * WC_RNG_SEED_CB and makes no entropy claim of its own; the callback
     * reads OS kernel entropy and verifies every block (RCT/APT) before
     * returning it. The agent installs lightriderSeedCb; wc_GenerateSeed
     * is shown here only to keep the sample self-contained. */
    wc_SetSeed_Cb(wc_GenerateSeed);
    if (wolfCrypt_GetStatus_fips() != 0) return 1;  /* approved state */
    WC_RNG rng;
    if (wc_InitRng(&rng) != 0) return 1;            /* fail-closed */
    unsigned char buf[32];
    wc_RNG_GenerateBlock(&rng, buf, sizeof buf);
    wc_FreeRng(&rng);
    return 0;
}
```

Compile against the FIPS build tree and library:

```
gcc app.c -I build/fips-src \
    build/fips-src/src/.libs/libwolfssl.so \
    -Wl,-rpath,$PWD/build/fips-src/src/.libs -o app
```

PQC provider (ML-KEM-768, ML-DSA-65, outside the FIPS boundary):

```c
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
/* Build with -DWOLFSSL_USER_SETTINGS -Iscripts/pqc
 * -Ibuild/pqc-src/wolfssl-5.9.2-stable and link
 * build/lib/pqc/libveloce-pqc.so.
 * See scripts/pqc/selftest.c for a complete keygen / encapsulate /
 * decapsulate / sign / verify example. */
```

Rules when bypassing the agent (spec 8): keep the recorded SHA-256 check
before loading the libraries, source all PQC randomness from the FIPS DRBG
(the *WithRandom / *WithSeed APIs), and never ship wolfSSL source or
headers to third parties (object code only under the commercial agreement).

## Rebuild from scratch

```
FORCE_REBUILD=1 bash scripts/run_gates.sh
```

Appendix A recipes are automated in scripts/build_fips.sh (configure,
double-make with fips-hash.sh, testwolfcrypt gate) and scripts/build_pqc.sh
(standalone ML-KEM / ML-DSA / SHA-3 provider with self-test gate).
