# Publishing a Veloce release on Zenodo

Zenodo (zenodo.org, operated by CERN) hosts versioned, DOI-referenced
artifacts. This repository is prepared for Zenodo's native GitHub release
integration through the root `.zenodo.json` file. A published Zenodo record
is public and persistent even if the GitHub repository is private.

The current Veloce release is publicly downloadable and free to use under
the included Lightrider Inc license; no client subscription is required for
this archived version. Future managed services, enterprise features,
support, updates, or client releases may require a paid subscription.
"Open access" describes public file access only: it does not make Veloce OSI
open source or override `LICENSE`.

## Choose one publication path

Use the native GitHub integration for a source release and automatic DOI.
Use a manual Zenodo deposit when the DOI must cover binary release assets as
well as source. Do not use both paths for the same version, or duplicate DOI
records may be created.

## What may be published (hard rules, spec 8.1)

Permitted in the public archive:

- Lightrider-owned sources: qsearch/, cli/, python/, agent/, ipc/, tests/,
  scripts/ (except any file from the wolfSSL tree), docs/, examples/,
  installer/, assets/.
- Compiled artifacts: veloce-agent, veloce, qsearch binaries; the Python
  wheel; libwolfssl.so.* and libveloce-pqc.so as object code with the
  build-record hash files.
- LICENSE (Lightrider commercial) and THIRD_PARTY_NOTICES.md.

Never published, under any circumstances:

- The wolfSSL commercial FIPS bundle
  (wolfssl-5.9.2-commercial-fips-linuxv5.2.1/, vendor/, any *.c, *.h,
  configure, or archive from it). The agreement's confidentiality clause
  (spec 8.1, section 5) covers the source; only object code ships.
- build/fips-src, build/pqc-src (copies of wolfSSL trees).
- Internal requirement documents (`*.docx`, `plan/`, guidance PDFs) and the
  CBOM workbook template unless product management clears them.
- Generated scan evidence (`results/`, `host-results/`, `host-inventory/`,
  `qsearch-out/`, `certs-out/`, and root CBOM output files). These may expose
  host paths, installed cryptography, and confidential source-tree names.
- ~/.veloce state, diagnostic bundles, or anything containing keys.

`scripts/make_release.sh` enforces the object-code rule for the binary
archive. `.gitignore` prevents confidential untracked inputs from being
committed, while `.gitattributes` applies `export-ignore` to tracked internal
plans and generated findings when `git archive` or GitHub builds a source
archive.

The Linux binary archive is the client delivery: it contains the Veloce
executables, the versioned wolfCrypt FIPS shared object, the PQC shared
object, their build records, and a one-command launcher. It contains no
wolfSSL source and no Veloce native implementation source. The optional
pure-Python SDK wheel and Python example are inspectable; omit both from a
SDK-free runtime delivery if the Python API is not required by
building with `VELOCE_INCLUDE_PYTHON_SDK=0`.

## Step 0: publication approval and preflight

Before creating a public record:

1. Confirm `LICENSE` carries a current legal approval. Lightrider legal
   approved LICENSE v1.0 on 2026-08-05; the file records that date. Any edit
   to the text voids the approval and requires a new sign-off before release.
   Two supporting records are held outside this repository and must be on
   file before publication: wolfSSL's written consent to public open-access
   redistribution of the wolfCrypt and PQC provider object code under
   Agreement v.01-24, and the export classification and any BIS notification
   for the distributed cryptographic object code.
2. Confirm that the GitHub source snapshot itself may be public. A private
   GitHub repository does not make an open-access Zenodo record private.
3. Confirm that `.zenodo.json` describes the commercial terms correctly.
   Update its description if the availability or subscription policy changes.
4. Run the gates and archive leak check below.

Prepare the artifacts:

```
bash scripts/run_gates.sh          # must end ALL GATES GREEN
bash scripts/make_release.sh       # build/dist/veloce-1.0.0-linux-x86_64.tar.gz
                                   # build/dist/veloce_pqc-1.0.0-py3-none-any.whl
                                   # build/dist/SHA256SUMS
git archive --format=tar.gz -o build/dist/veloce-1.0.0-source.tar.gz HEAD
```

`git archive` applies `export-ignore` rules from the committed
`.gitattributes`. Verify the release tree is committed and run a final check:

```
tar -tzf build/dist/veloce-1.0.0-source.tar.gz \
  | grep -iE '(^|/)(vendor|plan|results|host-results|host-inventory|qsearch-out|certs-out)/|wolfssl-5.9.2-commercial|\\.docx$|(^|/)(agent-cbom.json|veloce-cbom.cdx.json)$' \
  && echo LEAK || echo CLEAN
```

Windows artifacts (MSI, once the S0 vendor items close) are added to the
same deposit as additional files; one deposit carries all platforms.

## Step 1: connect GitHub to Zenodo (one-time owner action)

1. Create or sign in to an account at https://zenodo.org.
2. In the Zenodo profile menu, open **Linked accounts** and connect the
   GitHub account that can access `lightriderinc/Veloce`.
3. In the Zenodo profile menu, open **GitHub**, select **Sync now**, find
   `lightriderinc/Veloce`, and enable its toggle.
4. Optional: create a "Lightrider Inc" community
   (Communities, New community) so all Veloce releases are grouped and
   searchable under one page.

This account authorization cannot be completed from the repository. The
native integration does not require a Zenodo API token or GitHub Actions
secret.

## Step 2A: publish through the GitHub integration (recommended for source)

1. Ensure `.zenodo.json`, `LICENSE`, and `THIRD_PARTY_NOTICES.md` are
   committed before tagging. Keep `.gitattributes` intact so internal plans
   and generated host findings are excluded from the source archive.
2. Create the version tag from the approved commit, for example `v1.0.0`.
3. Create a non-draft GitHub Release for that tag. Draft releases do not
   trigger the final archive; prereleases should be used only when they are
   intended to receive a permanent DOI.
4. Wait for Zenodo to ingest the release, then open **Zenodo > GitHub >
   Veloce** and follow the record DOI.
5. Verify the Zenodo record's title, version, creators, license, description,
   files, and external archival status before announcing it.

Treat native GitHub ingestion as a source snapshot. GitHub Release assets
such as the Linux archive, wheel, or MSI are separate from the repository
snapshot; verify the generated Zenodo file list rather than assuming those
assets are covered by the DOI. If the DOI must cover them, use Step 2B.

## Step 2B: create a manual deposit (source plus binaries)

1. Click Upload (https://zenodo.org/uploads/new).
2. Upload the files from build/dist/:
   - veloce-1.0.0-linux-x86_64.tar.gz (Linux binaries + libraries)
   - veloce_pqc-1.0.0-py3-none-any.whl (Python SDK, all platforms)
   - veloce-1.0.0-source.tar.gz (Lightrider-owned source)
   - SHA256SUMS
   - Later: veloce-1.0.0-windows-x86_64.msi
3. Resource type: Software.
4. Title: "Veloce PQC SDK 1.0.0 (Lightrider Inc)".
5. Creators: Lightrider Inc; add individual authors with ORCID iDs if
   desired (Guo, Martin; role: author).
6. Description (rendered as the landing page): paste the summary from
   README.md plus platform install notes and the statement
   "Built with wolfCrypt (FIPS 140-3 certificate #4718); wolfSSL
   distributed as object code only under commercial license."
7. License: select **Other Open** for the publicly downloadable custom-
   licensed files and reference `LICENSE` in the description. Do NOT select
   an OSI license (MIT, Apache) or a Creative Commons software license by
   accident. If Zenodo's current form offers a more precise custom-license
   choice, use it and keep the description explicit that access is free for
   this release but use remains governed by the attached Lightrider license.
8. Access right: Open Access (files downloadable by everyone) with the
   custom license governing use. (Open access here describes download
   availability, not an open-source grant.)
9. Keywords: post-quantum cryptography, ML-KEM, ML-DSA, FIPS 140-3, CBOM,
   CycloneDX, wolfSSL, quantum-vulnerable discovery.
10. Related identifiers (optional): the GitHub repository URL
    (relation: "is supplement to"), the CMVP certificate page URL.

## Step 3: publish and record the DOI

1. Press Publish. Zenodo mints two DOIs:
   - a version DOI for 1.0.0 (cite this exact release), and
   - a concept DOI that always resolves to the latest version.
2. Record both DOIs in README.md and the release notes, and add the DOI
   badge (Zenodo shows the Markdown snippet on the record page).

Treat publication as permanent: a published record's files cannot be
silently replaced (that is the point of a DOI). Metadata can be edited
afterward; file changes require a new version.

## Step 4: new versions

For 1.0.1 and later: open the existing record, click "New version",
upload the new artifact set, update the version field, publish. The
concept DOI stays constant; each version gets its own DOI.

## Platform download matrix (what users get)

| Platform | Artifact | Install |
|---|---|---|
| Linux x86-64 | veloce-1.0.0-linux-x86_64.tar.gz | untar, enter its directory, run `bin/veloce-fire-up`; optionally `pip install` the included wheel |
| Windows 11 x86-64 | veloce-1.0.0-windows-x86_64.msi (pending vendor DLL-config items) | MSI installs VelocePqcAgent service + CLI; then `pip install veloce_pqc-*.whl` |
| Any (SDK only) | veloce_pqc-1.0.0-py3-none-any.whl | `pip install`; requires a reachable agent |

Verification instructions to include in the description:

```
sha256sum -c SHA256SUMS
```

## Checklist before pressing Publish

- [ ] ALL GATES GREEN on the release commit
- [ ] `.zenodo.json` is valid JSON and committed before the version tag
- [ ] GitHub-to-Zenodo repository toggle is enabled by the owning account
- [x] Legal has approved the current `LICENSE` (v1.0, 2026-08-05; re-approve
      if the text changes)
- [ ] Public/free-current and future-subscription wording is still accurate
- [ ] tar -tzf of every archive shows no wolfSSL source, no vendor/,
      no internal plans, and no generated host scan evidence
- [ ] LICENSE and THIRD_PARTY_NOTICES.md present in every archive
- [ ] "Built with wolfCrypt (FIPS 140-3 cert #4718)" statement in the
      description (spec 8.1 attribution)
- [ ] License field is Other Open/custom and the description points to the
      Lightrider license rather than implying an OSI license
- [x] Legal sign-off on the LICENSE text and on the same-release
      public-tree PQC provider sources (vendor item, docs/STATUS.md),
      2026-08-05
- [ ] wolfSSL written consent to public open-access redistribution of the
      object code under Agreement v.01-24 is on file
- [ ] Export classification and any required BIS notification for the
      distributed cryptographic object code are on file
