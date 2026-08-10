# Publishing a Veloce release on Zenodo

Zenodo (zenodo.org, operated by CERN) hosts versioned, DOI-referenced
artifacts free of charge, with no bandwidth cost to Lightrider, and permits
custom (non-open-source) licenses. This guide produces a public record from
which any platform (Windows, Linux) can download Veloce.

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
- Internal requirement documents (*.docx, guidance PDFs) and the CBOM
  workbook template unless product management clears them.
- ~/.veloce state, diagnostic bundles, or anything containing keys.

scripts/make_release.sh enforces the object-code rule for the binary
archive; the repository .gitignore enforces it for the source archive.

## Step 0: prepare the artifacts

```
bash scripts/run_gates.sh          # must end ALL GATES GREEN
bash scripts/make_release.sh       # build/dist/veloce-1.0.0-linux-x86_64.tar.gz
                                   # build/dist/veloce_pqc-1.0.0-py3-none-any.whl
                                   # build/dist/SHA256SUMS
git archive --format=tar.gz -o build/dist/veloce-1.0.0-source.tar.gz HEAD
```

`git archive` respects the repository contents only; verify the tree was
committed with .gitignore in place and run a final check:

```
tar -tzf build/dist/veloce-1.0.0-source.tar.gz | grep -iE "wolfssl-5.9.2-commercial|vendor/|\\.docx" && echo LEAK || echo CLEAN
```

Windows artifacts (MSI, once the S0 vendor items close) are added to the
same deposit as additional files; one deposit carries all platforms.

## Step 1: account and community

1. Create an account at https://zenodo.org (email, GitHub, or ORCID).
2. Optional: create a "Lightrider Inc" community
   (Communities, New community) so all Veloce releases are grouped and
   searchable under one page.

## Step 2: create the deposit

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
7. License: choose "Other (attached)" / custom license and reference the
   LICENSE file inside the archives. Do NOT select an OSI license (MIT,
   Apache) by accident: Zenodo's default is CC-BY for some resource types;
   the deposit must say Lightrider commercial license. If the picker
   requires a listed entry, select "Other (Not Open)" and name
   "Lightrider Inc Commercial License" in the description.
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

Publishing is permanent: a published record's files cannot be silently
replaced (that is the point of a DOI). Metadata can be edited afterward;
file changes require a new version.

## Step 4: new versions

For 1.0.1 and later: open the existing record, click "New version",
upload the new artifact set, update the version field, publish. The
concept DOI stays constant; each version gets its own DOI.

## Optional: GitHub integration (automated releases)

If the public source lives on GitHub (Lightrider-owned code only, with the
.gitignore rules in force):

1. On Zenodo: profile menu, GitHub, flip the toggle for the repository.
2. Create a GitHub Release (tag v1.0.0); Zenodo archives the release
   tarball and mints the DOI automatically.
3. Attach the binary artifacts (tar.gz, whl, MSI) to the same GitHub
   Release for platform downloads; Zenodo archives the source snapshot.
   Binaries attached to the GitHub release are NOT pulled in by Zenodo
   automatically; upload them to the Zenodo record manually (Step 2) if
   the DOI must cover binaries too.

## Platform download matrix (what users get)

| Platform | Artifact | Install |
|---|---|---|
| Linux x86-64 | veloce-1.0.0-linux-x86_64.tar.gz | untar, run bin/veloce-gen-config, start bin/veloce-agent, `pip install` the wheel |
| Windows 11 x86-64 | veloce-1.0.0-windows-x86_64.msi (pending vendor DLL-config items) | MSI installs VelocePqcAgent service + CLI; then `pip install veloce_pqc-*.whl` |
| Any (SDK only) | veloce_pqc-1.0.0-py3-none-any.whl | `pip install`; requires a reachable agent |

Verification instructions to include in the description:

```
sha256sum -c SHA256SUMS
```

## Checklist before pressing Publish

- [ ] ALL GATES GREEN on the release commit
- [ ] tar -tzf of every archive shows no wolfSSL source, no vendor/,
      no internal documents
- [ ] LICENSE and THIRD_PARTY_NOTICES.md present in every archive
- [ ] "Built with wolfCrypt (FIPS 140-3 cert #4718)" statement in the
      description (spec 8.1 attribution)
- [ ] License field set to the custom Lightrider license, not an OSI one
- [ ] Legal sign-off on the LICENSE text and on the same-release
      public-tree PQC provider sources (vendor item, docs/STATUS.md)
