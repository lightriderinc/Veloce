# CBOM field mapping (Appendix B): SDK and qSearch to the workbook

Both the Veloce agent self-report (`veloce cbom` / `export_cbom()`) and
qSearch findings flow into the Light Rider CBOM workbook
(Light_Rider_CBOM_Template_Updated.xlsx).

| Veloce report field | CBOM inventory column |
|---|---|
| Crypto library / module + version (`fips_module_version`, `library`) | Crypto Library/Provider; Library Version; Cryptographic Module |
| FIPS certificate (`fips_certificate`) | FIPS 140-3 Certificate |
| Entropy provider + ESV certificate (`entropy_source`, ESV item) | Entropy Source; ESV Status/Certificate |
| Algorithm + parameter set (`algorithms`, e.g. ML-KEM-768) | Algorithm; Key/Parameter Size; Target PQC Algorithm |
| TLS version + hybrid group (`configure_hybrid_tls` result) | Protocol/Version; Cipher Suite |
| Approved-mode + self-test status (`approved_mode`, `self_tests`) | Notes / runtime validation record |
| OS edition, build, CPU arch (`operating_environment`) | Operating System (Supplier sheet); Environment |
| qSearch provenance + confidence (`provenance`, `confidence`) | Discovery Findings: Discovery Method, Finding Confidence, Validation Status, False Positive?, Blind Spot/Limitation |
| Scan runs (`files_scanned`, `generated_unix`) | Scanning Log sheet (tool/method, findings counts, false positives) |

SDK-only fields carried in the JSON/CSV exports: agent version, wolfCrypt
DLL/so name + SHA-256, EMS enabled/disabled, cloud-entropy mix-in state,
installation and last-verified timestamps.

Sources: `qsearch-out/findings.json` (canonical), `cbom.cdx.json`
(CycloneDX 1.6), `m2302-inventory.json`, and the agent export
(`export_cbom(format="records"|"cyclonedx")`). Merge the agent self-report
into a scan with `qsearch scan <root> --merge-agent-cbom <agent-export.json>`.

## Direct workbook exports

Every qSearch run additionally writes two CSV files whose headers match the
workbook sheets exactly, for direct paste-in:

- `workbook-discovery-findings.csv`: one row per finding, columns
  Finding ID through Assigned Owner of the "Discovery Findings" sheet.
  Populated by the tool: Discovery Date, Discovery Method (provenance),
  Tool / Capability, Coverage Domain, Asset / Endpoint, Observed Crypto
  Artifact, Algorithm / Protocol, Library / Package, Evidence Location,
  Finding Confidence, Validation Status ("Unvalidated (automated
  finding)"), Blind Spot / Limitation, Remediation Required. Left for the
  analyst: CBOM Record ID, Mission Thread ID, Authoritative Record
  Matched?, False Positive?, Assigned Owner.
- `workbook-scanning-log.csv`: one row per run, columns Scan ID through
  Notes of the "Scanning Log" sheet (date, tool, scope, environment,
  assets scanned, finding counts, high-risk count, operator, evidence
  location).
