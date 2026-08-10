"""Gate G2 addition: qSearch workbook exports match the Light Rider CBOM
workbook (Light_Rider_CBOM_Template_Updated.xlsx) sheet columns exactly
(Appendix B; cbom/field-mapping.md)."""
import csv
import os
import subprocess
import zipfile
import xml.etree.ElementTree as ET

import pytest

from conftest import QSEARCH_BIN, ROOT

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
RNS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
WORKBOOK = os.path.join(ROOT, "Light_Rider_CBOM_Template_Updated.xlsx")


def workbook_headers(sheet_name):
    z = zipfile.ZipFile(WORKBOOK)
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
    relmap = {r.get("Id"): r.get("Target") for r in rels}
    strings = []
    sroot = ET.fromstring(z.read("xl/sharedStrings.xml"))
    for si in sroot.findall(NS + "si"):
        strings.append("".join(t.text or "" for t in si.iter(NS + "t")))
    for sheet in wb.iter(NS + "sheet"):
        if sheet.get("name") != sheet_name:
            continue
        target = relmap[sheet.get(RNS + "id")].lstrip("/")
        path = target if target.startswith("xl/") else "xl/" + target
        root = ET.fromstring(z.read(path))
        row = root.find(".//" + NS + "row")
        headers = []
        for c in row.findall(NS + "c"):
            v = c.find(NS + "v")
            if v is None:
                continue
            headers.append(strings[int(v.text)] if c.get("t") == "s"
                           else v.text)
        return headers
    raise AssertionError(f"sheet {sheet_name} not in workbook")


@pytest.fixture(scope="module")
def outdir(tmp_path_factory, planted_tree_module):
    if not os.path.exists(QSEARCH_BIN):
        pytest.skip("qsearch not built")
    if not os.path.exists(WORKBOOK):
        pytest.skip("workbook template not present")
    out = tmp_path_factory.mktemp("wb")
    r = subprocess.run(
        [QSEARCH_BIN, "scan", str(planted_tree_module), "--out", str(out),
         "--quiet"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return out


@pytest.fixture(scope="module")
def planted_tree_module(tmp_path_factory):
    tree = tmp_path_factory.mktemp("planted")
    (tree / "legacy.c").write_text("RSA_generate_key(2048, 65537, 0, 0);\n")
    return tree


def test_discovery_findings_columns_match_workbook(outdir):
    expected = workbook_headers("Discovery Findings")
    with open(outdir / "workbook-discovery-findings.csv") as f:
        got = next(csv.reader(f))
    assert got == expected


def test_scanning_log_columns_match_workbook(outdir):
    expected = workbook_headers("Scanning Log")
    with open(outdir / "workbook-scanning-log.csv") as f:
        rows = list(csv.reader(f))
    assert rows[0] == expected
    assert len(rows) == 2  # header + one row per run
    row = dict(zip(rows[0], rows[1]))
    assert row["Tool / Method"].startswith("qSearch")
    assert row["Scan ID"].startswith("SCAN-")


def test_run_log_written(outdir):
    text = open(outdir / "qsearch-run.log").read()
    assert "duration_ms:" in text
    assert "findings_total:" in text
    assert "Light_Rider_CBOM_Template_Updated.xlsx" in text
