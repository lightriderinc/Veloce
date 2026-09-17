"""Windows platform artifacts and desktop UI contracts.

The pytest battery runs on the Linux reference machine, so the Windows
deliverables are validated statically: the WiX package parses and carries the
branding, upgrade, and UI wiring; the PowerShell entry points reference the
release contract (payload, signing exclusions, checksums, named pipe); the
rendered brand assets are well-formed; and the desktop page keeps the element
and asset contract that app.js and the local server rely on.
"""
import importlib.util
import json
import re
import struct
import sys
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
WINDOWS = ROOT / "installer" / "windows"
BRANDING = ROOT / "assets" / "branding"
STATIC = ROOT / "desktop" / "static"
sys.path.insert(0, str(ROOT))

WIX_NS = "http://wixtoolset.org/schemas/v4/wxs"
WIX_UI_NS = "http://wixtoolset.org/schemas/v4/wxs/ui"
PALETTE = ("#fff802", "#ffdc0c", "#fd8c27", "#f82848", "#a72848")


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ----------------------------------------------------------------- WiX MSI

def test_wix_package_carries_branding_upgrade_and_ui():
    root = ET.fromstring((WINDOWS / "veloce.wxs").read_text(encoding="utf-8"))
    package = root.find(f"{{{WIX_NS}}}Package")
    assert package is not None
    assert package.get("Manufacturer") == "Lightrider Inc"
    assert package.get("UpgradeCode") == "B1F95227-6988-4FEA-9705-485619A6E0CB"
    assert package.get("Version") == "$(ProductVersion)"
    assert package.find(f"{{{WIX_NS}}}MajorUpgrade") is not None

    icon = package.find(f"{{{WIX_NS}}}Icon")
    assert icon is not None and icon.get("SourceFile").endswith("veloce.ico")
    properties = {p.get("Id"): p.get("Value") for p in package.iter(f"{{{WIX_NS}}}Property")}
    assert properties.get("ARPPRODUCTICON") == icon.get("Id")

    variables = {v.get("Id"): v.get("Value") for v in package.iter(f"{{{WIX_NS}}}WixVariable")}
    assert variables["WixUILicenseRtf"] == "$(LicenseRtf)"
    assert variables["WixUIBannerBmp"].endswith("wix-banner.bmp")
    assert variables["WixUIDialogBmp"].endswith("wix-dialog.bmp")
    ui = package.find(f"{{{WIX_UI_NS}}}WixUI")
    assert ui is not None and ui.get("Id") == "WixUI_InstallDir"
    assert ui.get("InstallDirectory") == "INSTALLFOLDER"

    shortcut = next(package.iter(f"{{{WIX_NS}}}Shortcut"))
    assert shortcut.get("Icon") == icon.get("Id")
    assert shortcut.get("Directory") == "ProgramMenuFolder"
    files = next(package.iter(f"{{{WIX_NS}}}Files"))
    assert files.get("Include") == "$(PayloadDir)\\**"


def test_release_builder_wires_branding_signing_and_checksums():
    text = (WINDOWS / "build-release.ps1").read_text(encoding="utf-8")
    assert '$Version = "1.2.0"' in text
    for required in ("-ext WixToolset.UI.wixext", "BrandingDir=$Branding",
                     "LicenseRtf=$LicenseRtf", "ProductVersion=$Version",
                     "CertificateThumbprint", "SHA256SUMS-windows-$Arch.txt",
                     "--discovery-only", "--runtime-dir"):
        assert required in text, f"build-release.ps1 lacks {required}"
    # Hash-recorded libraries are never rewritten by signing.
    assert "-notmatch '\\\\lib\\\\'" in text
    # sha256sum -c compatible checksum lines.
    assert '"$hash  $(Split-Path -Leaf $artifact)"' in text


def test_windows_fire_up_uses_records_pipe_and_state_dir():
    text = (WINDOWS / "veloce-fire-up.ps1").read_text(encoding="utf-8")
    assert "\\\\.\\pipe\\$PipeName" in text and 'PipeName = "LightRider.PQC.v1"' in text
    assert "wolfcrypt-fips.build-record.json" in text
    assert "veloce-pqc.build-record.json" in text
    assert "Lightrider\\Veloce" in text and "LOCALAPPDATA" in text
    assert "--json status" in text and "--json self-test" in text
    assert 'mode = "disabled"' in text and 'entropy_mixin = "off"' in text
    assert "_internal\\bin" in text  # portable desktop payload layout


# --------------------------------------------------------------- branding

def test_brand_mark_svg_uses_lightrider_gradient():
    root = ET.fromstring((BRANDING / "veloce.svg").read_text(encoding="utf-8"))
    stops = [s.get("stop-color").lower() for s in root.iter("{http://www.w3.org/2000/svg}stop")]
    assert stops == list(PALETTE)
    assert (STATIC / "favicon.svg").read_bytes() == (BRANDING / "veloce.svg").read_bytes()


def test_icon_files_are_well_formed():
    ico = (BRANDING / "veloce.ico").read_bytes()
    reserved, kind, count = struct.unpack_from("<HHH", ico, 0)
    assert (reserved, kind) == (0, 1)
    sizes = set()
    for index in range(count):
        width, height = struct.unpack_from("<BB", ico, 6 + index * 16)
        sizes.add(256 if width == 0 else width)
    assert {16, 32, 48, 256} <= sizes
    assert (BRANDING / "veloce.icns").read_bytes()[:4] == b"icns"
    assert (BRANDING / "veloce-256.png").read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


@pytest.mark.parametrize("name,size", [("wix-banner.bmp", (493, 58)),
                                       ("wix-dialog.bmp", (493, 312))])
def test_wix_bitmaps_have_required_dimensions(name, size):
    data = (BRANDING / name).read_bytes()
    assert data[:2] == b"BM"
    width, height = struct.unpack_from("<ii", data, 18)
    assert (width, abs(height)) == size


def test_desktop_packager_uses_icon_and_renders_license_rtf(tmp_path):
    builder = _load(ROOT / "scripts" / "build_desktop_release.py", "build_desktop_release")
    (tmp_path / "bin").mkdir()
    args = builder.pyinstaller_args(tmp_path, tmp_path / "dist", tmp_path / "work",
                                    "windows", "x86_64")
    icon = args[args.index("--icon") + 1]
    assert icon.endswith("veloce.ico")
    assert builder.rtf_escape("a{b}\\c\n") == "a\\{b\\}\\\\c\\par\n"
    assert builder.rtf_escape("\u00e9") == "\\u233?"
    target = tmp_path / "license.rtf"
    builder.write_license_rtf(ROOT / "LICENSE", target)
    text = target.read_text(encoding="ascii")
    assert text.startswith("{\\rtf1\\ansi") and text.rstrip().endswith("}")


# --------------------------------------------------------- desktop UI page

class _IdCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.assets = set()
        self.inline_style = []
        self.inline_handlers = []
        self.inline_scripts = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if "id" in attributes:
            assert attributes["id"] not in self.ids, f"duplicate id {attributes['id']}"
            self.ids.add(attributes["id"])
        if tag in ("link", "script") and attributes.get("href" if tag == "link" else "src"):
            self.assets.add(attributes["href" if tag == "link" else "src"])
        if tag == "script" and "src" not in attributes:
            self.inline_scripts += 1
        if "style" in attributes:
            self.inline_style.append(tag)
        self.inline_handlers.extend(k for k in attributes if k.startswith("on"))


def _parse_index():
    collector = _IdCollector()
    collector.feed((STATIC / "index.html").read_text(encoding="utf-8"))
    return collector


def test_page_keeps_every_element_id_that_app_js_uses():
    page = _parse_index()
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    referenced = set(re.findall(r'byId\("([\w-]+)"\)', script))
    referenced |= set(re.findall(r'setText\("([\w-]+)"', script))
    referenced |= set(re.findall(r'setValueState\("([\w-]+)"', script))
    for page_name in re.findall(r'^\s+(\w+): "', re.search(r"PAGE_TITLES = \{(.*?)\};", script, re.S).group(1), re.M):
        referenced.add(f"{page_name}-page")
    missing = referenced - page.ids
    assert not missing, f"index.html lacks ids used by app.js: {sorted(missing)}"


def test_page_respects_the_content_security_policy():
    page = _parse_index()
    assert not page.inline_style, f"inline style attributes violate style-src 'self': {page.inline_style}"
    assert not page.inline_handlers and page.inline_scripts == 0
    server = (ROOT / "desktop" / "veloce_desktop.py").read_text(encoding="utf-8")
    for asset in page.assets:
        assert f'"{asset}":' in server, f"{asset} is not served by veloce_desktop.py"
    assert "/favicon.svg" in page.assets


def test_stylesheet_uses_palette_and_system_appearance():
    css = (STATIC / "styles.css").read_text(encoding="utf-8")
    assert css.count("{") == css.count("}")
    lowered = css.lower()
    for color in PALETTE:
        assert color in lowered, f"palette color {color} missing"
    assert "color-scheme: light dark" in css
    assert "@media (prefers-color-scheme: dark)" in css
    # Readability floor: base type is 15px and labels are not tiny uppercase.
    assert "font-size: 15px" in css
    assert "text-transform: uppercase" not in css.split(".validation-item strong")[0]
    for state in ("width-10", "width-50", "width-100", "value-good", "value-bad",
                  "value-warn", "status-dot", "classification", "live-pill.live",
                  "live-pill.failed", "toast.success", "nav-item.active"):
        assert state in css, f"styles.css lacks the {state} class app.js relies on"


# ------------------------------------------------------------ gen_config

def test_gen_config_resolves_libraries_from_build_records(tmp_path):
    gen = _load(ROOT / "scripts" / "gen_config.py", "gen_config")
    lib_dir = tmp_path / "fips"
    lib_dir.mkdir()
    (lib_dir / "wolfssl-fips.dll").write_bytes(b"MZ")
    (lib_dir / "build-record.json").write_text(json.dumps({"library": "wolfssl-fips.dll"}))
    assert gen.recorded_library(str(lib_dir), "*.nomatch").endswith("wolfssl-fips.dll")
    (lib_dir / "build-record.json").write_text("{}")
    assert gen.recorded_library(str(lib_dir), "wolfssl-fips*.dll").endswith("wolfssl-fips.dll")
    assert gen.recorded_library(str(lib_dir), "*.so") is None
    windows = gen.platform_defaults("win32")
    assert windows["endpoint_key"] == "pipe"
    assert windows["endpoint"] == r"\\.\pipe\LightRider.PQC.v1"
    assert gen.platform_defaults("linux")["endpoint_key"] == "socket"
