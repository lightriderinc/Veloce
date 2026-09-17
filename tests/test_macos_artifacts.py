"""macOS platform artifacts: launchd template, launcher, and build script.

The pytest battery runs on the Linux reference machine, so these tests
validate the macOS deliverables statically: the LaunchAgent plist parses and
carries the required keys, the shell entry points are syntactically valid
bash, and the launcher wires the dylib artifact names the macOS runtime
build stages.
"""
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).parents[1]
MACOS = ROOT / "installer" / "macos"


def _bash_syntax_ok(path: Path) -> None:
    subprocess.run(["bash", "-n", str(path)], check=True)


def test_launchd_plist_template_parses_with_required_keys():
    plist = MACOS / "com.lightrider.veloce-agent.plist"
    text = plist.read_text(encoding="utf-8")
    root = ET.fromstring(text)
    assert root.tag == "plist"
    keys = [el.text for el in root.iter("key")]
    for required in ("Label", "ProgramArguments", "RunAtLoad", "KeepAlive",
                     "StandardOutPath", "StandardErrorPath"):
        assert required in keys, f"missing plist key {required}"
    strings = [el.text for el in root.iter("string")]
    assert "com.lightrider.veloce-agent" in strings
    for placeholder in ("__VELOCE_AGENT__", "__VELOCE_CONFIG__",
                        "__VELOCE_LOG__"):
        assert placeholder in text, f"missing template placeholder {placeholder}"


def test_macos_fire_up_is_valid_and_wires_dylib_names():
    fire_up = MACOS / "veloce-fire-up"
    _bash_syntax_ok(fire_up)
    text = fire_up.read_text(encoding="utf-8")
    assert "libwolfssl.*.dylib" in text
    assert "libveloce-pqc.dylib" in text
    assert "wolfcrypt-fips.build-record.json" in text
    assert "veloce-pqc.build-record.json" in text
    assert "--launchd" in text
    # arm64 has no RDSEED: the launcher must select the seed source explicitly.
    assert '"entropy": {"source": entropy_source}' in text
    assert "os-drbg" in text and "rdseed" in text
    assert 'ems": {"mode": "disabled"' in text.replace("'", '"') or \
        '"mode": "disabled"' in text


def test_build_macos_script_is_valid_and_fail_closed():
    script = ROOT / "scripts" / "build_macos.sh"
    _bash_syntax_ok(script)
    text = script.read_text(encoding="utf-8")
    assert "set -euo pipefail" in text
    # wolfEntropy stays out of the build (wolfSSL 2026-08-27).
    assert "--enable-fips=v5" in text
    assert "--enable-wolfEntropy" not in text
    # Smoke gate must verify the module, provider, and live agent.
    assert "testwolfcrypt" in text
    assert "all checks passed" in text
    assert "approved_mode" in text
    # No validated-deployment claim for the macOS OE.
    assert "no macOS OE exists on any wolfCrypt certificate" in text


def test_macos_release_builder_still_requires_explicit_mode():
    builder = MACOS / "build-release.sh"
    _bash_syntax_ok(builder)
    text = builder.read_text(encoding="utf-8")
    assert "--discovery-only" in text and "--runtime-dir" in text


def test_macos_dmg_explains_gatekeeper_and_verifies_notarization():
    text = (MACOS / "build-release.sh").read_text(encoding="utf-8")
    # Drag-install layout and a per-build-type note for the user.
    assert 'ln -s /Applications "$DMG_STAGE/Applications"' in text
    assert "How to open Veloce.txt" in text
    assert "Open Anyway" in text and "xattr -dr com.apple.quarantine" in text
    # Notarized builds are stapled and assessed; ad-hoc builds warn loudly.
    assert "xcrun notarytool submit" in text and "xcrun stapler staple" in text
    assert "xcrun stapler validate" in text and "spctl --assess" in text
    assert "VELOCE_NOTARY_KEYCHAIN" in text
    assert "ad-hoc signed; Gatekeeper will block first launch" in text
