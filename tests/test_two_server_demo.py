"""Exercise the file-exchange commands used by the manual two-host guide."""
import os
from pathlib import Path
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "examples" / "two-server" / "two_party_demo.py"


def test_two_party_demo(agent, tmp_path):
    env = os.environ.copy()
    env["VELOCE_SOCKET"] = agent["socket"]
    env["PYTHONPATH"] = str(ROOT / "python")

    def run(*args):
        return subprocess.run(
            [sys.executable, str(DEMO), *map(str, args)],
            env=env, capture_output=True, text=True, check=True,
        )

    message = tmp_path / "message.txt"
    signed = tmp_path / "signed.json"
    message.write_text("two-host signature fixture\n", encoding="utf-8")
    run("sign-create", "--message-file", message, "--out", signed)
    verified = run("verify", "--input", signed)
    assert "signature valid: True" in verified.stdout

    public = tmp_path / "recipient-public.json"
    private = tmp_path / "recipient-private.json"
    response = tmp_path / "kem-response.json"
    run("kem-init", "--public-out", public, "--private-state", private)
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    run("kem-encapsulate", "--public-input", public,
        "--response-out", response)
    finished = run("kem-finish", "--private-state", private,
                   "--response-input", response)
    assert "shared secrets match: True" in finished.stdout
