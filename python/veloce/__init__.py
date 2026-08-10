"""Veloce PQC SDK, Lightrider Inc.

Pure-Python client for the Veloce agent (spec 7.1): the 17 public API
functions, the approved V1 extension set_entropy_mixin, and the erratum
addition mldsa_generate_keypair (required for mldsa_sign/mldsa_verify to be
exercisable; flagged for guidance reconciliation).

All cryptography executes inside the local Veloce agent over authenticated
IPC; private keys never cross the channel and are represented only as
opaque handles (spec 8).

No output is produced on import (library convention, spec 7.3); the ASCII
banner is available explicitly via veloce.banner().
"""
from __future__ import annotations

import base64 as _b64
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ._client import (
    Client,
    ConnectionError_,
    DegradedError,
    VeloceError,
    default_socket_path,
)

__version__ = "1.0.0"
__all__ = [
    "initialize", "health", "version",
    "list_policy_profiles", "list_crypto_providers",
    "list_entropy_providers", "validation_status",
    "mlkem_generate_keypair", "mlkem_encapsulate", "mlkem_decapsulate",
    "mldsa_generate_keypair", "mldsa_sign", "mldsa_verify",
    "configure_hybrid_tls", "run_fips_self_tests", "approved_mode_status",
    "export_cbom", "generate_diagnostic_bundle",
    "set_entropy_mixin", "release_key",
    "banner", "KeyPair",
    "VeloceError", "DegradedError", "ConnectionError_",
]

_client: Optional[Client] = None


def _c() -> Client:
    global _client
    if _client is None:
        _client = Client()
    return _client


@dataclass(frozen=True)
class KeyPair:
    """Public key plus the agent-held opaque private key handle."""

    algorithm: str
    parameter_set: int
    public_key: bytes
    private_key_handle: str

    def release(self) -> None:
        """Zeroize and drop the private key inside the agent."""
        release_key(self.private_key_handle)


# Lifecycle -----------------------------------------------------------------

def initialize(socket_path: Optional[str] = None) -> Dict[str, Any]:
    """Connect to the agent and return its status snapshot."""
    global _client
    if socket_path is not None:
        _client = Client(socket_path)
    return _c().call("initialize")


def health() -> Dict[str, Any]:
    return _c().call("health")


def version() -> Dict[str, Any]:
    return _c().call("version")


# Discovery -----------------------------------------------------------------

def list_policy_profiles() -> Dict[str, Any]:
    return _c().call("list_policy_profiles")


def list_crypto_providers() -> Dict[str, Any]:
    return _c().call("list_crypto_providers")


def list_entropy_providers() -> Dict[str, Any]:
    return _c().call("list_entropy_providers")


def validation_status() -> Dict[str, Any]:
    return _c().call("validation_status")


# ML-KEM --------------------------------------------------------------------

def mlkem_generate_keypair(parameter_set: int = 768) -> KeyPair:
    r = _c().call("mlkem_generate_keypair", {"parameter_set": parameter_set})
    return KeyPair("ML-KEM", parameter_set,
                   _b64.b64decode(r["public_key"]),
                   r["private_key_handle"])


def mlkem_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Returns (ciphertext, shared_secret)."""
    r = _c().call("mlkem_encapsulate",
                  {"public_key": _b64.b64encode(public_key).decode()})
    return _b64.b64decode(r["ciphertext"]), _b64.b64decode(r["shared_secret"])


def mlkem_decapsulate(private_key_handle: str, ciphertext: bytes) -> bytes:
    r = _c().call("mlkem_decapsulate", {
        "private_key_handle": private_key_handle,
        "ciphertext": _b64.b64encode(ciphertext).decode(),
    })
    return _b64.b64decode(r["shared_secret"])


# ML-DSA --------------------------------------------------------------------

def mldsa_generate_keypair(parameter_set: int = 65) -> KeyPair:
    r = _c().call("mldsa_generate_keypair", {"parameter_set": parameter_set})
    return KeyPair("ML-DSA", parameter_set,
                   _b64.b64decode(r["public_key"]),
                   r["private_key_handle"])


def mldsa_sign(private_key_handle: str, message: bytes) -> bytes:
    r = _c().call("mldsa_sign", {
        "private_key_handle": private_key_handle,
        "message": _b64.b64encode(message).decode(),
    })
    return _b64.b64decode(r["signature"])


def mldsa_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    r = _c().call("mldsa_verify", {
        "public_key": _b64.b64encode(public_key).decode(),
        "message": _b64.b64encode(message).decode(),
        "signature": _b64.b64encode(signature).decode(),
    })
    return bool(r["valid"])


# TLS / FIPS ----------------------------------------------------------------

def configure_hybrid_tls(
        policy: str = "LIGHTRIDER_PQC_TRANSITION") -> Dict[str, Any]:
    """Select a policy profile (never raw algorithm strings, spec 5.4)."""
    return _c().call("configure_hybrid_tls", {"policy": policy})


def run_fips_self_tests() -> Dict[str, Any]:
    return _c().call("run_fips_self_tests")


def approved_mode_status() -> Dict[str, Any]:
    return _c().call("approved_mode_status")


# Reporting -----------------------------------------------------------------

def export_cbom(format: str = "records",
                path: Optional[str] = None) -> Dict[str, Any]:
    """CBOM export; format is "records" or "cyclonedx" (spec 4.4).

    When path is given the document is also written to that file.
    """
    doc = _c().call("export_cbom", {"format": format})
    if path:
        import json
        with open(path, "w") as f:
            json.dump(doc, f, indent=2)
    return doc


def generate_diagnostic_bundle(path: Optional[str] = None) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    if path:
        params["path"] = path
    return _c().call("generate_diagnostic_bundle", params)


# V1 extension (spec 6.2) and key custody ------------------------------------

def set_entropy_mixin(enabled: bool) -> Dict[str, Any]:
    """User-controllable cloud-entropy mix-in; requires EMS enabled."""
    return _c().call("set_entropy_mixin", {"enabled": enabled})


def release_key(private_key_handle: str) -> None:
    _c().call("release_key", {"private_key_handle": private_key_handle})


# Branding (spec 7.3) --------------------------------------------------------

_BANNER = r"""
  _   _  ____  __     ___    ____  ____
 | | | || ___| | |   / _ \  / ___|| ___|
 | | | || |_   | |  | | | || |    | |_
 | |_| || __|  | |__| |_| || |___ | __|
  \___/ |____| |____|\___/  \____||____|
"""


def banner() -> str:
    """Lightrider startup banner with the live status line."""
    line = f"Lightrider Inc -- Veloce PQC SDK v{__version__}"
    try:
        v = version()
        a = approved_mode_status()
        h = health()
        status = (f"FIPS 140-3 {v.get('fips_certificate', '#4718')}"
                  f" | ESV entropy: "
                  f"{'OK' if h['entropy']['healthy'] else 'FAILED'}"
                  f" | approved mode: {'on' if a['approved'] else 'off'}")
    except VeloceError:
        status = "agent unreachable"
    return f"{_BANNER}{line}\n{status}\n"
