#!/usr/bin/env python3
"""Manual two-host ML-DSA and ML-KEM exchange through local Veloce agents.

This is an interoperability demonstration, not an application encryption
protocol.  Files marked private must never leave the recipient host.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict

import veloce


FORMAT = "veloce-two-party-demo/1"


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def read_json(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as source:
        value = json.load(source)
    if not isinstance(value, dict) or value.get("format") != FORMAT:
        raise ValueError(f"{path}: unsupported demo document")
    return value


def write_json(path: str, value: Dict[str, Any], private: bool = False) -> None:
    target = Path(path)
    target.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    if private:
        os.chmod(target, 0o600)


def initialize() -> None:
    status = veloce.initialize()
    if not status.get("approved_mode"):
        raise RuntimeError(f"Veloce agent is not ready: {status}")


def sign_create(args: argparse.Namespace) -> None:
    initialize()
    message = Path(args.message_file).read_bytes()
    key = veloce.mldsa_generate_keypair()
    try:
        signature = veloce.mldsa_sign(key.private_key_handle, message)
        write_json(args.out, {
            "format": FORMAT,
            "operation": "ML-DSA-65-signature",
            "message_b64": b64e(message),
            "public_key_b64": b64e(key.public_key),
            "signature_b64": b64e(signature),
        })
    finally:
        key.release()
    print(f"signature bundle written: {args.out}")


def verify(args: argparse.Namespace) -> None:
    initialize()
    bundle = read_json(args.input)
    if bundle.get("operation") != "ML-DSA-65-signature":
        raise ValueError("not an ML-DSA signature bundle")
    valid = veloce.mldsa_verify(
        b64d(bundle["public_key_b64"]),
        b64d(bundle["message_b64"]),
        b64d(bundle["signature_b64"]),
    )
    print(f"signature valid: {valid}")
    if not valid:
        raise SystemExit(1)


def kem_init(args: argparse.Namespace) -> None:
    initialize()
    key = veloce.mlkem_generate_keypair()
    write_json(args.public_out, {
        "format": FORMAT,
        "operation": "ML-KEM-768-public-key",
        "public_key_b64": b64e(key.public_key),
    })
    write_json(args.private_state, {
        "format": FORMAT,
        "operation": "ML-KEM-768-private-state",
        "private_key_handle": key.private_key_handle,
    }, private=True)
    print(f"public exchange file written: {args.public_out}")
    print(f"private state written locally: {args.private_state}")
    print("Do not copy the private-state file and do not restart the agent.")


def kem_encapsulate(args: argparse.Namespace) -> None:
    initialize()
    public_doc = read_json(args.public_input)
    if public_doc.get("operation") != "ML-KEM-768-public-key":
        raise ValueError("not an ML-KEM public-key document")
    ciphertext, shared_secret = veloce.mlkem_encapsulate(
        b64d(public_doc["public_key_b64"])
    )
    fingerprint = hashlib.sha256(shared_secret).hexdigest()
    write_json(args.response_out, {
        "format": FORMAT,
        "operation": "ML-KEM-768-encapsulation",
        "ciphertext_b64": b64e(ciphertext),
        "shared_secret_sha256": fingerprint,
    })
    print(f"encapsulation response written: {args.response_out}")
    print(f"sender shared-secret fingerprint: {fingerprint}")


def kem_finish(args: argparse.Namespace) -> None:
    initialize()
    private_doc = read_json(args.private_state)
    response = read_json(args.response_input)
    if private_doc.get("operation") != "ML-KEM-768-private-state":
        raise ValueError("not an ML-KEM private-state document")
    if response.get("operation") != "ML-KEM-768-encapsulation":
        raise ValueError("not an ML-KEM encapsulation response")
    handle = private_doc["private_key_handle"]
    try:
        shared_secret = veloce.mlkem_decapsulate(
            handle, b64d(response["ciphertext_b64"])
        )
        actual = hashlib.sha256(shared_secret).hexdigest()
        expected = response["shared_secret_sha256"]
        matched = hmac.compare_digest(actual, expected)
        print(f"recipient shared-secret fingerprint: {actual}")
        print(f"shared secrets match: {matched}")
        if not matched:
            raise SystemExit(1)
    finally:
        veloce.release_key(handle)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    command = commands.add_parser("sign-create")
    command.add_argument("--message-file", required=True)
    command.add_argument("--out", required=True)
    command.set_defaults(func=sign_create)

    command = commands.add_parser("verify")
    command.add_argument("--input", required=True)
    command.set_defaults(func=verify)

    command = commands.add_parser("kem-init")
    command.add_argument("--public-out", required=True)
    command.add_argument("--private-state", required=True)
    command.set_defaults(func=kem_init)

    command = commands.add_parser("kem-encapsulate")
    command.add_argument("--public-input", required=True)
    command.add_argument("--response-out", required=True)
    command.set_defaults(func=kem_encapsulate)

    command = commands.add_parser("kem-finish")
    command.add_argument("--private-state", required=True)
    command.add_argument("--response-input", required=True)
    command.set_defaults(func=kem_finish)
    return root


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
