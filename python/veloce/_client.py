"""Veloce IPC client internals (ipc/protocol.md).

Pure Python, standard library only. This module never loads any crypto
library; all cryptography is performed by the Veloce agent (spec 3).
"""
from __future__ import annotations

import json
import os
import socket
import struct
import threading
from typing import Any, Dict, Optional

_PROTOCOL_VERSION = 1
_MAX_FRAME = 1 << 20


class VeloceError(Exception):
    """Agent-reported error; code is one of the ipc/protocol.md codes."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class DegradedError(VeloceError):
    """The agent is fail-closed; crypto services are refused (spec 5.1)."""


class ConnectionError_(VeloceError):
    """The agent is not reachable on the IPC socket."""


def default_socket_path() -> str:
    env = os.environ.get("VELOCE_SOCKET")
    if env:
        return env
    if os.geteuid() == 0:
        return "/run/veloce/agent.sock"
    return os.path.expanduser("~/.veloce/agent.sock")


class Client:
    def __init__(self, socket_path: Optional[str] = None):
        self._path = socket_path or default_socket_path()
        self._sock: Optional[socket.socket] = None
        self._lock = threading.Lock()
        self._id = 0

    def connect(self) -> None:
        if self._sock is not None:
            return
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(self._path)
        except OSError as e:
            s.close()
            raise ConnectionError_(
                "unreachable",
                f"cannot connect to Veloce agent at {self._path}: {e}",
            ) from e
        self._sock = s

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                finally:
                    self._sock = None

    def call(self, op: str, params: Optional[Dict[str, Any]] = None) -> Any:
        with self._lock:
            self.connect()
            assert self._sock is not None
            self._id += 1
            req = json.dumps(
                {"v": _PROTOCOL_VERSION, "id": self._id, "op": op,
                 "params": params or {}}
            ).encode("utf-8")
            if len(req) > _MAX_FRAME:
                raise VeloceError("bad_request", "request too large")
            try:
                self._sock.sendall(struct.pack(">I", len(req)) + req)
                hdr = self._recv_exact(4)
                (n,) = struct.unpack(">I", hdr)
                if n == 0 or n > _MAX_FRAME:
                    raise VeloceError("internal", "invalid response frame")
                payload = self._recv_exact(n)
            except (OSError, EOFError) as e:
                self.close()
                raise ConnectionError_(
                    "unreachable", f"agent connection lost: {e}"
                ) from e
        resp = json.loads(payload.decode("utf-8"))
        if resp.get("ok"):
            return resp.get("result")
        err = resp.get("error") or {}
        code = err.get("code", "internal")
        message = err.get("message", "unknown error")
        if code == "degraded":
            raise DegradedError(code, message)
        raise VeloceError(code, message)

    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("connection closed by agent")
            buf += chunk
        return buf
