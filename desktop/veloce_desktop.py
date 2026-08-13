#!/usr/bin/env python3
"""Veloce Desktop: local qSearch UI and live FIPS status dashboard.

The application binds only to a random loopback port, opens the system browser,
and requires an unguessable token for every API request. Cryptography remains in
the native Veloce agent; this process only invokes the qSearch and Veloce CLIs.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
import webbrowser
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse


APP_VERSION = "1.0.0"
MAX_REQUEST_BYTES = 64 * 1024
MAX_UI_FINDINGS = 500


def _bundle_root() -> Path:
    frozen_root = getattr(sys, "_MEIPASS", None)
    if frozen_root:
        return Path(frozen_root)
    return Path(__file__).resolve().parent.parent


def _executable_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _tool_name(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def _user_state_dir(system: Optional[str] = None) -> Path:
    system = system or platform.system()
    if system == "Windows":
        return (Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) /
                "Lightrider" / "Veloce")
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Veloce"
    return Path.home() / ".veloce"


def find_tool(name: str, env_name: str) -> Optional[Path]:
    """Find a packaged/native tool without using a shell search path blindly."""
    candidates: List[Path] = []
    configured = os.environ.get(env_name)
    if configured:
        candidates.append(Path(configured).expanduser())
    executable = _tool_name(name)
    root = _bundle_root()
    exe_dir = _executable_dir()
    candidates.extend([
        root / "bin" / executable,
        exe_dir / "bin" / executable,
        exe_dir / executable,
        root / "build" / "bin" / executable,
    ])
    on_path = shutil.which(executable)
    if on_path:
        candidates.append(Path(on_path))
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def _subprocess_kwargs() -> Dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
    return {}


def run_json_command(command: List[str], timeout: int = 20) -> Dict[str, Any]:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        **_subprocess_kwargs(),
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(detail or f"command exited {completed.returncode}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("native command returned invalid JSON") from exc
    if isinstance(value, dict) and "ok" in value:
        if value.get("ok") is True and isinstance(value.get("result"), dict):
            return value["result"]
        error = value.get("error") or {}
        raise RuntimeError(error.get("message", "native command failed"))
    if not isinstance(value, dict):
        raise RuntimeError("native command returned a non-object JSON value")
    return value


def _record_candidates(file_name: str) -> List[Path]:
    root = _bundle_root()
    exe_dir = _executable_dir()
    return [
        root / "lib" / file_name,
        exe_dir / "lib" / file_name,
        root / "build" / "lib" / "fips" / "build-record.json"
        if file_name.startswith("wolfcrypt") else
        root / "build" / "lib" / "pqc" / "build-record.json",
    ]


def load_record(file_name: str) -> Optional[Dict[str, Any]]:
    for candidate in _record_candidates(file_name):
        try:
            value = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            value["_record_path"] = str(candidate.resolve())
            return value
    return None


def summarize_findings(document: Dict[str, Any]) -> Dict[str, Any]:
    findings = document.get("findings")
    if not isinstance(findings, list):
        findings = []
    counts = {"total": len(findings), "quantum_vulnerable": 0,
              "high_risk": 0, "pqc_ready": 0}
    by_algorithm: Dict[str, int] = {}
    clean: List[Dict[str, Any]] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        classification = item.get("classification")
        risk = item.get("risk")
        if classification == "quantum-vulnerable":
            counts["quantum_vulnerable"] += 1
        if classification == "pqc-ready":
            counts["pqc_ready"] += 1
        if risk == "high":
            counts["high_risk"] += 1
        algorithm = str(item.get("algorithm", "Unknown"))
        by_algorithm[algorithm] = by_algorithm.get(algorithm, 0) + 1
        if len(clean) < MAX_UI_FINDINGS:
            clean.append({
                "algorithm": algorithm,
                "classification": str(classification or "context"),
                "risk": str(risk or "info"),
                "asset": str(item.get("asset", "")),
                "evidence": str(item.get("source_of_evidence", "")),
            })
    top = sorted(by_algorithm.items(), key=lambda item: (-item[1], item[0]))[:10]
    return {
        "scan_root": str(document.get("scan_root", "")),
        "files_scanned": int(document.get("files_scanned", 0) or 0),
        "counts": counts,
        "top_algorithms": [{"algorithm": name, "count": count}
                           for name, count in top],
        "findings": clean,
        "findings_truncated": len(clean) < len(findings),
    }


@dataclass
class ScanJob:
    id: str
    target: str
    output: str
    state: str = "queued"
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


class DesktopService:
    def __init__(self, token: str):
        self.token = token
        self.jobs: Dict[str, ScanJob] = {}
        self.jobs_lock = threading.Lock()
        self.server: Optional[ThreadingHTTPServer] = None
        self._bootstrap_attempted = False

    def _release_manifest(self) -> Optional[Dict[str, Any]]:
        candidates = [
            _bundle_root() / "release-manifest.json",
            _executable_dir() / "release-manifest.json",
            _executable_dir().parent / "Resources" / "release-manifest.json",
        ]
        for path in candidates:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(value, dict):
                return value
        return None

    def platform_info(self) -> Dict[str, Any]:
        manifest = self._release_manifest() or {}
        return {
            "app_version": APP_VERSION,
            "platform": platform.system(),
            "platform_release": platform.release(),
            "machine": platform.machine(),
            "qsearch_available": find_tool("qsearch", "VELOCE_QSEARCH") is not None,
            "veloce_cli_available": find_tool("veloce", "VELOCE_CLI") is not None,
            "release_mode": manifest.get("mode", "development"),
        }

    def _packaged_endpoint(self) -> Optional[tuple[Path, str, str]]:
        """Return and export the endpoint shared by a packaged agent and CLI."""
        manifest = self._release_manifest()
        if not manifest or manifest.get("mode") != "full-runtime":
            return None
        system = platform.system()
        state = _user_state_dir(system)
        if system == "Windows":
            key = "pipe"
            endpoint = os.environ.setdefault(
                "VELOCE_PIPE", r"\\.\pipe\LightRider.PQC.v1")
        else:
            key = "socket"
            endpoint = os.environ.setdefault(
                "VELOCE_SOCKET", str(state / "agent.sock"))
        return state, key, endpoint

    def _start_packaged_agent(self) -> bool:
        """Start a bundled per-user agent once; never infer success from spawn."""
        if self._bootstrap_attempted:
            return False
        self._bootstrap_attempted = True
        packaged_endpoint = self._packaged_endpoint()
        if packaged_endpoint is None:
            return False
        agent = find_tool("veloce-agent", "VELOCE_AGENT")
        fips_record = load_record("wolfcrypt-fips.build-record.json")
        pqc_record = load_record("veloce-pqc.build-record.json")
        if agent is None or not fips_record or not pqc_record:
            return False
        fips_record_path = Path(str(fips_record.get("_record_path", "")))
        pqc_record_path = Path(str(pqc_record.get("_record_path", "")))
        fips_library = fips_record_path.parent / str(fips_record.get("library", ""))
        pqc_library = pqc_record_path.parent / str(pqc_record.get("library", ""))
        if not fips_library.is_file() or not pqc_library.is_file():
            return False

        state, endpoint_key, endpoint = packaged_endpoint
        state.mkdir(parents=True, exist_ok=True)
        config = {
            endpoint_key: endpoint,
            "fips_lib": str(fips_library.resolve()),
            "fips_record": str(fips_record_path.resolve()),
            "pqc_lib": str(pqc_library.resolve()),
            "pqc_record": str(pqc_record_path.resolve()),
            "ems": {"mode": "disabled", "endpoint": "", "entropy_mixin": "off"},
        }
        config_path = state / "agent.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        try:
            config_path.chmod(0o600)
        except OSError:
            pass
        log_path = state / "agent.log"
        creationflags = 0
        popen_options: Dict[str, Any] = {"start_new_session": os.name != "nt"}
        if os.name == "nt":
            creationflags = (getattr(subprocess, "CREATE_NO_WINDOW", 0) |
                             getattr(subprocess, "DETACHED_PROCESS", 0))
            popen_options = {"creationflags": creationflags}
        with log_path.open("ab") as log:
            process = subprocess.Popen(
                [str(agent), "--config", str(config_path), "--quiet"],
                stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                **popen_options,
            )
        (state / "agent.pid").write_text(f"{process.pid}\n", encoding="ascii")
        return True

    def fips_snapshot(self) -> Dict[str, Any]:
        # Export the packaged endpoint before the first CLI call so a second
        # desktop process reconnects to the existing per-user macOS agent.
        self._packaged_endpoint()
        fips_record = load_record("wolfcrypt-fips.build-record.json")
        pqc_record = load_record("veloce-pqc.build-record.json")
        snapshot: Dict[str, Any] = {
            "live": False,
            "approved_mode": False,
            "state": "unavailable",
            "status": None,
            "version": None,
            "validation": None,
            "fips_record": fips_record,
            "pqc_record": pqc_record,
            "message": "Veloce native agent is not installed or not running.",
        }
        cli = find_tool("veloce", "VELOCE_CLI")
        if cli is None:
            return snapshot
        for attempt in range(2):
            try:
                status = run_json_command([str(cli), "--json", "status"])
                version = run_json_command([str(cli), "--json", "version"])
                validation = run_json_command([str(cli), "--json", "validation"])
                break
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                snapshot["message"] = str(exc)
                if attempt == 0 and self._start_packaged_agent():
                    time.sleep(1.0)
                    continue
                return snapshot
        snapshot.update({
            "live": True,
            "approved_mode": status.get("approved_mode") is True,
            "state": str(status.get("state", "unknown")),
            "status": status,
            "version": version,
            "validation": validation,
            "message": "Live status from the local Veloce agent.",
        })
        return snapshot

    def run_self_test(self) -> Dict[str, Any]:
        cli = find_tool("veloce", "VELOCE_CLI")
        if cli is None:
            raise RuntimeError("Veloce CLI is not installed in this release")
        return run_json_command([str(cli), "--json", "self-test"], timeout=120)

    def select_directory(self) -> str:
        system = platform.system()
        if system == "Windows":
            command = [
                "powershell.exe", "-NoProfile", "-STA", "-Command",
                "Add-Type -AssemblyName System.Windows.Forms; "
                "$d=New-Object System.Windows.Forms.FolderBrowserDialog; "
                "$d.Description='Choose a folder for qSearch'; "
                "if($d.ShowDialog() -eq 'OK'){$d.SelectedPath}",
            ]
        elif system == "Darwin":
            command = [
                "osascript", "-e",
                'POSIX path of (choose folder with prompt "Choose a folder for qSearch")',
            ]
        elif shutil.which("zenity"):
            command = ["zenity", "--file-selection", "--directory",
                       "--title=Choose a folder for qSearch"]
        elif shutil.which("kdialog"):
            command = ["kdialog", "--getexistingdirectory", str(Path.home())]
        else:
            raise RuntimeError("No supported graphical folder picker is installed")
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=300, check=False,
            **_subprocess_kwargs(),
        )
        selected = completed.stdout.strip()
        if completed.returncode != 0 or not selected:
            return ""
        path = Path(selected).expanduser()
        if not path.is_dir():
            raise RuntimeError("The selected folder is not readable")
        return str(path.resolve())

    def start_scan(self, target_value: str) -> ScanJob:
        qsearch = find_tool("qsearch", "VELOCE_QSEARCH")
        if qsearch is None:
            raise RuntimeError("qSearch executable is not installed in this release")
        target = Path(target_value).expanduser()
        if not target.is_dir():
            raise RuntimeError("Choose an existing directory to scan")
        report_root = Path.home() / "Documents" / "Veloce Reports"
        stamp = time.strftime("%Y%m%d-%H%M%S")
        output = report_root / f"qsearch-{stamp}-{uuid.uuid4().hex[:6]}"
        job = ScanJob(id=uuid.uuid4().hex, target=str(target.resolve()),
                      output=str(output))
        with self.jobs_lock:
            self.jobs[job.id] = job
        thread = threading.Thread(
            target=self._run_scan, args=(job, qsearch), daemon=True,
            name=f"qsearch-{job.id[:8]}",
        )
        thread.start()
        return job

    def _run_scan(self, job: ScanJob, qsearch: Path) -> None:
        job.state = "running"
        output = Path(job.output)
        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            completed = subprocess.run(
                [str(qsearch), "scan", job.target, "--out", job.output, "--quiet"],
                capture_output=True,
                text=True,
                check=False,
                **_subprocess_kwargs(),
            )
            if completed.returncode != 0:
                detail = completed.stderr.strip() or completed.stdout.strip()
                raise RuntimeError(detail or f"qSearch exited {completed.returncode}")
            report = json.loads((output / "findings.json").read_text(encoding="utf-8"))
            job.result = summarize_findings(report)
            job.state = "complete"
        except Exception as exc:  # background job boundary
            job.error = str(exc)
            job.state = "failed"
        finally:
            job.completed_at = time.time()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self.jobs_lock:
            job = self.jobs.get(job_id)
            return asdict(job) if job else None

    def open_report(self, job_id: str) -> None:
        with self.jobs_lock:
            job = self.jobs.get(job_id)
            if job is None or job.state != "complete":
                raise RuntimeError("Completed scan report not found")
            output = Path(job.output)
        if platform.system() == "Windows":
            os.startfile(str(output))  # type: ignore[attr-defined]
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", str(output)])
        else:
            subprocess.Popen(["xdg-open", str(output)])

    def request_shutdown(self) -> None:
        if self.server is not None:
            threading.Thread(target=self.server.shutdown, daemon=True).start()


class DesktopHandler(BaseHTTPRequestHandler):
    server_version = "VeloceDesktop/1.0"

    @property
    def service(self) -> DesktopService:
        return getattr(self.server, "service")

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.environ.get("VELOCE_DESKTOP_DEBUG") == "1":
            super().log_message(fmt, *args)

    def _security_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self'; style-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def _send_json(self, value: Any, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self._security_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized(self) -> bool:
        return secrets.compare_digest(
            self.headers.get("X-Veloce-Token", ""), self.service.token)

    def _read_json(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length < 0 or length > MAX_REQUEST_BYTES:
            raise ValueError("request is too large")
        raw = self.rfile.read(length)
        value = json.loads(raw or b"{}")
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def _serve_static(self, request_path: str) -> None:
        files = {
            "/": ("desktop/static/index.html", "text/html; charset=utf-8"),
            "/index.html": ("desktop/static/index.html", "text/html; charset=utf-8"),
            "/app.js": ("desktop/static/app.js", "application/javascript; charset=utf-8"),
            "/styles.css": ("desktop/static/styles.css", "text/css; charset=utf-8"),
        }
        item = files.get(request_path)
        if item is None:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        relative, content_type = item
        try:
            body = (_bundle_root() / relative).read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self._security_headers()
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            self._serve_static(parsed.path)
            return
        if not self._authorized():
            self._send_json({"error": "unauthorized"}, HTTPStatus.FORBIDDEN)
            return
        try:
            if parsed.path == "/api/platform":
                self._send_json(self.service.platform_info())
            elif parsed.path == "/api/fips":
                self._send_json(self.service.fips_snapshot())
            elif parsed.path == "/api/qsearch/job":
                job_id = parse_qs(parsed.query).get("id", [""])[0]
                job = self.service.get_job(job_id)
                if job is None:
                    self._send_json({"error": "job not found"}, HTTPStatus.NOT_FOUND)
                else:
                    self._send_json(job)
            else:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except Exception as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        parsed = urlparse(self.path)
        if not self._authorized():
            self._send_json({"error": "unauthorized"}, HTTPStatus.FORBIDDEN)
            return
        try:
            data = self._read_json()
            if parsed.path == "/api/fips/self-test":
                self._send_json(self.service.run_self_test())
            elif parsed.path == "/api/qsearch/select-directory":
                self._send_json({"path": self.service.select_directory()})
            elif parsed.path == "/api/qsearch/run":
                job = self.service.start_scan(str(data.get("target", "")))
                self._send_json(asdict(job), HTTPStatus.ACCEPTED)
            elif parsed.path == "/api/qsearch/open-report":
                self.service.open_report(str(data.get("job_id", "")))
                self._send_json({"opened": True})
            elif parsed.path == "/api/shutdown":
                self._send_json({"stopping": True})
                self.service.request_shutdown()
            else:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-browser", action="store_true",
                        help="start the local UI server without opening a browser")
    parser.add_argument("--port", type=int, default=0,
                        help="loopback port; 0 chooses an available port")
    args = parser.parse_args()

    token = secrets.token_urlsafe(32)
    service = DesktopService(token)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DesktopHandler)
    setattr(server, "service", service)
    service.server = server
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/?token={token}"
    if not args.no_browser:
        threading.Timer(0.25, lambda: webbrowser.open(url)).start()
    else:
        print(url, flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
