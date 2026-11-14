#!/usr/bin/env python3
"""Run the native clamctl CLI and MCP server against the Rust server and a synthetic clamd.

Needs target/release/clamv-webui (or CLAMV_WEBUI_BIN), cli/dist/linux_amd64/clamctl
(or CLAMCTL_BIN) and Go on PATH. Everything lives in a temporary directory.
"""
from pathlib import Path
import datetime
import os
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


class Clamd(socketserver.StreamRequestHandler):
    def handle(self):
        first = self.rfile.read(1)
        if not first:
            return
        end = b"\0" if first == b"z" else b"\n"
        data = bytearray()
        while len(data) < 8192:
            char = self.rfile.read(1)
            if not char or char == end:
                break
            data.extend(char)
        command = data.decode("utf-8")
        name, _, argument = command.partition(" ")
        version = "ClamAV 1.5.4/27920/" + datetime.datetime.now(datetime.timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
        if name == "PING":
            reply = "PONG"
        elif name == "VERSION":
            reply = version
        elif name == "STATS":
            reply = "POOLS: 1\nTHREADS: live 5 idle 3 max 10 idle-timeout 30\nQUEUE: 0 items\nMEMSTATS: heap N/A pools 1 pools_used 1.500M pools_total 2.000M\nEND"
        elif name == "INSTREAM":
            payload = bytearray()
            while True:
                header = self.rfile.read(4)
                if len(header) != 4:
                    return
                size = struct.unpack("!I", header)[0]
                if size == 0:
                    break
                payload.extend(self.rfile.read(size))
            if b"CLAMD_ERROR" in payload:
                reply = "stream: Synthetic scanner failure ERROR"
            else:
                reply = "stream: Win.Test.EICAR_HDB-1 FOUND" if b"EICAR" in payload else "stream: OK"
        elif name in {"SCAN", "MULTISCAN", "CONTSCAN"}:
            target = Path(argument)
            files = [p for p in target.rglob("*") if p.is_file()] if target.is_dir() else [target]
            lines = []
            for f in files:
                try:
                    lines.append(str(f) + (": Win.Test.EICAR_HDB-1 FOUND" if b"EICAR" in f.read_bytes() else ": OK"))
                except OSError:
                    lines.append(str(f) + ": File unavailable ERROR")
            reply = ("\0" if end == b"\0" else "\n").join(lines) or (argument + ": OK")
        else:
            reply = "UNKNOWN COMMAND"
        self.wfile.write(reply.encode("utf-8") + end)


class ClamdServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    server_bin = Path(os.environ.get("CLAMV_WEBUI_BIN", ROOT / "target/release/clamv-webui"))
    binary = Path(os.environ.get("CLAMCTL_BIN", ROOT / "cli/dist/linux_amd64/clamctl"))
    if not server_bin.is_file() or not binary.is_file():
        raise SystemExit("Build the server (cargo build --release) and the CLI before running this check.")
    with tempfile.TemporaryDirectory(prefix="clamctl-rust-") as name, ClamdServer(("127.0.0.1", 0), Clamd) as clamd:
        folder = Path(name)
        scan = folder / "scan"
        scan.mkdir()
        sample = scan / "clean.txt"
        sample.write_text("clean path validation")
        password = "ClamctlIsolatedIntegrationAdmin456"
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAMAV_", "OIDC_", "LDAP_", "WEBHOOK_"))}
        env.update({"DATA_DIR": str(folder / "data"), "LISTEN_ADDR": f"127.0.0.1:{port}",
                    "CLAMD_ENDPOINT": f"tcp://127.0.0.1:{clamd.server_address[1]}", "SCAN_ROOTS": str(scan),
                    "BOOTSTRAP_ADMIN_PASSWORD": password, "LOG_FORMAT": "json"})
        threading.Thread(target=clamd.serve_forever, daemon=True).start()
        with (folder / "server.log").open("w+") as log:
            application = subprocess.Popen([str(server_bin)], cwd=folder, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                server = f"http://127.0.0.1:{port}"
                deadline = time.monotonic() + 30
                while True:
                    if application.poll() is not None or time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError("server did not start:\n" + log.read()[-6000:])
                    try:
                        with urllib.request.urlopen(server + "/healthz", timeout=1) as response:
                            if response.status == 200:
                                break
                    except OSError:
                        time.sleep(0.2)
                env.update({"CLAMCTL_INTEGRATION_SERVER": server, "CLAMCTL_INTEGRATION_BINARY": str(binary),
                            "CLAMCTL_INTEGRATION_PASSWORD": password, "CLAMCTL_INTEGRATION_SCAN_PATH": str(sample),
                            "GOTOOLCHAIN": os.environ.get("GOTOOLCHAIN", "local")})
                subprocess.run([os.environ.get("CLAMCTL_GO", "go"), "test", "-count=1", "-run", "^TestSpringApplication$", "-v",
                                "./internal/cli"], cwd=ROOT / "cli", env=env, check=True, timeout=300)
            except BaseException:
                log.seek(0)
                print("---- server log (tail) ----\n" + log.read()[-4000:])
                raise
            finally:
                application.terminate()
                try:
                    application.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    application.kill()
                    application.wait(timeout=5)
                clamd.shutdown()


if __name__ == "__main__":
    main()
