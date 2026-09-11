#!/usr/bin/env python3
# Checkmk special agent for Palo Alto Networks firewalls (PAN-OS XML API)
# License: GNU General Public License v2 - see LICENSE
"""A stand-in for the PAN-OS XML API, for testing without a firewall.

Serves the canned responses from ``panos_fixtures`` over HTTPS with a
self-signed certificate, so the special agent can be pointed at it exactly as
it would be pointed at a real device:

    python3 tests/panos_api_stub.py --port 8443 &
    agent_paloalto_api --host 127.0.0.1 --port 8443 --api-key TEST --no-cert-check

Only the parts of the API the agent uses are implemented: ``type=op`` and
``type=keygen``. A request without the expected API key is answered with the
same error PAN-OS returns, so the failure path can be tested too.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import html
import ssl
import subprocess
import sys
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from panos_fixtures import RESPONSES

API_KEY = "TESTKEY"

# Commands the agent may send that the fixtures deliberately do not answer.
# GlobalProtect is optional on a real firewall, so 'Invalid command' has to be
# reproducible here as well.
UNSUPPORTED: tuple[str, ...] = ()


def _make_self_signed_cert(directory: Path) -> tuple[Path, Path]:
    cert = directory / "stub.pem"
    key = directory / "stub.key"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=panos-stub",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


class Handler(BaseHTTPRequestHandler):
    server_version = "PanOSStub/1.0"

    def _send(self, body: str, status: int = 200) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, code: str, message: str) -> None:
        self._send(
            f'<response status="error" code="{code}">'
            f"<msg><line>{html.escape(message)}</line></msg></response>"
        )

    # Name required by BaseHTTPRequestHandler.
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.rstrip("/") != "/api":
            self._send("<html><body>PAN-OS stub</body></html>", status=404)
            return

        query = urllib.parse.parse_qs(parsed.query)
        request_type = (query.get("type") or [""])[0]

        if request_type == "keygen":
            self._send(
                f'<response status="success"><result><key>{API_KEY}</key></result></response>'
            )
            return

        # The agent sends the key in the header, never in the URL.
        if self.headers.get("X-PAN-KEY") != API_KEY:
            self._error("403", "Invalid Credential")
            return

        if request_type != "op":
            self._error("400", f"Unsupported request type '{request_type}'")
            return

        cmd = (query.get("cmd") or [""])[0]
        for fragment in UNSUPPORTED:
            if cmd.startswith(fragment):
                self._error("400", "Invalid command")
                return
        for fragment, xml in RESPONSES.items():
            if cmd.startswith(fragment):
                self._send(f'<response status="success"><result>{xml}</result></response>')
                return
        self._error("400", f"Invalid command: {cmd[:120]}")

    def log_message(self, fmt: str, *args) -> None:
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        sys.stderr.write(f"[{stamp}] {fmt % args}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PAN-OS XML API stub")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument(
        "--no-globalprotect",
        action="store_true",
        help="answer the GlobalProtect command with 'Invalid command', as a "
        "firewall without GP gateways does",
    )
    args = parser.parse_args(argv)

    if args.no_globalprotect:
        global UNSUPPORTED
        UNSUPPORTED = ("<show><global-protect-gateway>",)

    with tempfile.TemporaryDirectory() as tmp:
        cert, key = _make_self_signed_cert(Path(tmp))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)

        server = ThreadingHTTPServer((args.bind, args.port), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        sys.stderr.write(
            f"PAN-OS stub listening on https://{args.bind}:{args.port}/api/ (API key: {API_KEY})\n"
        )
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
