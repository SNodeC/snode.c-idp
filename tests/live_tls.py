"""Exercise the real SNode.C HTTP/TLS transport against loopback servers.
Usage: python live_tls.py --probe BINARY --work-dir FRESH_DIRECTORY
"""

import argparse
import http.server
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import threading
import time


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/disconnect":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
        elif self.path == "/timeout":
            time.sleep(12)
        else:
            body = b"x" * (1048577 if self.path == "/oversized" else 2)
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("Location", "/ok")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / "tmp").mkdir()
    os.environ["TMPDIR"] = str(root / "tmp")
    os.umask(0o077)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(root / "key.pem"),
            "-out",
            str(root / "cert.pem"),
        ],
        check=True,
        capture_output=True,
    )
    (root / "empty.conf").touch()
    (root / "empty-ca").mkdir()
    servers = []
    results = []
    try:
        for secure in [False, True]:
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.daemon_threads = True
            if secure:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(root / "cert.pem", root / "key.pem")
                server.socket = context.wrap_socket(server.socket, server_side=True)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        http_port, tls_port = [s.server_port for s in servers]
        cases = [
            ("HTTP success", f"http://localhost:{http_port}/ok", True, 200),
            ("Trusted TLS and hostname", f"https://localhost:{tls_port}/ok", True, 200),
            ("TLS hostname mismatch", f"https://127.0.0.1:{tls_port}/ok", True, 0),
            ("Untrusted TLS certificate", f"https://localhost:{tls_port}/ok", False, 0),
            (
                "Redirect is not followed",
                f"http://localhost:{http_port}/redirect",
                True,
                302,
            ),
            (
                "Oversized response rejected",
                f"http://localhost:{http_port}/oversized",
                True,
                0,
            ),
            (
                "Peer disconnect completes once",
                f"http://localhost:{http_port}/disconnect",
                True,
                0,
            ),
            (
                "Read timeout completes once",
                f"http://localhost:{http_port}/timeout",
                True,
                0,
            ),
        ]
        for name, url, trusted, expected in cases:
            started = time.monotonic()
            try:
                env = dict(
                    os.environ,
                    TEST_URL=url,
                    XDG_CONFIG_HOME=str(root / "config"),
                    XDG_STATE_HOME=str(root / "state"),
                    SSL_CERT_FILE=(
                        str(root / "cert.pem") if trusted else str(root / "missing.pem")
                    ),
                    SSL_CERT_DIR=str(root / "empty-ca"),
                )
                run = subprocess.run(
                    [args.probe, "--config-file", str(root / "empty.conf")],
                    env=env,
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                result = re.search(r"RESULT (\d+) (\d+)", run.stdout)
                assert (
                    run.returncode == 0
                    and result
                    and (int(result[1]), int(result[2])) == (expected, 1)
                ), (
                    "Unexpected transport result: "
                    + run.stdout[-700:]
                    + run.stderr[-700:]
                )
                results.append(
                    dict(
                        test=name,
                        status="passed",
                        seconds=round(time.monotonic() - started, 3),
                    )
                )
            except Exception as error:
                results.append(dict(test=name, status="failed", error=str(error)))
            print(json.dumps(results[-1]), flush=True)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return int(any(r["status"] != "passed" for r in results))


if __name__ == "__main__":
    raise SystemExit(main())
