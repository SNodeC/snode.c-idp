"""Explicit loopback checks for the existing IDP host's VHost/redirect configuration."""

import argparse
from contextlib import contextmanager
import json
import os
import resource
from pathlib import Path
import socket
import subprocess
import time

import requests


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        number = listener.getsockname()[1]
    return number


@contextmanager
def running(command, env, log_path):
    with log_path.open("w") as log:
        process = subprocess.Popen(
            command, env=env, stdout=log, stderr=subprocess.STDOUT
        )
        try:
            deadline = time.monotonic() + 10
            ready = False
            while not ready and process.poll() is None and time.monotonic() < deadline:
                try:
                    ready = (
                        requests.get(
                            env["IDP_BASE_URL"] + "/health", timeout=1
                        ).status_code
                        == 200
                    )
                except requests.RequestException:
                    time.sleep(0.05)
            assert ready, "IDP did not become ready: " + str(log_path)
            yield
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--idp", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    for command in [
        [
            "openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
            "-out",
            str(root / "private.pem"),
        ],
        ["openssl", "rand", "-out", str(root / "totp.key"), "32"],
    ]:
        subprocess.run(command, check=True, capture_output=True)
    (root / "empty.conf").touch()
    origin = "http://localhost:" + str(free_port())
    env = dict(
        os.environ,
        IDP_BASE_URL=origin,
        IDP_ISSUER=origin,
        IDP_PORT=origin.rsplit(":", 1)[1],
        DB_PATH=str(root / "auth.db"),
        IDP_PRIVATE_KEY_PATH=str(root / "private.pem"),
        TOTP_KEY_PATH=str(root / "totp.key"),
        IDP_CLIENTS="{}",
        SMTP_COMMAND="",
        OAUTH_GOOGLE_CLIENT_ID="",
        OAUTH_GOOGLE_CLIENT_SECRET="",
        XDG_CONFIG_HOME=str(root / "config"),
        XDG_STATE_HOME=str(root / "state"),
    )
    env.pop("HOST_REDIRECTS", None)
    command = [
        args.idp,
        "--config-file",
        str(root / "empty.conf"),
        "IdpServer",
        "local",
        "--host",
        "127.0.0.1",
    ]
    results = []

    def check(name, operation):
        nonlocal origin
        origin = "http://localhost:" + str(free_port())
        env.update(
            IDP_BASE_URL=origin, IDP_ISSUER=origin, IDP_PORT=origin.rsplit(":", 1)[1]
        )
        try:
            operation()
            results.append(dict(test=name, status="passed"))
        except Exception as error:
            results.append(dict(test=name, status="failed", error=str(error)))
        print(json.dumps(results[-1]), flush=True)

    def defaults():
        with running(command, env, root / "default.log"):
            assert requests.get(origin + "/auth/register", timeout=5).status_code == 200
            for host in ["localhost", "localhost:" + env["IDP_PORT"]]:
                response = requests.get(
                    origin + "/health", headers={"Host": host}, timeout=5
                )
                assert (
                    response.status_code == 200
                    and response.json()["service"] == "snodec-idp"
                )
            assert requests.get(origin + "/missing", timeout=5).status_code == 404
            for path in ["/", "/health", "/auth/login", "/.well-known/jwks.json"]:
                response = requests.get(
                    origin + path,
                    headers={
                        "Host": "unknown.example",
                        "X-Forwarded-Host": "localhost",
                    },
                    timeout=5,
                )
                assert (
                    response.status_code == 404 and "Location" not in response.headers
                )
            assert (
                requests.get(
                    origin + "/health",
                    headers={"Host": "localhost.evil.example"},
                    timeout=5,
                ).status_code
                == 404
            )

    check("default URLs and protocol paths preserved; unknown hosts rejected", defaults)

    def configured_redirects():
        destinations = {
            "client-"
            + str(i)
            + ".example": "https://app.example/landing/"
            + str(i)
            + "?configured=1"
            for i in range(32)
        }
        destinations["local-client.example"] = "http://localhost:8084/"
        mapped = dict(env, HOST_REDIRECTS=json.dumps(destinations))
        with running(command, mapped, root / "redirects.log"):
            for host, target in destinations.items():
                for method in ["GET", "POST", "HEAD"]:
                    response = requests.request(
                        method,
                        origin
                        + "/auth/login?return=https://attacker.example/&code=secret",
                        headers={
                            "Host": host + ":8080",
                            "Cookie": "snodec_session=irrelevant",
                        },
                        data="password=do-not-forward",
                        allow_redirects=False,
                        timeout=5,
                    )
                    assert (
                        response.status_code == 303
                        and response.headers["Location"] == target
                    )
                    assert response.headers["Cache-Control"] == "no-store"
                    assert response.headers["Referrer-Policy"] == "no-referrer"
                    assert "Set-Cookie" not in response.headers
            for host in ["client-0.example", "client-0.example:8080"]:
                response = requests.get(
                    origin + "/",
                    headers={"Host": host},
                    allow_redirects=False,
                    timeout=5,
                )
                assert response.status_code == 303
                assert response.headers["Location"] == destinations["client-0.example"]
            for host in [
                "unknown.example",
                "CLIENT-0.EXAMPLE",
                "client-0.example.evil",
                "client-0.example:8080:bad",
                "[::1]:8080",
            ]:
                response = requests.get(
                    origin + "/",
                    headers={"Host": host},
                    allow_redirects=False,
                    timeout=5,
                )
                assert response.status_code == 404
                assert "Location" not in response.headers
            assert requests.get(origin + "/health", timeout=5).status_code == 200

    check(
        "multiple fixed redirects, ports and methods; no IDP or request-data leakage",
        configured_redirects,
    )

    def invalid(specification, expected):
        bad = dict(
            env,
            HOST_REDIRECTS=specification,
            DB_PATH=str(root / "invalid-must-not-create.db"),
        )
        process = subprocess.Popen(
            command,
            env=bad,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            output, _ = process.communicate(timeout=10)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        assert process.returncode != 0 and expected in output
        assert not Path(
            bad["DB_PATH"]
        ).exists(), "Invalid routing configuration touched storage"

    for name, specification, expected in [
        ("non-object", "[]", "must be a JSON object"),
        ("malformed JSON", "{", "parse_error"),
        (
            "duplicate",
            '{"a.example":"https://one.example/","a.example":"https://two.example/"}',
            "Duplicate redirect hostname",
        ),
        (
            "case-duplicate",
            '{"a.example":"https://one.example/","A.EXAMPLE":"https://two.example/"}',
            "Duplicate redirect hostname",
        ),
        (
            "IDP conflict",
            '{"LOCALHOST":"https://one.example/"}',
            "conflict with IDP hostname",
        ),
        (
            "wildcard",
            '{"*.example":"https://one.example/"}',
            "Invalid redirect hostname",
        ),
        (
            "host port",
            '{"a.example:443":"https://one.example/"}',
            "Invalid redirect hostname",
        ),
        (
            "host scheme",
            '{"https://a.example":"https://one.example/"}',
            "Invalid redirect hostname",
        ),
        (
            "empty label",
            '{"a..example":"https://one.example/"}',
            "Invalid redirect hostname",
        ),
        (
            "long label",
            json.dumps({"a" * 64 + ".example": "https://one.example/"}),
            "Invalid redirect hostname",
        ),
        ("non-string target", '{"a.example":[]}', "must be a URL string"),
        ("relative target", '{"a.example":"/client"}', "Invalid HTTP endpoint"),
        (
            "script target",
            '{"a.example":"javascript:alert(1)"}',
            "Invalid HTTP endpoint",
        ),
        ("remote HTTP target", '{"a.example":"http://one.example/"}', "HTTPS required"),
        (
            "credentials in target",
            '{"a.example":"https://user:password@one.example/"}',
            "Invalid HTTP endpoint",
        ),
        (
            "header injection",
            json.dumps({"a.example": "https://one.example/\r\nX-Injected: yes"}),
            "Invalid HTTP endpoint",
        ),
    ]:
        check(
            "reject " + name,
            lambda spec=specification, reason=expected: invalid(spec, reason),
        )

    def public_health_probe():
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=idp.example", "-addext", "subjectAltName=DNS:idp.example,DNS:localhost",
            "-keyout", str(root / "tls.key"), "-out", str(root / "tls.pem"),
        ], check=True, capture_output=True)
        public = dict(
            env,
            CURL_CA_BUNDLE=str(root / "tls.pem"),
            IDP_BASE_URL="https://idp.example:" + env["IDP_PORT"],
            IDP_ISSUER="https://idp.example:" + env["IDP_PORT"],
            HOST_REDIRECTS="",
        )
        with (root / "public-health.log").open("w") as log:
            process = subprocess.Popen(
                command + ["tls", "--cert", str(root / "tls.pem"), "--cert-key", str(root / "tls.key")],
                env=public, stdout=log, stderr=subprocess.STDOUT
            )
            try:
                deadline = time.monotonic() + 10
                result = None
                while (
                    (result is None or result.returncode != 0)
                    and process.poll() is None
                    and time.monotonic() < deadline
                ):
                    result = subprocess.run(
                        [
                            "/bin/sh",
                            str(
                                Path(__file__).resolve().parents[1]
                                / "scripts/healthcheck.sh"
                            ),
                        ],
                        env=public,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode != 0:
                        time.sleep(0.05)
                assert result is not None and result.returncode == 0
                assert json.loads(result.stdout)["service"] == "snodec-idp"
                assert requests.get(origin.replace("http:", "https:") + "/health",
                                    verify=str(root / "tls.pem"), timeout=5).status_code == 404
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    check(
        "shared container health probe sends configured public Host",
        public_health_probe,
    )
    (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    assert all(
        result["status"] == "passed" for result in results
    ), "VHost test failures"


if __name__ == "__main__":
    main()
