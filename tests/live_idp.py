"""Explicit installed-router isolation/lifetime test; never run implicitly by CTest."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import time

import requests


def port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        value = listener.getsockname()[1]
    return value


def register(origin, password):
    session = requests.Session()
    response = session.get(origin + "/auth/register", timeout=5)
    transaction = re.search(r'name="transaction" value="([^"]+)"', response.text)[1]
    response = session.post(
        origin + "/auth/register",
        data=dict(
            username="isolated",
            email="isolated@example.test",
            password=password,
            confirm_password=password,
            transaction=transaction,
        ),
        headers={"Origin": origin},
        allow_redirects=False,
        timeout=5,
    )
    assert response.status_code == 302, response.status_code
    assert "snodec_session" in session.cookies
    return session


def login(origin, password):
    session = requests.Session()
    response = session.get(origin + "/auth/login", timeout=5)
    transaction = re.search(r'name="transaction" value="([^"]+)"', response.text)[1]
    response = session.post(
        origin + "/auth/login",
        data=dict(username="isolated", password=password, transaction=transaction),
        headers={"Origin": origin},
        allow_redirects=False,
        timeout=5,
    )
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    os.umask(0o077)
    configurations = []
    for index in range(2):
        directory = root / str(index)
        directory.mkdir()
        for command in [
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
                str(directory / "private.pem"),
            ],
            ["openssl", "rand", "-out", str(directory / "totp.key"), "32"],
        ]:
            subprocess.run(command, check=True, capture_output=True)
        number = port()
        configurations.append(
            dict(
                name="Idp" + str(index),
                port=number,
                issuer="http://localhost:" + str(number),
                clients={"client-" + str(index): ["http://localhost:8099/callback"]},
                databasePath=str(directory / "auth.db"),
                privateKeyPath=str(directory / "private.pem"),
                totpKeyPath=str(directory / "totp.key"),
                smtpCommand="cat > " + shlex.quote(str(directory / "mail.eml")),
            )
        )
    (root / "config.json").write_text(json.dumps(configurations))
    (root / "empty.conf").touch()
    # These must not override explicitly constructed middleware configuration.
    env = dict(
        os.environ,
        TEST_IDP_CONFIG=str(root / "config.json"),
        IDP_ISSUER="invalid",
        IDP_BASE_URL="invalid",
        DB_PATH="/nonexistent/auth.db",
        TOTP_KEY_PATH="/nonexistent/key",
        SMTP_COMMAND="false",
        OAUTH_GOOGLE_CLIENT_ID="invalid",
        OAUTH_GOOGLE_CLIENT_SECRET="invalid",
        XDG_CONFIG_HOME=str(root / "config"),
        XDG_STATE_HOME=str(root / "state"),
    )
    command = [args.server, "--config-file", str(root / "empty.conf")]
    for entry in configurations:
        command += [entry["name"], "local", "--host", "127.0.0.1"]
    log = (root / "server.log").open("w")
    process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
    results = []
    try:
        deadline = time.monotonic() + 15
        ready = False
        while not ready and time.monotonic() < deadline:
            try:
                ready = all(
                    requests.get(c["issuer"] + "/health", timeout=1).status_code == 200
                    for c in configurations
                )
            except requests.RequestException:
                time.sleep(0.1)
        assert ready, "Two middleware instances did not start"
        sessions = []
        keys = []
        for index, entry in enumerate(configurations):
            origin = entry["issuer"]
            for method in ["GET", "POST"]:
                response = requests.request(
                    method,
                    origin + "/auth/login",
                    headers={"Host": "unconfigured.example"},
                    timeout=5,
                )
                assert (
                    response.status_code == 200 and response.text == "downstream router"
                )
                assert "Cache-Control" not in response.headers
            for method, path in [
                ("GET", "/downstream"),
                ("POST", "/downstream"),
                ("OPTIONS", "/downstream"),
                ("DELETE", "/downstream"),
                ("GET", "/oauth2/token"),
                ("POST", "/health"),
                ("POST", "/unclaimed"),
            ]:
                response = requests.request(method, origin + path, timeout=5)
                assert response.status_code == (404 if path == "/unclaimed" else 200), (
                    method,
                    path,
                    response.status_code,
                )
                assert response.text == "downstream router"
                for header in [
                    "Cache-Control",
                    "Referrer-Policy",
                    "X-Content-Type-Options",
                    "Content-Security-Policy",
                    "Set-Cookie",
                ]:
                    assert header not in response.headers, (method, path, header)
            for path, headers in [
                ("/auth/login", {}),
                ("/auth/register", {"Origin": "https://untrusted.example"}),
                ("/oauth2/token", {"Cookie": "session=untrusted"}),
                ("/oauth2/introspect", {"Cookie": "session=untrusted"}),
            ]:
                response = requests.post(origin + path, headers=headers, timeout=5)
                assert response.status_code == 403, (path, response.status_code)
                assert response.headers["Cache-Control"] == "no-store"
            results.append(
                "unmatched methods/paths reach downstream router untouched; matched IDP routes retain origin checks"
            )
            discovery = requests.get(
                origin + "/.well-known/openid-configuration", timeout=5
            ).json()
            assert discovery["issuer"] == origin
            keys.append(
                requests.get(origin + "/.well-known/jwks.json", timeout=5).json()
            )
            probe = requests.Session()
            parameters = dict(
                client_id="client-" + str(index),
                redirect_uri="http://localhost:8099/callback",
                response_type="code",
                code_challenge_method="S256",
                code_challenge="A" * 43,
                state="isolation",
            )
            assert (
                probe.get(
                    origin + "/oauth2/authorize",
                    params=parameters,
                    allow_redirects=False,
                    timeout=5,
                ).status_code
                == 302
            )
            parameters["client_id"] = "client-" + str(1 - index)
            assert (
                probe.get(
                    origin + "/oauth2/authorize",
                    params=parameters,
                    allow_redirects=False,
                    timeout=5,
                ).status_code
                == 400
            )
            assert (
                probe.get(
                    origin + "/auth/federated/google", allow_redirects=False, timeout=5
                ).status_code
                == 400
            )
            sessions.append(register(origin, "Password-for-instance-" + str(index)))
            target = "http://localhost:8099/app-" + str(index)
            parameters = {"client_id": "client-" + str(index), "return": target}
            page = sessions[-1].get(origin + "/settings", params=parameters, timeout=5)
            assert page.status_code == 200 and target in page.text
            parameters["client_id"] = "client-" + str(1 - index)
            assert sessions[-1].get(origin + "/settings", params=parameters, timeout=5).status_code == 400
            assert "Back to application" not in sessions[-1].get(origin + "/settings", timeout=5).text
        assert keys[0] != keys[1]
        results.append(
            "temporary middleware/configuration lifetime; independent issuer, keys, databases, clients, navigation and provider configuration"
        )
        cross = requests.get(
            configurations[1]["issuer"] + "/settings",
            cookies=sessions[0].cookies,
            allow_redirects=False,
            timeout=5,
        )
        assert cross.status_code == 302 and cross.headers["Location"] == "/auth/login"
        results.append("session from first instance rejected by second")
        for _ in range(5):
            assert (
                login(configurations[0]["issuer"], "wrong-password").status_code == 401
            )
        assert (
            login(configurations[0]["issuer"], "Password-for-instance-0").status_code
            == 400
        )
        assert (
            login(configurations[1]["issuer"], "Password-for-instance-1").status_code
            == 302
        )
        results.append("rate limiter state isolated between instances")
        for entry in configurations:
            response = requests.post(
                entry["issuer"] + "/auth/forgot-password",
                data={"email": "isolated@example.test"},
                headers={"Origin": entry["issuer"]},
                timeout=5,
            )
            assert response.status_code == 200
        for index, entry in enumerate(configurations):
            message = (root / str(index) / "mail.eml").read_text()
            assert entry["issuer"] + "/auth/reset-password?token=" in message
            other = configurations[1 - index]["issuer"]
            assert other + "/auth/reset-password" not in message
        results.append("per-instance mail configuration and reset origin")
        sessions[0].post(
            configurations[0]["issuer"] + "/auth/logout",
            headers={"Origin": configurations[0]["issuer"]},
            timeout=5,
        )
        assert (
            sessions[1]
            .get(
                configurations[1]["issuer"] + "/settings",
                allow_redirects=False,
                timeout=5,
            )
            .status_code
            == 200
        )
        results.append("logout isolated between instances")
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()
        (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
