"""Explicit loopback integration checks; never run by the normal build/CTest suite.

Usage: python live.py --work-dir DIR --idp BINARY --client BINARY
Requires requests, playwright (Chromium installed), and openssl. Uses fresh test
keys/accounts/database, a local mail sink, and closes its own processes on exit.
"""

import argparse
import base64
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import struct
import socket
import ssl
import sqlite3
import threading
import subprocess
import time
import traceback
from urllib.parse import parse_qs, urlparse, urlencode

import requests
from playwright.sync_api import sync_playwright

IDP = "http://localhost:18083"
APP = "http://localhost:18081"
SECOND = "http://127.0.0.1:18082"
PASSWORD = "Local-test-password-123!"


def totp(secret):
    digest = hmac.new(
        base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8)),
        struct.pack(">Q", int(time.time()) // 30),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 15
    return str(
        (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000
    ).zfill(6)


def reference(response):
    match = re.search(r'name="transaction" value="([^"]+)"', response.text)
    assert match, "No transaction form"
    return match[1]


def post(session, path, data):
    return session.post(
        IDP + path,
        data=data,
        headers={"Origin": IDP},
        allow_redirects=False,
        timeout=15,
    )


def registration(name, mfa=True, oauth=False):
    session = requests.Session()
    if oauth:
        session.get(APP + "/private", timeout=15)
    response = session.get(IDP + "/auth/register", timeout=15)
    response = post(
        session,
        "/auth/register",
        dict(
            transaction=reference(response),
            username=name,
            email=name + "@example.test",
            password=PASSWORD,
            confirm_password=PASSWORD,
            enable_mfa="1" if mfa else "0",
        ),
    )
    assert response.status_code == 302, "Registration rejected"
    secret = None
    if mfa:
        response = session.get(IDP + response.headers["Location"], timeout=15)
        secret = re.search(r"<p>([A-Z2-7]{16,})</p>", response.text)[1]
        response = post(
            session,
            "/auth/enroll/totp/verify",
            dict(transaction=reference(response), code=totp(secret)),
        )
        assert response.status_code == 302, "Enrollment rejected"
    if oauth:
        response = session.get(response.headers["Location"], timeout=15)
        assert response.status_code == (200 if mfa else 401), (
            "Unexpected application authorization: "
            + str(response.status_code)
            + " "
            + response.text[:100]
        )
    return session, secret


def token(session, host="localhost"):
    return next(
        c.value
        for c in session.cookies
        if c.name == "access_token" and c.domain.startswith(host)
    )


def api(origin, credential):
    return requests.get(
        origin + "/api", headers={"Authorization": "Bearer " + credential}, timeout=15
    )


def browser_flow(browser):
    context = browser.new_context()
    page = context.new_page()
    page.set_default_timeout(15000)
    page.goto(APP + "/private")
    page.get_by_role("link", name="Register", exact=True).click()
    for name, value in [
        ("username", "browser-user"),
        ("email", "browser@example.test"),
        ("password", PASSWORD),
        ("confirm_password", PASSWORD),
    ]:
        page.locator("[name=" + name + "]").fill(value)
    with page.expect_request(lambda r: r.method == "POST") as sent:
        page.get_by_role("button", name="Register", exact=True).click()
    assert (
        sent.value.all_headers().get("origin") == IDP
    ), "Browser form lost its Origin: " + str(sent.value.all_headers().get("origin"))
    secret = next(
        p.strip()
        for p in page.locator("p").all_text_contents()
        if re.fullmatch("[A-Z2-7]{16,}", p.strip())
    )
    page.locator("[name=code]").fill(totp(secret))
    page.get_by_role("button", name="Activate", exact=True).click()
    page.wait_for_url(APP + "/private")
    assert page.locator("body").inner_text() == "MFA authorized"
    cookies = context.cookies()
    access = next(c for c in cookies if c["name"] == "access_token")
    assert access["httpOnly"] and access["sameSite"] == "Lax"
    assert access["secure"] == APP.startswith("https://")
    assert "access_token" not in page.evaluate(
        "document.cookie"
    ), "Credential visible to script"
    assert not any(
        c["name"].startswith("oauth_") for c in cookies
    ), "Transaction cookie not consumed"
    first = access["value"]
    assert api(APP, first).status_code == 200
    page.goto(SECOND + "/private")
    page.wait_for_url(SECOND + "/private")
    second = next(
        c["value"]
        for c in context.cookies()
        if c["name"] == "access_token" and c["domain"] == "127.0.0.1"
    )
    assert api(SECOND, second).status_code == 200
    page.goto(IDP + "/auth/logout")
    page.get_by_role("button", name="Sign out", exact=True).click()
    assert api(APP, first).status_code == 401 and api(SECOND, second).status_code == 401
    page.goto(APP + "/private")
    page.wait_for_url(IDP + "/auth/login")
    assert page.locator("input[name=password]").is_visible()
    assert not any(c["name"] == "access_token" for c in context.cookies(APP))
    page.locator("[name=username]").fill("browser-user")
    page.locator("[name=password]").fill(PASSWORD)
    page.get_by_role("button", name="Sign in", exact=True).click()
    page.locator("[name=code]").fill(totp(secret))
    page.get_by_role("button", name="Verify", exact=True).click()
    page.wait_for_url(APP + "/private")
    assert page.locator("body").inner_text() == "MFA authorized"
    context.close()


def account_navigation(browser):
    context = browser.new_context()
    first = context.new_page()
    first.set_default_timeout(15000)
    # Registration and enrollment reached from settings retain the application's destination.
    first.goto(APP + "/account")
    first.get_by_role("link", name="Register", exact=True).click()
    for name, value in [("username", "navigation-user"), ("email", "navigation@example.test"),
                        ("password", PASSWORD), ("confirm_password", PASSWORD)]:
        first.locator("[name=" + name + "]").fill(value)
    first.get_by_role("button", name="Register", exact=True).click()
    secret = next(p.strip() for p in first.locator("p").all_text_contents()
                  if re.fullmatch("[A-Z2-7]{16,}", p.strip()))
    first.locator("[name=code]").fill(totp(secret))
    first.get_by_role("button", name="Activate", exact=True).click()
    first.wait_for_url(re.compile(re.escape(IDP + "/settings?")))
    target = APP + "/private?section=account&next=%2Fhome"
    back = first.get_by_role("link", name="Back to application", exact=True)
    assert back.get_attribute("href") == target
    second = context.new_page()
    second.goto(SECOND + "/account")
    other_target = SECOND + "/private?section=account&next=%2Fhome"
    assert second.get_by_role("link", name="Back to application", exact=True).get_attribute("href") == other_target
    # Forms, feedback redirects and subpage cancellation retain each tab's own destination.
    first.locator("[name=email]").fill("navigation-updated@example.test")
    first.get_by_role("button", name="Save Profile", exact=True).click()
    first.wait_for_url(re.compile("msg="))
    assert back.get_attribute("href") == target
    first.get_by_role("link", name="Delete", exact=True).click()
    first.locator("[name=confirm_username]").fill("wrong-name")
    first.locator("[name=password]").fill(PASSWORD)
    first.locator("[name=code]").fill(totp(secret))
    first.get_by_role("button", name="Delete my account permanently", exact=True).click()
    assert "username did not match" in first.locator("body").inner_text()
    assert back.get_attribute("href") == target
    first.get_by_role("link", name="Cancel", exact=True).click()
    first.get_by_role("link", name="Disable", exact=True).click()
    first.get_by_role("link", name="Cancel and Return", exact=True).click()
    first.get_by_role("link", name="Dashboard", exact=True).click()
    first.get_by_role("link", name="Settings", exact=True).click()
    assert back.get_attribute("href") == target
    first.reload()
    assert back.get_attribute("href") == target
    second.get_by_role("link", name="Back to application", exact=True).click()
    second.wait_for_url(other_target)
    assert second.locator("body").inner_text() == "MFA authorized"
    back.click()
    first.wait_for_url(target)
    assert first.locator("body").inner_text() == "MFA authorized"
    first.goto(IDP + "/settings")
    assert first.get_by_role("link", name="Back to application", exact=True).count() == 0
    # Reject foreign origins, client swaps and unsafe URL forms before any profile mutation.
    for client, destination in [("live-app", SECOND + "/private"), ("unknown", target),
                                ("live-app", "https://evil.example/private"),
                                ("live-app", "javascript:alert(1)"), ("live-app", "//evil.example")]:
        response = first.goto(IDP + "/settings?" + urlencode({"client_id": client, "return": destination}))
        assert response.status == 400
    first.goto(APP + "/account")
    response = first.evaluate("""async (target) => {
        const query = new URLSearchParams({client_id: 'live-app', return: 'https://evil.example/'});
        const body = new URLSearchParams({username: 'navigation-user', email: 'changed@example.test'});
        return (await fetch('/settings/profile?' + query, {method: 'POST', body})).status;
    }""", target)
    assert response == 400
    first.reload()
    assert first.locator("[name=email]").input_value() == "navigation-updated@example.test"
    # Disabling MFA revokes the session; optional enrollment and skip keep the return journey.
    first.get_by_role("link", name="Disable", exact=True).click()
    first.locator("[name=password]").fill(PASSWORD)
    first.locator("[name=code]").fill(totp(secret))
    first.get_by_role("button", name="Verify & Disable MFA", exact=True).click()
    first.locator("[name=username]").fill("navigation-user")
    first.locator("[name=password]").fill(PASSWORD)
    first.get_by_role("button", name="Sign in", exact=True).click()
    first.get_by_role("link", name="Enable", exact=True).click()
    assert first.get_by_role("button", name="Skip", exact=True).evaluate("el => getComputedStyle(el).backgroundColor") == "rgba(0, 0, 0, 0)"
    first.get_by_role("button", name="Skip", exact=True).click()
    assert back.get_attribute("href") == target
    first.get_by_role("link", name="Enable", exact=True).click()
    secret = next(p.strip() for p in first.locator("p").all_text_contents()
                  if re.fullmatch("[A-Z2-7]{16,}", p.strip()))
    first.locator("[name=code]").fill(totp(secret))
    first.get_by_role("button", name="Activate", exact=True).click()
    assert back.get_attribute("href") == target
    # Password changes revoke sessions; reauthentication returns to settings with the link intact.
    first.locator("[name=current_password]").fill(PASSWORD)
    first.locator("[name=new_password]").fill(PASSWORD + "-changed")
    first.locator("[name=confirm_password]").fill(PASSWORD + "-changed")
    first.get_by_role("button", name="Change Password", exact=True).click()
    first.locator("[name=username]").fill("navigation-user")
    first.locator("[name=password]").fill(PASSWORD + "-changed")
    first.get_by_role("button", name="Sign in", exact=True).click()
    first.locator("[name=code]").fill(totp(secret))
    first.get_by_role("button", name="Verify", exact=True).click()
    first.wait_for_url(re.compile(re.escape(IDP + "/settings?")))
    assert back.get_attribute("href") == target
    context.close()


def binding():
    for method in ["GET", "HEAD"]:
        session = requests.Session()
        session.cookies.set(
            "access_token", "invalid", domain=urlparse(APP).hostname, path="/"
        )
        response = session.request(
            method, APP + "/private", allow_redirects=False, timeout=15
        )
        assert response.status_code == 302
        cookie_headers = response.raw.headers.getlist("Set-Cookie")
        assert any(
            h.startswith("access_token=") and "Max-Age=0" in h for h in cookie_headers
        )
        assert any(h.startswith("oauth_") for h in cookie_headers)
    for method, headers in [
        ("GET", {"Authorization": "Bearer invalid"}),
        ("POST", {"Origin": APP, "Cookie": "access_token=invalid"}),
    ]:
        response = requests.request(
            method, APP + "/private", headers=headers, allow_redirects=False, timeout=15
        )
        assert response.status_code == 401
        assert "Location" not in response.headers
    session = requests.Session()
    first = session.get(IDP + "/auth/login", timeout=15)
    transaction = reference(first)
    direct = post(
        session,
        "/auth/mfa",
        {"transaction": transaction, "user_id": "1", "code": "000000"},
    )
    assert direct.status_code == 400, "Direct MFA accepted without primary proof"
    other = requests.Session()
    assert (
        post(
            other,
            "/auth/login",
            dict(transaction=transaction, username="browser-user", password=PASSWORD),
        ).status_code
        == 400
    )
    flow = requests.get(APP + "/private", allow_redirects=False, timeout=15)
    authorize = flow.headers["Location"]
    session.get(authorize, timeout=15)
    stale = post(
        session,
        "/auth/login",
        dict(transaction=transaction, username="browser-user", password=PASSWORD),
    )
    assert stale.status_code == 400, "Stale form accepted"
    params = parse_qs(urlparse(authorize).query)
    params["redirect_uri"] = ["http://192.168.1.1/callback"]
    assert (
        requests.get(IDP + "/oauth2/authorize", params=params, timeout=15).status_code
        == 400
    )
    assert (
        requests.get(
            APP + "/auth/callback?code=forged&state=forged", timeout=15
        ).status_code
        == 401
    )
    assert (
        requests.post(
            IDP + "/auth/register",
            headers={"Origin": "https://evil.example"},
            timeout=15,
        ).status_code
        == 403
    )
    for provider in ["apple", "meta"]:
        assert (
            requests.get(IDP + "/auth/federated/" + provider, timeout=15).status_code
            == 404
        )
    assert session.get(IDP + "/auth/federated/google", timeout=15).status_code == 400


def password_and_mfa():
    session, secret = registration("password-flow")
    post(session, "/auth/logout", {})
    page = session.get(APP + "/private", timeout=15)
    response = post(
        session,
        "/auth/login",
        dict(
            transaction=reference(page), username="password-flow", password="incorrect"
        ),
    )
    assert response.status_code == 401
    response = post(
        session,
        "/auth/login",
        dict(
            transaction=reference(response), username="password-flow", password=PASSWORD
        ),
    )
    assert "Authenticator code" in response.text and not any(
        c.name == "snodec_session" for c in session.cookies
    )
    ref = reference(response)
    wrong = post(session, "/auth/mfa", dict(transaction=ref, code="not-a-code"))
    assert wrong.status_code == 401
    response = post(session, "/auth/mfa", dict(transaction=ref, code=totp(secret)))
    assert response.status_code == 302
    callback = response.headers["Location"]
    assert session.get(callback, timeout=15).status_code == 200
    assert session.get(callback, timeout=15).status_code == 401
    assert session.get(
        IDP + "/oauth2/userinfo",
        headers={"Authorization": "Bearer " + token(session)},
        timeout=15,
    ).json()["sub"]
    single, _ = registration("password-only", mfa=False, oauth=True)
    assert not any(
        c.name == "access_token" for c in single.cookies
    ), "Rejected password-only cookie retained"


def reset_and_security_changes(root):
    session, _ = registration("reset-user", oauth=True)
    credential = token(session)
    response = post(
        session, "/auth/forgot-password", {"email": "reset-user@example.test"}
    )
    unknown = post(session, "/auth/forgot-password", {"email": "unknown@example.test"})
    assert response.status_code == unknown.status_code and response.text == unknown.text
    message = (root / "mail.txt").read_text()
    reset_url = re.search(r"https?://\S+", message)[0]
    reset_token = parse_qs(urlparse(reset_url).query)["token"][0]
    assert (
        reset_token not in response.text
        and reset_token not in (root / "idp.log").read_text()
    )
    recovery = requests.Session()
    assert recovery.get(reset_url, timeout=15).status_code == 200
    response = post(
        recovery,
        "/auth/reset-password",
        dict(
            token=reset_token,
            password="Replacement-Password-123!",
            password_confirm="Replacement-Password-123!",
        ),
    )
    assert response.status_code == 200, "Reset rejected"
    assert api(APP, credential).status_code == 401
    assert (
        post(
            recovery,
            "/auth/reset-password",
            dict(
                token=reset_token,
                password="Replacement-Password-123!",
                password_confirm="Replacement-Password-123!",
            ),
        ).status_code
        == 400
    )
    session, secret = registration("disable-user", oauth=True)
    credential = token(session)
    assert (
        post(
            session, "/settings/mfa/disable", dict(password=PASSWORD, code=totp(secret))
        ).status_code
        == 302
    )
    assert api(APP, credential).status_code == 401
    session, secret = registration("delete-user", oauth=True)
    credential = token(session)
    assert (
        post(
            session,
            "/settings/delete",
            dict(confirm_username="delete-user", password=PASSWORD, code=totp(secret)),
        ).status_code
        == 302
    )
    assert api(APP, credential).status_code == 401
    session, _ = registration("change-user", oauth=True)
    credential = token(session)
    assert (
        post(
            session,
            "/settings/password",
            dict(
                current_password=PASSWORD,
                new_password="Changed-Password-123!",
                confirm_password="Changed-Password-123!",
            ),
        ).status_code
        == 302
    )
    assert api(APP, credential).status_code == 401


def grants():
    session, _ = registration("grant-user")
    verifier = "v" * 43
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    response = session.get(
        IDP + "/oauth2/authorize",
        params=dict(
            client_id="live-app",
            redirect_uri=APP + "/auth/callback",
            response_type="code",
            scope="openid profile email",
            state="state",
            nonce="nonce",
            code_challenge=challenge,
            code_challenge_method="S256",
        ),
        allow_redirects=False,
        timeout=15,
    )
    response = session.get(
        IDP + response.headers["Location"], allow_redirects=False, timeout=15
    )
    code = parse_qs(urlparse(response.headers["Location"]).query)["code"][0]
    data = dict(
        grant_type="authorization_code",
        code=code,
        client_id="live-app",
        redirect_uri=APP + "/auth/callback",
        code_verifier=verifier,
    )
    assert (
        requests.post(
            IDP + "/oauth2/token", data=dict(data, code_verifier="x" * 43), timeout=15
        ).status_code
        == 400
    )
    assert (
        requests.post(
            IDP + "/oauth2/token",
            data=dict(data, redirect_uri=APP + "/wrong"),
            timeout=15,
        ).status_code
        == 400
    )
    tokens = requests.post(IDP + "/oauth2/token", data=data, timeout=15).json()
    assert (
        requests.post(IDP + "/oauth2/token", data=data, timeout=15).status_code == 400
    )
    assert api(APP, tokens["access_token"]).status_code == 200
    refresh = dict(
        grant_type="refresh_token",
        refresh_token=tokens["refresh_token"],
        client_id="live-app",
    )
    assert (
        requests.post(IDP + "/oauth2/token", data=refresh, timeout=15).status_code
        == 200
    )
    assert (
        requests.post(IDP + "/oauth2/token", data=refresh, timeout=15).status_code
        == 400
    )
    assert api(APP, tokens["access_token"]).status_code == 401


def backup_restore(root, binary, env):
    _, secret = registration("restore-user")
    source = sqlite3.connect(root / "auth.db")
    restored = sqlite3.connect(root / "restored.db")
    source.backup(restored)
    assert restored.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert (
        source.execute("SELECT COUNT(*) FROM user").fetchone()
        == restored.execute("SELECT COUNT(*) FROM user").fetchone()
    )
    source.close()
    restored.close()
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    origin = "http://127.0.0.1:" + str(port)
    current = dict(
        env,
        IDP_BASE_URL=origin,
        IDP_ISSUER=origin,
        IDP_PORT=str(port),
        DB_PATH=str(root / "restored.db"),
    )
    with (root / "restore.log").open("w") as log:
        process = subprocess.Popen(
            [
                binary,
                "--config-file",
                str(root / "empty.conf"),
                "IdpServer",
                "local",
                "--host",
                "127.0.0.1",
            ],
            cwd=root,
            env=current,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            ready = False
            deadline = time.monotonic() + 15
            while not ready and time.monotonic() < deadline:
                try:
                    ready = (
                        requests.get(origin + "/health", timeout=1).status_code == 200
                    )
                except requests.RequestException:
                    time.sleep(0.1)
            assert ready, "Restored IDP failed to start"
            session = requests.Session()
            page = session.get(origin + "/auth/login", timeout=15)
            response = session.post(
                origin + "/auth/login",
                headers={"Origin": origin},
                data=dict(
                    transaction=reference(page),
                    username="restore-user",
                    password=PASSWORD,
                ),
                timeout=15,
            )
            assert "Authenticator code" in response.text, "Restored password failed"
            response = session.post(
                origin + "/auth/mfa",
                headers={"Origin": origin},
                data=dict(transaction=reference(response), code=totp(secret)),
                timeout=15,
            )
            assert (
                response.status_code == 200 and "restore-user" in response.text
            ), "Restored encrypted TOTP failed"
        finally:
            process.kill()
            process.wait(timeout=10)


class Proxy(http.server.BaseHTTPRequestHandler):
    def forward(self):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.backend, timeout=15
        )
        try:
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            headers = dict(self.headers)
            headers["Connection"] = "close"
            connection.request(self.command, self.path, body, headers)
            response = connection.getresponse()
            payload = response.read()
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in [
                    "connection",
                    "transfer-encoding",
                    "content-length",
                ]:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (OSError, http.client.HTTPException):
            self.send_error(502)
        finally:
            connection.close()

    do_GET = forward
    do_HEAD = forward
    do_POST = forward

    def log_message(self, *args):
        pass


def main():
    global IDP, APP, SECOND
    ports = []
    reservations = []
    for _ in range(6):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        ports.append(listener.getsockname()[1])
        reservations.append(listener)
    IDP, APP, SECOND = (
        "http://localhost:" + str(ports[0]),
        "http://localhost:" + str(ports[1]),
        "http://127.0.0.1:" + str(ports[2]),
    )
    for listener in reservations:
        listener.close()
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument(
        "--https",
        action="store_true",
        help="Use direct IDP TLS and loopback client TLS proxies with an isolated test certificate",
    )
    parser.add_argument("--idp", required=True)
    parser.add_argument("--client", required=True)
    args = parser.parse_args()
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=True)
    (root / "tmp").mkdir(exist_ok=True)
    os.environ["TMPDIR"] = str(root / "tmp")
    assert not (root / "auth.db").exists(), "Use a fresh test directory"
    os.umask(0o077)
    browser_args = ["--no-sandbox"]
    if args.https:
        IDP, APP, SECOND = [
            origin.replace("http:", "https:") for origin in [IDP, APP, SECOND]
        ]
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
        [
            "openssl",
            "pkey",
            "-in",
            str(root / "private.pem"),
            "-pubout",
            "-out",
            str(root / "public.pem"),
        ],
        ["openssl", "rand", "-out", str(root / "totp.key"), "32"],
    ]:
        subprocess.run(command, check=True, capture_output=True)
    if args.https:
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
                "subjectAltName=DNS:localhost,IP:127.0.0.1",
                "-keyout",
                str(root / "tls.key"),
                "-out",
                str(root / "tls.pem"),
            ],
            check=True,
            capture_output=True,
        )
        pem = subprocess.run(
            ["openssl", "x509", "-in", str(root / "tls.pem"), "-pubkey", "-noout"],
            check=True,
            capture_output=True,
        ).stdout
        der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            input=pem,
            check=True,
            capture_output=True,
        ).stdout
        browser_args.append(
            "--ignore-certificate-errors-spki-list="
            + base64.b64encode(hashlib.sha256(der).digest()).decode()
        )
        os.environ["REQUESTS_CA_BUNDLE"] = str(root / "tls.pem")
        os.environ["SSL_CERT_FILE"] = str(root / "tls.pem")
    (root / "empty.conf").touch()
    (root / "mail.py").write_text(
        "import sys\nfrom pathlib import Path\nPath("
        + repr(str(root / "mail.txt"))
        + ").write_text(sys.stdin.read())\n"
    )
    env = os.environ.copy()
    env.update(
        XDG_CONFIG_HOME=str(root / "config"),
        XDG_STATE_HOME=str(root / "state"),
        IDP_BASE_URL=IDP,
        HOST_REDIRECTS="",
        IDP_ISSUER=IDP,
        IDP_PORT=str(ports[0]),
        IDP_PRIVATE_KEY_PATH=str(root / "private.pem"),
        TOTP_KEY_PATH=str(root / "totp.key"),
        DB_PATH=str(root / "auth.db"),
        IDP_CLIENTS=json.dumps(
            {
                "live-app": [APP + "/auth/callback"],
                "second-app": [SECOND + "/auth/callback"],
            }
        ),
        SMTP_COMMAND="python3 " + str(root / "mail.py"),
        OAUTH_GOOGLE_CLIENT_ID="",
        OAUTH_GOOGLE_CLIENT_SECRET="",
    )
    for port in ports:
        with socket.socket() as probe:
            assert (
                probe.connect_ex(("127.0.0.1", port)) != 0
            ), "Test port already occupied: " + str(port)
    proxies = []
    processes = []
    logs = []
    results = []
    try:
        if args.https:
            for public, backend in zip(ports[1:3], ports[4:]):
                proxy = http.server.ThreadingHTTPServer(("127.0.0.1", public), Proxy)
                proxy.daemon_threads = True
                proxy.backend = backend
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(root / "tls.pem", root / "tls.key")
                proxy.socket = context.wrap_socket(proxy.socket, server_side=True)
                threading.Thread(target=proxy.serve_forever, daemon=True).start()
                proxies.append(proxy)
        for name, binary, instance, extra in [
            ("idp", args.idp, "IdpServer", {}),
            (
                "client",
                args.client,
                "LiveClient",
                dict(
                    TEST_CLIENT="live-app",
                    TEST_CALLBACK=APP + "/auth/callback",
                    TEST_PORT=str(ports[4] if args.https else ports[1]),
                ),
            ),
            (
                "second",
                args.client,
                "LiveClient",
                dict(
                    TEST_CLIENT="second-app",
                    TEST_CALLBACK=SECOND + "/auth/callback",
                    TEST_PORT=str(ports[5] if args.https else ports[2]),
                ),
            ),
        ]:
            log = (root / (name + ".log")).open("w")
            logs.append(log)
            current = dict(
                env, TEST_ISSUER=IDP, TEST_PUBLIC_KEY=str(root / "public.pem"), **extra
            )
            processes.append(
                subprocess.Popen(
                    [
                        binary,
                        "--config-file",
                        str(root / "empty.conf"),
                        instance,
                        "local",
                        "--host",
                        "127.0.0.1",
                    ] + (["tls", "--cert", str(root / "tls.pem"), "--cert-key", str(root / "tls.key")]
                         if name == "idp" and args.https else []),
                    cwd=root,
                    env=current,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
            )
        ready = False
        deadline = time.monotonic() + 15
        while not ready and time.monotonic() < deadline:
            try:
                ready = (
                    all(p.poll() is None for p in processes)
                    and requests.get(IDP + "/health", timeout=1).status_code == 200
                    and requests.get(APP + "/api", timeout=1).status_code == 401
                )
            except requests.RequestException:
                time.sleep(0.1)
        assert ready, "Test services failed to start"
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=browser_args)
            for name, test in [
                (
                    "browser registration, MFA, cookies, SSO and logout",
                    lambda: browser_flow(browser),
                ),
                ("binding, CSRF and disabled providers", binding),
                ("account return navigation and tab isolation", lambda: account_navigation(browser)),
                ("password and MFA login", password_and_mfa),
                (
                    "reset and account-security revocation",
                    lambda: reset_and_security_changes(root),
                ),
                ("OAuth grants and refresh replay", grants),
                (
                    "SQLite backup and live password/TOTP restore",
                    lambda: backup_restore(root, args.idp, env),
                ),
            ]:
                try:
                    test()
                    results.append({"test": name, "status": "passed"})
                except Exception as error:
                    traceback.print_exc()
                    results.append(
                        {"test": name, "status": "failed", "error": str(error)}
                    )
                print(json.dumps(results[-1]), flush=True)
            browser.close()
        try:
            session, _ = registration("outage-user", oauth=True)
            credential = token(session)
            processes[0].kill()
            processes[0].wait(timeout=10)
            assert api(APP, credential).status_code == 401
            response = session.get(APP + "/private", allow_redirects=False, timeout=15)
            assert response.status_code == 302
            assert response.headers["Location"].startswith(IDP + "/oauth2/authorize?")
            assert not any(c.name == "access_token" for c in session.cookies), [
                (c.name, c.domain, c.path, c.expires) for c in session.cookies
            ]
            results.append(
                {"test": "IDP outage denies API and browser access", "status": "passed"}
            )
        except Exception as error:
            results.append(
                {"test": "IDP outage", "status": "failed", "error": str(error)}
            )
        print(json.dumps(results[-1]), flush=True)
    finally:
        for proxy in proxies:
            proxy.shutdown()
            proxy.server_close()
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log in logs:
            log.close()
        (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    return int(any(result["status"] != "passed" for result in results))


if __name__ == "__main__":
    raise SystemExit(main())
