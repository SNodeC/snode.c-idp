"""Explicit direct-TLS checks using the actual packaged IDP and example executables."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request
import ssl


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--idp', required=True)
    parser.add_argument('--app', required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    args = parser.parse_args()
    root = args.work_dir.resolve()
    root.mkdir(parents=True, exist_ok=False)
    with ExitStack() as stack:
        reservations = [stack.enter_context(socket.socket()) for _ in range(3)]
        for listener in reservations:
            listener.bind(('127.0.0.1', 0))
        idp_port, app_port, http_port = [listener.getsockname()[1] for listener in reservations]
    for command in [
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
         '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(root / 'tls.key'), '-out', str(root / 'tls.pem')],
        ['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(root / 'signing.pem')],
        ['openssl', 'pkey', '-in', str(root / 'signing.pem'), '-pubout', '-out', str(root / 'public.pem')],
        ['openssl', 'rand', '-out', str(root / 'totp.key'), '32'],
    ]:
        subprocess.run(command, capture_output=True, check=True)
    (root / 'empty.conf').touch()
    idp, app = f'https://localhost:{idp_port}', f'https://127.0.0.1:{app_port}'
    env = os.environ | dict(
        IDP_BASE_URL=idp, IDP_ISSUER=idp, IDP_PORT=str(idp_port), HTTP_PORT=str(http_port),
        HTTP_REDIRECTS=json.dumps({'localhost': idp, '127.0.0.1': app}), HOST_REDIRECTS='{}',
        IDP_PRIVATE_KEY_PATH=str(root / 'signing.pem'), IDP_PUBLIC_KEY_PATH=str(root / 'public.pem'),
        DB_PATH=str(root / 'auth.db'), TOTP_KEY_PATH=str(root / 'totp.key'),
        IDP_CLIENTS=json.dumps({'live-app': [app + '/auth/callback']}),
        APP_CLIENT_ID='live-app', APP_CALLBACK_URL=app + '/auth/callback', APP_PORT=str(app_port),
        SMTP_COMMAND='', OAUTH_GOOGLE_CLIENT_ID='', OAUTH_GOOGLE_CLIENT_SECRET='',
        XDG_CONFIG_HOME=str(root / 'config'), XDG_STATE_HOME=str(root / 'state'))
    context = ssl.create_default_context(cafile=str(root / 'tls.pem'))

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
    def get(url, headers=None):
        try:
            response = opener.open(urllib.request.Request(url, headers=headers or {}), timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        return response

    with ExitStack() as stack:
        for binary, instance, directory in [
            (args.idp, 'IdpServer', root),
            (args.app, 'MinimalMfaApp', Path(__file__).resolve().parents[1] / 'examples/minimal-mfa-app'),
        ]:
            command = [str(Path(binary).resolve()), '--config-file', str(root / 'empty.conf'),
                       instance, 'local', '--host', '127.0.0.1', 'tls', '--cert', str(root / 'tls.pem'),
                       '--cert-key', str(root / 'tls.key')]
            if instance == 'IdpServer':
                command += ['IdpHttp', 'local', '--host', '127.0.0.1']
            log = stack.enter_context((root / (instance + '.log')).open('w'))
            process = subprocess.Popen(command, env=env, cwd=directory, stdout=log, stderr=subprocess.STDOUT)
            def stop(child=process):
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            stack.callback(stop)
        deadline, ready = time.monotonic() + 15, False
        while not ready and time.monotonic() < deadline:
            try:
                with get(idp + '/health') as response:
                    ready = response.status == 200
            except OSError:
                time.sleep(0.05)
        assert ready, 'Direct IDP TLS did not start; inspect ' + str(root)
        subprocess.run(['sh', str(Path(__file__).resolve().parents[1] / 'scripts/healthcheck.sh')],
                       env=env | {'CURL_CA_BUNDLE': str(root / 'tls.pem')}, capture_output=True, check=True)
        with get(app + '/') as response:
            assert response.status == 308 and response.headers['Location'] == '/index.html'
        with get(app + '/index.html') as response:
            assert response.status == 200
        with get(app + '/private') as response:
            assert response.status in (302, 303)
            assert response.headers['Location'].startswith(idp + '/oauth2/authorize?')
        with get(idp + '/auth/login') as response:
            assert response.status == 200
        for host, destination in [('localhost', idp), ('127.0.0.1', app)]:
            with get(f'http://127.0.0.1:{http_port}/auth/login?next=x', {'Host': host}) as response:
                assert response.status == 308
                assert response.headers['Location'] == destination + '/auth/login?next=x'
        with get(f'http://127.0.0.1:{http_port}/', {'Host': 'unknown.example'}) as response:
            assert response.status == 404
        with get(idp + '/health', {'Host': 'unknown.example'}) as response:
            assert response.status == 404
    print('Direct trusted IDP/app TLS, authorization redirect, VHost isolation and HTTP redirects passed; listeners stopped.')


if __name__ == '__main__':
    main()
