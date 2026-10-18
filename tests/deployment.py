"""Deployment boundaries on disposable files; never issue certificates or start services."""
import importlib.util
import json
import io
import os
import pwd
import sqlite3
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deploy', ROOT / 'scripts/deploy.py')
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)


class DeploymentTest(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / 'packaging/deployment.example.json').read_text())
        self.config['accept_acme_terms'] = True

    def test_public_origins_and_registered_example(self):
        self.assertEqual(deploy.validate(self.config), ['app.example.org', 'core.snodec.org', 'core.vchrist.at'])
        for key, value in [('hostname', 'localhost'), ('hostname', 'bad;name.example'),
                           ('accept_acme_terms', False), ('google_client_secret', 'unpaired')]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                deploy.validate(self.config | {key: value})
        for callback in ['http://app.example.org/auth/callback', 'https://user@app.example.org/auth/callback',
                         'https://app.example.org/auth/callback#fragment', 'https://app.example.org:444/auth/callback']:
            with self.subTest(callback=callback), self.assertRaises(ValueError):
                deploy.validate(self.config | {'clients': {'minimal-mfa-app': [callback]}})
        with self.assertRaises(ValueError):
            deploy.validate(self.config | {'redirects': {'core.snodec.org': 'https://app.example.org/'}})

    def test_tls_proxy_preserves_host_and_origin_and_acme(self):
        bootstrap = deploy.nginx_config(self.config, False)
        site = deploy.nginx_config(self.config, True)
        self.assertIn('location ^~ /.well-known/acme-challenge/', bootstrap)
        self.assertIn('return 308 https://$host$request_uri;', bootstrap)
        self.assertNotIn('listen 443', bootstrap)
        self.assertIn('ssl_certificate /etc/letsencrypt/live/snodec-idp/fullchain.pem;', site)
        self.assertIn('proxy_set_header Host $host;', site)
        self.assertIn('proxy_set_header Origin $http_origin;', site)
        self.assertIn('proxy_pass http://127.0.0.1:8083;', site)
        self.assertIn('proxy_pass http://127.0.0.1:8084;', site)

    def test_first_provision_repeat_and_missing_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            public = deploy.provision_keys(root)
            keys = {p.name: p.read_bytes() for p in (root / 'keys').iterdir()}
            self.assertTrue(public.startswith('-----BEGIN PUBLIC KEY-----'))
            self.assertEqual(len(keys['totp.key']), 32)
            self.assertEqual(public, deploy.provision_keys(root))
            self.assertEqual(keys, {p.name: p.read_bytes() for p in (root / 'keys').iterdir()})
            (root / 'auth.db').touch()
            (root / 'keys/totp.key').unlink()
            with self.assertRaisesRegex(ValueError, 'original'):
                deploy.provision_keys(root)
            self.assertFalse((root / 'keys/totp.key').exists())

    def test_invalid_nginx_configuration_restores_previous_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'site.conf'
            path.write_text(deploy.MARKER + 'previous\n')
            with patch.object(deploy, 'SITE', path), patch.object(deploy, 'run', side_effect=subprocess.CalledProcessError(1, 'nginx')):
                with self.assertRaises(subprocess.CalledProcessError):
                    deploy.install_site(deploy.MARKER + 'invalid\n')
            self.assertEqual(path.read_text(), deploy.MARKER + 'previous\n')
            path.write_text('operator site\n')
            with patch.object(deploy, 'SITE', path), self.assertRaisesRegex(ValueError, 'unmanaged'):
                deploy.install_site('replacement')

    def test_deployment_restart_preserves_accounts_and_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            commands = []
            real_run, real_write = deploy.run, deploy.write
            def command(*args):
                commands.append(args)
                result = real_run(*args) if args[0] == 'openssl' else ''
                return result
            def write(path, content, mode=0o600):
                target = path if path.is_relative_to(root) else root / str(path).lstrip('/')
                real_write(target, content, mode)
            with patch.object(deploy, 'CONFIG', root / 'etc/config'), patch.object(deploy, 'DATA', root / 'data'), \
                 patch.object(deploy, 'WEBROOT', root / 'webroot'), patch.object(deploy, 'CERT', root / 'cert'), \
                 patch.object(deploy, 'SITE', root / 'site.conf'), patch.object(deploy, 'preflight', return_value='certbot.timer'), \
                 patch.object(deploy, 'run', side_effect=command), patch.object(deploy, 'write', side_effect=write), \
                 patch.object(deploy.pwd, 'getpwnam', return_value=pwd.getpwuid(os.getuid())), \
                 patch.object(deploy.urllib.request, 'urlopen', side_effect=lambda *args, **kwargs: io.BytesIO(b'{"status":"ok"}')):
                previous = os.umask(0o077)
                try:
                    deploy.deploy(self.config)
                    with sqlite3.connect(root / 'data/auth.db') as db:
                        db.execute('create table account (name text)')
                        db.execute("insert into account values ('preserve-me')")
                    original = {p.name: p.read_bytes() for p in (root / 'data/keys').iterdir()}
                    deploy.deploy(self.config)
                    self.assertEqual(original, {p.name: p.read_bytes() for p in (root / 'data/keys').iterdir()})
                    with sqlite3.connect(root / 'data/auth.db') as db:
                        self.assertEqual(db.execute('select name from account').fetchall(), [('preserve-me',)])
                    self.assertEqual((root / 'etc/config/idp.env').stat().st_mode & 0o777, 0o600)
                    self.assertEqual((root / 'webroot').stat().st_mode & 0o777, 0o755)
                    self.assertEqual(len(list((root / 'data/backups').iterdir())), 1)
                    self.assertTrue(any(c[:2] == ('certbot', 'certonly') and '--webroot' in c for c in commands))
                    self.assertIn(('systemctl', 'enable', '--now', 'certbot.timer'), commands)
                    hook = (root / 'etc/letsencrypt/renewal-hooks/deploy/snodec-idp').read_text()
                    self.assertIn('nginx -t\nsystemctl reload nginx', hook)
                finally:
                    os.umask(previous)

    def test_check_is_read_only_and_does_not_print_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'config.json'
            path.write_text(json.dumps(self.config | {'google_client_id': 'id', 'google_client_secret': 'DO-NOT-PRINT'}))
            result = subprocess.run(['python3', str(ROOT / 'scripts/deploy.py'), str(path), '--check'],
                                    capture_output=True, text=True, check=True)
            self.assertIn('Valid deployment', result.stdout)
            self.assertNotIn('DO-NOT-PRINT', result.stdout + result.stderr)
            self.assertEqual(list(Path(tmp).iterdir()), [path])


if __name__ == '__main__':
    unittest.main()
