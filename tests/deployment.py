"""Deployment boundaries on disposable files; never issue certificates or start services."""
from contextlib import closing
import hashlib
import re
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

    def test_bootstrap_downloads_pinned_helper_and_cleans_up_on_failure(self):
        script = (ROOT / 'scripts/deploy-core-snodec-org.sh').read_text()
        helper = (ROOT / 'scripts/deploy.py').read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(helper)).encode() + b'\0' + helper).hexdigest()
        self.assertEqual(re.search(r'^helper_blob=(\w+)$', script, re.M).group(1), blob)
        # Exercise the actual download/install/launch sequence with fake external
        # commands. No root, package installation, network or services are needed.
        sequence = script[script.index('installer_directory=$(mktemp'):]
        for failure in (False, True):
            with self.subTest(download_failure=failure), tempfile.TemporaryDirectory() as tmp:
                harness = """set -eu
curl() {
    printf 'download %s\n' "$*" >> "$TEST_LOG"
    local status=0
    if [ "$FAIL_DOWNLOAD" = yes ]; then
        status=22
    else
        printf '# fixture\n' > "${@: -1}"
    fi
    return "$status"
}
sh() { printf 'install %s\n' "$*" >> "$TEST_LOG"; }
python3() {
    test -f "$1"
    printf 'launch %s\n' "$*" >> "$TEST_LOG"
}
""" + sequence
                log = Path(tmp) / 'commands'
                result = subprocess.run(['bash', '-c', harness], capture_output=True, text=True,
                    env=os.environ | {'TEST_LOG': str(log), 'FAIL_DOWNLOAD': 'yes' if failure else 'no'})
                commands = log.read_text()
                self.assertIn('/git/blobs/' + blob, commands)
                self.assertEqual(result.returncode, 22 if failure else 0, result.stderr)
                self.assertEqual('launch ' in commands, not failure)
                self.assertEqual('install ' in commands, not failure)
                temporary = re.search(r'--output (.+)/deploy.py', commands).group(1)
                self.assertFalse(Path(temporary).exists())

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

    def test_direct_origins_and_port_conflicts(self):
        self.assertEqual(deploy.http_targets(self.config), {
            'core.snodec.org': 'https://core.snodec.org:8088',
            'core.vchrist.at': 'https://core.vchrist.at:8088',
            'app.example.org': 'https://app.example.org'})
        for port in (0, 80, 443, 65536):
            with self.subTest(port=port), self.assertRaises(ValueError):
                deploy.validate(self.config | {'idp_port': port})
        config = self.config | {'example': self.config['example'] | {'port': 8443},
                               'clients': {'minimal-mfa-app': ['https://app.example.org:8443/auth/callback']}}
        deploy.validate(config)
        self.assertEqual(deploy.http_targets(config)['app.example.org'], 'https://app.example.org:8443')

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

    def test_proxy_configuration_is_rejected_before_mutation(self):
        with self.assertRaisesRegex(ValueError, 'terminate TLS directly'):
            deploy.validate(self.config | {'tls': {'mode': 'proxy'}})

    def test_deployment_restart_preserves_accounts_and_keys(self):
        for mode in ('letsencrypt', 'files'):
            config = self.config | {'tls': {'mode': mode}}
            if mode == 'files':
                config['tls'].update(certificate='/etc/ssl/cert.pem', private_key='/etc/ssl/key.pem')
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
                     patch.object(deploy, 'SYSTEMD', root / 'systemd'), patch.object(deploy, 'CERT', root / 'cert'), \
                     patch.object(deploy, 'check_certificates'), patch.object(deploy, 'preflight', return_value='certbot.timer' if mode == 'letsencrypt' else None), \
                     patch.object(deploy, 'run', side_effect=command), patch.object(deploy, 'write', side_effect=write), \
                     patch.object(deploy.pwd, 'getpwnam', return_value=pwd.getpwuid(os.getuid())), \
                     patch.object(deploy.urllib.request, 'urlopen', side_effect=lambda *args, **kwargs: io.BytesIO(b'{"status":"ok"}')):
                    previous = os.umask(0o077)
                    try:
                        deploy.deploy(config)
                        with closing(sqlite3.connect(root / 'data/auth.db')) as db:
                            db.execute('create table account (name text)')
                            db.execute("insert into account values ('preserve-me')")
                            db.commit()
                        original = {p.name: p.read_bytes() for p in (root / 'data/keys').iterdir()}
                        deploy.deploy(config)
                        self.assertEqual(original, {p.name: p.read_bytes() for p in (root / 'data/keys').iterdir()})
                        with closing(sqlite3.connect(root / 'data/auth.db')) as db:
                            self.assertEqual(db.execute('select name from account').fetchall(), [('preserve-me',)])
                        self.assertEqual((root / 'etc/config/idp.env').stat().st_mode & 0o777, 0o600)
                        self.assertEqual(len(list((root / 'data/backups').iterdir())), 1)
                        env = (root / 'etc/config/idp.env').read_text()
                        self.assertNotIn('PROTECTED_WEBAPP_URL', env)
                        self.assertIn('IDP_BASE_URL="https://core.snodec.org:8088"', env)
                        self.assertIn('IDP_PORT="8088"', env)
                        self.assertIn('APP_PORT="443"', (root / 'etc/config/example.env').read_text())
                        credentials = (root / 'systemd/snodec-idp.service.d/tls.conf').read_text()
                        self.assertIn('LoadCredential=tls-key:', credentials)
                        if mode == 'letsencrypt':
                            issuance = next(c for c in commands if c[:2] == ('certbot', 'certonly'))
                            self.assertIn('--standalone', issuance)
                            self.assertEqual(issuance[issuance.index('--pre-hook') + 1], 'systemctl stop snodec-idp')
                            self.assertEqual(issuance[issuance.index('--post-hook') + 1], 'systemctl start snodec-idp')
                            self.assertIn(('systemctl', 'enable', '--now', 'certbot.timer'), commands)
                            hook = (root / 'etc/letsencrypt/renewal-hooks/deploy/snodec-idp').read_text()
                            self.assertIn('systemctl try-restart snodec-idp snodec-idp-example', hook)
                            self.assertIn('$RENEWED_LINEAGE', hook)
                        else:
                            self.assertFalse(any(c[0] == 'certbot' for c in commands))
                            self.assertFalse(any(c[0] == 'nginx' for c in commands))
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

    def test_prompts_require_first_input_and_keep_saved_values_without_echoing_secrets(self):
        prompts = []
        answers = iter(['', 'idp.example.org', ''])
        def answer(prompt):
            prompts.append(prompt)
            return next(answers)
        with patch('builtins.input', side_effect=answer), patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(deploy.ask('Host', 'Example only', convert=deploy.hostname), 'idp.example.org')
            self.assertEqual(deploy.ask('Host', 'Saved host', 'saved.example.org'), 'saved.example.org')
            with patch.object(deploy.getpass, 'getpass', return_value='') as hidden:
                self.assertEqual(deploy.ask('Secret', 'Hidden', 'NEVER-ECHO', secret=True), 'NEVER-ECHO')
                self.assertNotIn('NEVER-ECHO', hidden.call_args.args[0])
            self.assertNotIn('NEVER-ECHO', output.getvalue())
        self.assertEqual(prompts[:2], ['Host: ', 'Host: '])
        self.assertIn('[saved.example.org]', prompts[2])

    def test_first_wizard_has_no_prefilled_deployment_answers(self):
        answers = iter(['idp.example.org', '8088', 'yes', 'app.example.org', '443', 'my-client', 'no', 'no',
                        '8.8.8.8', 'files', '/etc/ssl/cert.pem', '/etc/ssl/key.pem', 'no', 'disabled'])
        prompts = []
        def answer(prompt):
            prompts.append(prompt)
            return next(answers)
        config = {}
        with patch('builtins.input', side_effect=answer), patch('sys.stdout', new_callable=io.StringIO):
            deploy.collect_config(config)
        self.assertTrue(all('[' not in prompt for prompt in prompts), prompts)
        self.assertEqual(config['hostname'], 'idp.example.org')
        self.assertEqual(config['tls'], {'mode': 'files', 'certificate': '/etc/ssl/cert.pem', 'private_key': '/etc/ssl/key.pem'})
        self.assertEqual(config['clients'], {'my-client': ['https://app.example.org/auth/callback']})
        self.assertEqual(config['google_client_secret'], '')
        self.assertEqual(config['smtp_command'], '')

    def test_first_wizard_collects_files_google_and_smtp_without_defaults(self):
        answers = iter(['idp.example.org', '8088', 'yes', 'app.example.org', '443', 'my-client', 'no', 'no',
                        '8.8.8.8', 'files', '/etc/ssl/cert.pem', '/etc/ssl/key.pem', 'yes', 'google-id',
                        'smtp', 'smtp.example.org', 'implicit', '465', 'sender@example.org', 'mail-user',
                        'recipient@example.org'])
        prompts = []
        def answer(prompt):
            prompts.append(prompt)
            return next(answers)
        config = {}
        with patch('builtins.input', side_effect=answer), patch.object(deploy.getpass, 'getpass', side_effect=['GOOGLE-SECRET', 'MAIL-SECRET']),              patch('sys.stdout', new_callable=io.StringIO) as output:
            deploy.collect_config(config)
        self.assertTrue(all('[' not in prompt for prompt in prompts), prompts)
        self.assertEqual(config['mail']['port'], 465)
        self.assertEqual(config['google_client_secret'], 'GOOGLE-SECRET')
        self.assertEqual(config['mail']['password'], 'MAIL-SECRET')
        self.assertNotIn('GOOGLE-SECRET', output.getvalue())
        self.assertNotIn('MAIL-SECRET', output.getvalue())

    def test_saved_wizard_retains_full_callback_list_and_credentials(self):
        config = self.config | {'tls': {'mode': 'files', 'certificate': '/etc/ssl/cert.pem', 'private_key': '/etc/ssl/key.pem'}, 'public_ips': ['8.8.8.8'],
                                'google_client_id': 'saved-id', 'google_client_secret': 'HIDDEN'}
        config['clients']['minimal-mfa-app'].append('https://app.example.org/second/callback')
        original = json.loads(json.dumps(config))
        answers = iter(['', '', '', '', '', '', 'no', '', '', '', '', '', '', '', ''])
        with patch('builtins.input', side_effect=lambda prompt: next(answers)),              patch.object(deploy.getpass, 'getpass', return_value=''), patch('sys.stdout', new_callable=io.StringIO) as output:
            deploy.collect_config(config)
        self.assertEqual(config, original)
        self.assertNotIn('HIDDEN', output.getvalue())

    def test_existing_external_application_callbacks_are_defaults(self):
        config = self.config | {'tls': {'mode': 'files', 'certificate': '/etc/ssl/cert.pem', 'private_key': '/etc/ssl/key.pem'}, 'public_ips': ['8.8.8.8']}
        config.pop('example')
        original = json.loads(json.dumps(config))
        answers = iter(['', '', '', '', '', 'no', '', '', '', '', '', '', ''])
        with patch('builtins.input', side_effect=lambda prompt: next(answers)), patch('sys.stdout', new_callable=io.StringIO):
            deploy.collect_config(config)
        self.assertEqual(config, original)

    def test_files_mode_needs_no_certbot_and_old_packages_are_rejected(self):
        config = self.config | {'tls': {'mode': 'files', 'certificate': '/etc/ssl/cert.pem', 'private_key': '/etc/ssl/key.pem'}}
        with tempfile.TemporaryDirectory() as tmp:
            unit = Path(tmp) / 'service'
            with patch.object(deploy, 'DATA', Path(tmp)), patch.object(deploy.os, 'geteuid', return_value=0), \
                 patch.object(deploy.shutil, 'which', side_effect=lambda name: None if name in ('nginx', 'certbot') else '/usr/bin/' + name), \
                 patch.object(deploy, 'run', return_value=str(unit)), patch.object(deploy, 'check_listeners'), \
                 patch.object(deploy, 'check_certificates') as certificates:
                unit.write_text('old loopback unit')
                with self.assertRaisesRegex(ValueError, 'rebuilt direct-TLS packages'):
                    deploy.preflight(config)
                unit.write_text('tls --cert %d/tls-cert --cert-key %d/tls-key')
                self.assertIsNone(deploy.preflight(config))
                certificates.assert_called_once_with(config)

    def test_dns_rejects_wrong_ipv6_and_nonpublic_input(self):
        config = self.config | {'public_ips': ['8.8.8.8']}
        for address, valid in [('8.8.8.8', True), ('2001:4860:4860::8888', False)]:
            with self.subTest(address=address), patch.object(deploy.socket, 'getaddrinfo', return_value=[(None, None, None, None, (address, 443))]),                  patch('sys.stdout', new_callable=io.StringIO):
                if valid:
                    deploy.check_dns(config)
                else:
                    with self.assertRaisesRegex(ValueError, 'DNS'):
                        deploy.check_dns(config)
        for address in ('127.0.0.1', '::1', '10.0.0.1'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                deploy.address_list(address)

    def test_mail_configuration_is_protected_and_has_no_shell_secret(self):
        mail = {'host': 'smtp.example.org', 'port': 587, 'tls': 'starttls', 'username': 'user',
                'password': 'secret"with\\slashes', 'from': 'sender@example.org', 'test_to': 'test@example.org'}
        config = self.config | {'mail': mail, 'smtp_command': ''}
        deploy.validate(config)
        with tempfile.TemporaryDirectory() as tmp, patch.object(deploy, 'CONFIG', Path(tmp)), patch.object(deploy.os, 'chown'):
            command = deploy.provision_mail(config, pwd.getpwuid(os.getuid()))
            path = Path(tmp) / 'mail/msmtprc'
            self.assertNotIn(mail['password'], command)
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o750)
            self.assertIn('tls_certcheck "on"', path.read_text())
            self.assertIn('set_from_header "on"', path.read_text())
            self.assertIn('allow_from_override "off"', path.read_text())
            self.assertIn('password "secret\\"with\\\\slashes"', path.read_text())
        with self.assertRaises(ValueError):
            deploy.validate(config | {'smtp_command': '/usr/bin/other-mail'})

    def test_real_certificate_validation_rejects_wrong_name_key_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            key, cert = root / 'key.pem', root / 'cert.pem'
            deploy.run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                       '-keyout', str(key), '-out', str(cert), '-days', '1',
                       '-subj', '/CN=idp.example.org', '-addext', 'subjectAltName=DNS:idp.example.org')
            key.chmod(0o600)
            config = {'hostname': 'idp.example.org', 'idp_port': 8088, 'clients': {}, 'tls': {
                'mode': 'files', 'certificate': str(cert), 'private_key': str(key)}}
            with patch.dict(os.environ, {'SSL_CERT_FILE': str(cert)}):
                deploy.check_certificates(config)
                with self.assertRaises(subprocess.CalledProcessError):
                    deploy.check_certificates(config | {'hostname': 'wrong.example.org'})
                key.chmod(0o644)
                with self.assertRaisesRegex(ValueError, 'world-accessible'):
                    deploy.check_certificates(config)
                key.chmod(0o600)
                deploy.run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(key))
                with self.assertRaisesRegex(ValueError, 'do not match'):
                    deploy.check_certificates(config)

    def test_listener_conflicts_are_not_stopped(self):
        for port, pid, valid in [(80, 9, False), (443, 9, False), (8088, 9, False),
                                 (8088, 7, True), (443, 7, True), (22, 9, True)]:
            line = f'LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:* users:(("server",pid={pid},fd=3))'
            with self.subTest(port=port, pid=pid), \
                 patch.object(deploy, 'run', side_effect=lambda *args: line if args[0] == 'ss' else '7') as command, \
                 patch('sys.stdout', new_callable=io.StringIO):
                if valid:
                    deploy.check_listeners(self.config)
                else:
                    with self.assertRaises(ValueError):
                        deploy.check_listeners(self.config)
                self.assertFalse(any('stop' in call.args for call in command.call_args_list))

    def test_failed_and_interrupted_steps_persist_incomplete_report(self):
        for error in (RuntimeError('test failure'), KeyboardInterrupt()):
            with self.subTest(error=type(error)), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'report.json'
                report = {'checks': {}, 'complete': False}
                with patch.object(deploy, 'retry', side_effect=error), self.assertRaises(type(error)):
                    deploy.checked_step(report, path, 'Deployment', lambda: None)
                self.assertFalse(json.loads(path.read_text())['complete'])
                self.assertEqual(json.loads(path.read_text())['checks']['Deployment'], 'failed or interrupted')

    def test_pending_browser_or_renewal_checks_never_report_complete(self):
        for status in ('passed', 'pending', 'failed'):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'deployment.json'
                config = self.config | {'tls': {'mode': 'files', 'certificate': '/etc/ssl/cert.pem', 'private_key': '/etc/ssl/key.pem'}}
                deploy.write(path, json.dumps(config))
                with patch.object(deploy.os, 'geteuid', return_value=0), patch.object(deploy.sys.stdin, 'isatty', return_value=True),                      patch.object(deploy, 'collect_config'), patch.object(deploy, 'yes', return_value=True),                      patch.object(deploy, 'network_setup'), patch.object(deploy, 'deploy'), patch.object(deploy, 'verify_http'),                      patch.object(deploy, 'choice', return_value=status), patch('sys.stdout', new_callable=io.StringIO):
                    self.assertEqual(deploy.interactive(path), status == 'passed')
                report = json.loads(path.with_name('deployment-report.json').read_text())
                self.assertEqual(report['complete'], status == 'passed')
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(len(list(path.parent.glob('deployment.json.previous-*'))), 1)

    def test_https_redirect_verification_requires_correct_public_destinations(self):
        def response(url, bad=False):
            result = io.BytesIO(b'{"status":"ok"}')
            result.status, result.headers = 200, {}
            if url.startswith('http:'):
                result.status = 308
                result.headers['Location'] = deploy.http_targets(self.config)[deploy.urlsplit(url).hostname] + '/auth/login'
            if url == 'https://core.vchrist.at:8088/':
                result.status = 303
                result.headers['Location'] = 'https://wrong.example.org/' if bad else self.config['redirects']['core.vchrist.at']
            return result
        for bad in (False, True):
            with self.subTest(bad=bad), patch.object(deploy.urllib.request, 'build_opener') as opener,                  patch.object(deploy.urllib.request, 'urlopen', side_effect=response):
                opener.return_value.open.side_effect = lambda url, **kwargs: response(url, bad)
                # urlopen also supplies the timeout keyword.
                with patch.object(deploy.urllib.request, 'urlopen', side_effect=lambda url, **kwargs: response(url)):
                    if bad:
                        with self.assertRaisesRegex(ValueError, 'redirect failed'):
                            deploy.verify_http(self.config)
                    else:
                        deploy.verify_http(self.config)

    def test_mail_test_uses_service_sandbox_and_requires_receipt(self):
        config = self.config | {'smtp_command': '/usr/bin/msmtp -t'}
        with patch.object(deploy.shutil, 'which', return_value='/usr/bin/systemd-run'),              patch.object(deploy, 'ask', return_value='recipient@example.org'),              patch.object(deploy.subprocess, 'run') as command, patch.object(deploy, 'yes', return_value=False):
            with self.assertRaisesRegex(ValueError, 'not confirmed'):
                deploy.test_mail(config)
        args = command.call_args.args[0]
        self.assertIn('--property=User=snodec-idp', args)
        self.assertIn('--property=ProtectHome=yes', args)
        self.assertIn(b'To: recipient@example.org', command.call_args.kwargs['input'])

    def test_firewall_only_changes_confirmed_active_ufw(self):
        for active in (False, True):
            commands = []
            def command(*args):
                commands.append(args)
                return 'Status: active' if active else 'Status: inactive'
            with self.subTest(active=active), patch.object(deploy, 'check_dns'), patch.object(deploy, 'check_listeners'),                  patch.object(deploy, 'choice', return_value='ufw'), patch.object(deploy, 'yes', return_value=True),                  patch.object(deploy, 'run', side_effect=command), patch.object(deploy.shutil, 'which', return_value=None),                  patch('builtins.input', return_value=''), patch('sys.stdout', new_callable=io.StringIO):
                if active:
                    deploy.network_setup(self.config)
                    self.assertEqual(commands, [('ufw', 'status'), ('ufw', 'allow', '80/tcp'), ('ufw', 'allow', '8088/tcp'), ('ufw', 'allow', '443/tcp')])
                else:
                    with self.assertRaisesRegex(ValueError, 'not active'):
                        deploy.network_setup(self.config)
                    self.assertEqual(commands, [('ufw', 'status')])

    def test_package_units_load_private_credentials_and_no_proxy_dependency(self):
        for name in ('snodec-idp', 'snodec-idp-example'):
            text = (ROOT / ('packaging/' + name + '.service.in')).read_text()
            self.assertIn('tls --cert %d/tls-cert --cert-key %d/tls-key', text)
            self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE', text)
            self.assertIn('--host 0.0.0.0', text)
        self.assertNotIn('nginx', (ROOT / 'cmake/Packing.cmake').read_text())


if __name__ == '__main__':
    unittest.main()
