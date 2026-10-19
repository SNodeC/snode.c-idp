#!/usr/bin/env python3
"""Explicit systemd deployment with direct SNode.C TLS. Package installation never calls this file."""
import argparse
from contextlib import closing
import getpass
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import sys
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from email.message import EmailMessage

CONFIG = Path('/etc/snodec-idp')
DATA = Path('/var/lib/snodec-idp')
SYSTEMD = Path('/etc/systemd/system')
CERT = Path('/etc/letsencrypt/live/snodec-idp')


def run(*args):
    result = subprocess.run(args, check=True, text=True, capture_output=True)
    return result.stdout


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or not re.fullmatch(
            r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', value):
        raise ValueError('Hostnames must be lowercase public DNS names')
    return value


def https_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or any(c.isspace() or ord(c) < 32 or c in '\\";$' for c in value)):
        raise ValueError('Expected a public HTTPS URL without credentials or fragment')
    hostname(parsed.hostname)
    if parsed.port is not None:
        port_number(parsed.port)
    return value


def port_number(value):
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError('Enter a TCP port between 1 and 65535')
    return port


def https_origin(host, port):
    origin = 'https://' + host + (':' + str(port) if port != 443 else '')
    return origin


def http_targets(config):
    origin = https_origin(config['hostname'], config['idp_port'])
    targets = {config['hostname']: origin}
    targets.update({host: https_origin(host, config['idp_port']) for host in config.get('redirects', {})})
    if config.get('example'):
        targets[config['example']['hostname']] = https_origin(config['example']['hostname'], config['example']['port'])
    return targets


def single_line(value):
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Enter one line without control characters')
    return value


def email(value):
    if not isinstance(value, str) or not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', value):
        raise ValueError('Enter a complete email address, for example operator@example.org')
    return value


def validate(config):
    allowed = {'hostname', 'acme_email', 'accept_acme_terms', 'clients', 'redirects',
               'google_client_id', 'google_client_secret', 'smtp_command', 'example', 'tls', 'mail', 'public_ips', 'idp_port'}
    if set(config) - allowed:
        raise ValueError('Unknown deployment configuration field')
    hostname(config['hostname'])
    if not isinstance(config.get('idp_port'), int) or port_number(config['idp_port']) == 80:
        raise ValueError('Set idp_port for the direct HTTPS listener, e.g. 8088; port 80 is reserved for HTTP redirects')
    tls = config.get('tls', {'mode': 'letsencrypt'})
    if tls.get('mode') not in ('letsencrypt', 'files'):
        raise ValueError('TLS mode must be letsencrypt or files; applications terminate TLS directly')
    if tls['mode'] == 'letsencrypt':
        email(config.get('acme_email', ''))
        if config.get('accept_acme_terms') is not True:
            raise ValueError('Set accept_acme_terms to true after reviewing the ACME terms')
    elif tls['mode'] == 'files':
        for key in ('certificate', 'private_key'):
            if not re.fullmatch(r'/[A-Za-z0-9_./-]+', tls.get(key, '')):
                raise ValueError('Certificate/key paths must be absolute and contain no spaces or shell characters')
    if set(tls) - {'mode', 'certificate', 'private_key'}:
        raise ValueError('Unknown TLS field')
    if 'public_ips' in config:
        if not isinstance(config['public_ips'], list) or not config['public_ips']:
            raise ValueError('public_ips must be a nonempty list')
        address_list(','.join(config['public_ips']))
    mail = config.get('mail')
    if mail:
        if set(mail) != {'host', 'port', 'tls', 'username', 'password', 'from', 'test_to'}:
            raise ValueError('SMTP configuration fields are incomplete or unknown')
        hostname(mail['host'])
        if mail['tls'] not in ('starttls', 'implicit') or not isinstance(mail['port'], int) or not 0 < mail['port'] < 65536:
            raise ValueError('SMTP needs a valid port and starttls or implicit TLS')
        email(mail['from'])
        email(mail['test_to'])
        for key in ('username', 'password'):
            single_line(mail[key])
        if bool(mail['username']) != bool(mail['password']):
            raise ValueError('SMTP authentication requires both username and password')
        if config.get('smtp_command'):
            raise ValueError('Choose managed SMTP or an existing mail command, not both')
    if not isinstance(config['clients'], dict) or not isinstance(config.get('redirects', {}), dict):
        raise ValueError('clients and redirects must be JSON objects')
    for client, callbacks in config['clients'].items():
        if not client or not isinstance(callbacks, list) or not callbacks:
            raise ValueError('Each client needs at least one exact callback URL')
        for callback in callbacks:
            https_url(callback)
    hosts = {config['hostname']}
    for host, target in config.get('redirects', {}).items():
        hostname(host)
        https_url(target)
        if host in hosts:
            raise ValueError('Redirect hostname conflicts with the IDP')
        hosts.add(host)
    example = config.get('example')
    if example:
        if set(example) != {'hostname', 'client_id', 'port'}:
            raise ValueError('example requires hostname, client_id and port')
        if not isinstance(example['port'], int) or port_number(example['port']) in (80, config['idp_port']):
            raise ValueError('Application HTTPS port must differ from IDP and HTTP redirect ports')
        host = hostname(example['hostname'])
        if host in hosts or https_origin(host, example['port']) + '/auth/callback' not in config['clients'].get(example['client_id'], []):
            raise ValueError('Example needs a distinct hostname and a registered callback')
        hosts.add(host)
    for key in ('google_client_id', 'google_client_secret', 'smtp_command'):
        value = config.get(key, '')
        if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Secrets and commands must be single-line strings')
    if bool(config.get('google_client_id')) != bool(config.get('google_client_secret')):
        raise ValueError('Google requires both client ID and secret')
    return sorted(hosts)


def write(path, content, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content.encode())
    temporary.chmod(mode)
    temporary.replace(path)


def environment(values):
    # systemd EnvironmentFile values: quoted values, escaped backslashes/quotes.
    result = ''.join(key + '="' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"\n'
                     for key, value in values.items())
    return result


def provision_keys(data):
    keys = data / 'keys'
    keys.mkdir(parents=True, exist_ok=True, mode=0o700)
    private, totp = keys / 'private.pem', keys / 'totp.key'
    if (data / 'auth.db').exists() and (not private.is_file() or not totp.is_file()):
        raise ValueError('Existing database requires its original signing and TOTP keys')
    if not private.exists():
        run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(private))
    if not totp.exists():
        run('openssl', 'rand', '-out', str(totp), '32')
    if totp.stat().st_size != 32:
        raise ValueError('TOTP key must contain exactly 32 bytes')
    run('openssl', 'pkey', '-in', str(private), '-check', '-noout')
    public = run('openssl', 'pkey', '-in', str(private), '-pubout')
    private.chmod(0o600)
    totp.chmod(0o600)
    return public


def preflight(config):
    validate(config)
    if os.geteuid() != 0:
        raise ValueError('Deployment must run as root; --check needs no privilege')
    mode = config.get('tls', {}).get('mode', 'letsencrypt')
    binaries = ['systemctl', 'systemd-sysusers', 'openssl', 'auth_idp']
    if mode == 'letsencrypt':
        binaries.append('certbot')
    if config.get('mail'):
        binaries.append('msmtp')
    for binary in binaries:
        if not shutil.which(binary):
            raise ValueError('Install required program: ' + binary)
    if config.get('example') and not shutil.which('minimal-mfa-app'):
        raise ValueError('Install snodec-idp-example before deploying it')
    services = ['snodec-idp'] + (['snodec-idp-example'] if config.get('example') else [])
    for service in services:
        unit = Path(run('systemctl', 'show', service, '--property=FragmentPath', '--value').strip())
        if not unit.is_file() or 'tls --cert %d/tls-cert --cert-key %d/tls-key' not in unit.read_text():
            raise ValueError('Install rebuilt direct-TLS packages before deploying: ' + service)
    check_listeners(config)
    if (DATA / 'auth.db').exists() and not all((DATA / 'keys' / key).is_file() for key in ('private.pem', 'totp.key')):
        raise ValueError('Restore original database keys before deployment')
    # Use the distribution's existing renewal scheduler, not a competing timer.
    timer = None
    if mode == 'letsencrypt':
        timers = run('systemctl', 'list-unit-files', '--type=timer', '--no-legend')
        timer = next((name for name in ('certbot.timer', 'certbot-renew.timer') if name in timers.split()), None)
        if timer is None:
            raise ValueError('Install the distribution Certbot renewal timer')
    if mode == 'files':
        check_certificates(config)
    if config.get('public_ips'):
        check_dns(config)
    return timer


def certificate_paths(config):
    tls = config.get('tls', {})
    paths = (Path(tls['certificate']), Path(tls['private_key'])) if tls.get('mode') == 'files' else (
        CERT / 'fullchain.pem', CERT / 'privkey.pem')
    return paths


def check_certificates(config):
    certificate, key = certificate_paths(config)
    if not certificate.is_file() or not key.is_file():
        raise ValueError('Certificate or private-key file is missing; copy the PEM files to the server and retry')
    if key.stat().st_mode & 0o007:
        raise ValueError('The TLS private key must not be world-accessible; use chmod 600 on its file')
    # OpenSSL verifies validity, trust chain, each DNS name and key matching.
    run('openssl', 'x509', '-in', str(certificate), '-checkend', '0', '-noout')
    for host in validate(config):
        run('openssl', 'verify', '-purpose', 'sslserver', '-verify_hostname', host,
            '-untrusted', str(certificate), str(certificate))
    if run('openssl', 'x509', '-in', str(certificate), '-pubkey', '-noout') != run('openssl', 'pkey', '-in', str(key), '-passin', 'pass:', '-pubout'):
        raise ValueError('The certificate and private key do not match')


def check_dns(config):
    expected = {str(ipaddress.ip_address(address)) for address in config['public_ips']}
    for host in validate(config):
        actual = {item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        if not actual or not actual <= expected:
            raise ValueError('DNS for ' + host + ' resolves to ' + ', '.join(sorted(actual))
                             + '; expected only ' + ', '.join(sorted(expected)) + '. Correct A/AAAA records or the expected IPs.')
        print('DNS verified: ' + host + ' -> ' + ', '.join(sorted(actual)))


def provision_mail(config, user):
    command = config.get('smtp_command', '')
    if config.get('mail'):
        mail = config['mail']
        directory = CONFIG / 'mail'
        directory.mkdir(exist_ok=True, mode=0o750)
        os.chown(directory, 0, user.pw_gid)
        directory.chmod(0o750)
        quote = lambda value: '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'
        values = dict(host=mail['host'], port=mail['port'], tls='on', tls_certcheck='on',
                      tls_starttls='on' if mail['tls'] == 'starttls' else 'off',
                      auth='on' if mail['username'] else 'off', **{'from': mail['from']},
                      allow_from_override='off', set_from_header='on')
        if mail['username']:
            values.update(user=mail['username'], password=mail['password'])
        path = directory / 'msmtprc'
        write(path, 'account default\n' + ''.join(name + ' ' + quote(value) + '\n' for name, value in values.items()), 0o600)
        os.chown(path, user.pw_uid, user.pw_gid)
        command = '/usr/bin/msmtp --file=' + str(path) + ' -t'
    else:
        (CONFIG / 'mail/msmtprc').unlink(missing_ok=True)
    return command


def deploy(config):
    timer = preflight(config)
    CONFIG.mkdir(parents=True, exist_ok=True, mode=0o755)
    CONFIG.chmod(0o755)
    # Snapshot account data and keys before modifying generated configuration.
    if (DATA / 'auth.db').exists():
        backup = DATA / 'backups' / str(time.time_ns())
        backup.mkdir(parents=True, mode=0o700)
        with closing(sqlite3.connect(DATA / 'auth.db')) as source, closing(sqlite3.connect(backup / 'auth.db')) as target:
            source.backup(target)
        shutil.copytree(DATA / 'keys', backup / 'keys')
        shutil.copytree(CONFIG, backup / 'configuration')
    users = 'u snodec-idp - "SNode.C identity provider" /var/lib/snodec-idp\n'
    if config.get('example'):
        users += 'u snodec-idp-example - "SNode.C MFA example"\n'
    write(Path('/etc/sysusers.d/snodec-idp.conf'), users, 0o644)
    run('systemd-sysusers', '/etc/sysusers.d/snodec-idp.conf')
    DATA.mkdir(parents=True, exist_ok=True, mode=0o700)
    public = provision_keys(DATA)
    user = pwd.getpwnam('snodec-idp')
    for path in (DATA, DATA / 'keys', *(DATA / 'keys').iterdir(), *DATA.glob('auth.db*')):
        os.chown(path, user.pw_uid, user.pw_gid)
    example = config.get('example')
    origin = https_origin(config['hostname'], config['idp_port'])
    mail_command = provision_mail(config, user)
    values = dict(IDP_BASE_URL=origin, IDP_ISSUER=origin, IDP_PORT=config['idp_port'], HTTP_PORT='80', HTTP_REDIRECTS=json.dumps(http_targets(config)), DB_PATH=str(DATA / 'auth.db'),
                  IDP_PRIVATE_KEY_PATH=str(DATA / 'keys/private.pem'), TOTP_KEY_PATH=str(DATA / 'keys/totp.key'),
                  IDP_CLIENTS=json.dumps(config['clients']), HOST_REDIRECTS=json.dumps(config.get('redirects', {})),
                  OAUTH_GOOGLE_CLIENT_ID=config.get('google_client_id', ''),
                  OAUTH_GOOGLE_CLIENT_SECRET=config.get('google_client_secret', ''), SMTP_COMMAND=mail_command)
    write(CONFIG / 'idp.env', environment(values))
    write(CONFIG / 'empty.conf', '', 0o644)
    write(CONFIG / 'public.pem', public, 0o644)
    services = ['snodec-idp']
    if example:
        write(CONFIG / 'example.env', environment(dict(IDP_BASE_URL=origin, APP_CLIENT_ID=example['client_id'],
              APP_CALLBACK_URL=https_origin(example['hostname'], example['port']) + '/auth/callback', APP_PORT=example['port'], IDP_PUBLIC_KEY_PATH=str(CONFIG / 'public.pem'))))
        services.append('snodec-idp-example')
    elif (CONFIG / 'example.env').exists():
        run('systemctl', 'disable', '--now', 'snodec-idp-example')
        (CONFIG / 'example.env').unlink()
    certificate, key = certificate_paths(config)
    for service in services:
        write(SYSTEMD / (service + '.service.d') / 'tls.conf',
              '[Service]\nLoadCredential=tls-cert:' + str(certificate) + '\nLoadCredential=tls-key:' + str(key) + '\n')
    run('systemctl', 'daemon-reload')
    mode = config.get('tls', {}).get('mode', 'letsencrypt')
    if mode == 'letsencrypt':
        # Restrict the deploy hook to this certificate; private keys stay root-only.
        write(Path('/etc/letsencrypt/renewal-hooks/deploy/snodec-idp'),
              '#!/bin/sh\nset -eu\nif [ "$RENEWED_LINEAGE" = "' + str(CERT) + '" ]; then\n'
              '    systemctl try-restart ' + ' '.join(services) + '\nfi\n', 0o755)
        run('certbot', 'certonly', '--standalone', '--non-interactive', '--agree-tos', '--email', config['acme_email'],
            '--cert-name', 'snodec-idp', '--renew-with-new-domains',
            '--pre-hook', 'systemctl stop snodec-idp', '--post-hook', 'systemctl start snodec-idp',
            '-d', ','.join(validate(config)))
    check_certificates(config)
    if timer:
        run('systemctl', 'enable', '--now', timer)
    for service in services:
        run('systemctl', 'enable', service)
        run('systemctl', 'restart', service)
    deadline = time.monotonic() + 120
    healthy = False
    while not healthy and time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(origin + '/health', timeout=5) as response:
                healthy = json.load(response).get('status') == 'ok'
        except (OSError, ValueError):
            time.sleep(1)
    if not healthy:
        raise RuntimeError('HTTPS health check failed; inspect journalctl -u snodec-idp')
    print('Deployed ' + origin + '; renewal: ' + (timer or 'operator-managed'))


def ask(label, explanation, default=None, secret=False, convert=single_line):
    print('\n' + explanation)
    valid, result = False, None
    while not valid:
        hint = ' [Enter keeps saved value]' if secret and default else (' [' + str(default) + ']' if default not in (None, '') else '')
        raw = getpass.getpass(label + hint + ': ') if secret else input(label + hint + ': ')
        try:
            result = convert(raw if raw != '' or default is None else default)
            valid = True
        except (ValueError, TypeError) as error:
            print('Please correct this answer: ' + str(error))
    return result


def choice(label, explanation, options, default=None):
    def accepted(value):
        if value not in options:
            raise ValueError('Choose one of: ' + ', '.join(options))
        return value
    return ask(label, explanation + '\nChoices: ' + ', '.join(options), default, convert=accepted)


def yes(label, explanation, default=None):
    result = choice(label, explanation, ('yes', 'no'), ('yes' if default else 'no') if default is not None else None) == 'yes'
    return result


def nonempty(value):
    single_line(value)
    if not value:
        raise ValueError('A value is required')
    return value


def address_list(value):
    addresses = [str(ipaddress.ip_address(part.strip())) for part in value.split(',')]
    if any(not ipaddress.ip_address(address).is_global or ipaddress.ip_address(address).version != 4 for address in addresses):
        raise ValueError('Enter public globally routable IPv4 addresses; these service units use IPv4 listeners')
    return addresses


def collect_config(config):
    print('\nStep 4: Public hostnames and client registration')
    config['hostname'] = ask('IDP hostname', 'The public login service, without https:// or a path. Example: core.snodec.org.',
                             config.get('hostname'), convert=hostname)
    config['idp_port'] = ask('IDP HTTPS port', 'The IDP listens directly on this public port. Example: 8088. '
                             'Port 80 is reserved for HTTP redirects and ACME.', config.get('idp_port'), convert=port_number)
    old = config.get('example', {})
    if yes('Deploy the styled example?', 'The example provides a browser test application on a DISTINCT hostname. '
           'Choose no to register an application you already run.', bool(old) if config.get('clients') else None):
        host = ask('Application hostname', 'Create a DNS name pointing to this server. For example core.vchrist.at. '
                   'It must differ from the IDP and must not also be a redirect hostname.', old.get('hostname', ''), convert=hostname)
        app_port = ask('Application HTTPS port', 'The application serves HTTPS directly; use 443 for the standard HTTPS URL. '
                       'It must differ from the IDP port.', old.get('port'), convert=port_number)
        client = ask('Application client ID', 'A stable name, not a secret; for example minimal-mfa-app. The callback is registered automatically.',
                     old.get('client_id'), convert=nonempty)
        config['example'] = {'hostname': host, 'client_id': client, 'port': app_port}
        callbacks = config.setdefault('clients', {}).setdefault(client, [])
        callback = https_origin(host, app_port) + '/auth/callback'
        if callback not in callbacks:
            callbacks.append(callback)
    else:
        config.pop('example', None)
        client = ask('Client ID', 'Use the same identifier configured by your application developer.', next(iter(config.get('clients', {})), None), convert=nonempty)
        callbacks = config.get('clients', {}).get(client, [])
        if not callbacks or not yes('Keep saved callbacks?', json.dumps(callbacks), True):
            callback = ask('Application callback URL', 'Ask the application developer for the exact HTTPS OAuth callback, '
                           'for example https://app.example.org/auth/callback. This is NOT the Google callback.',
                           callbacks[0] if callbacks else None, convert=https_url)
            config.setdefault('clients', {})[client] = [callback]
    if config.get('clients'):
        print('Registered callbacks: ' + json.dumps(config['clients']))
    while yes('Add another client?', 'Each application needs its own ID and exact callback URL. Existing registrations are preserved.'):
        client = ask('Client ID', 'Existing IDs will have their callback list replaced.', convert=nonempty)
        callback = ask('Callback URL', 'Exact HTTPS OAuth callback supplied by that application.', convert=https_url)
        config['clients'][client] = [callback]
    if config.get('redirects'):
        print('Existing redirects: ' + json.dumps(config['redirects']))
    if not config.get('redirects') or not yes('Keep these redirects?', 'Choose no to replace the mapping; clients remain unchanged.', True):
        config['redirects'] = {}
        while yes('Add a redirect hostname?', 'Optional: an additional hostname can redirect to your application. '
                   'It must have DNS pointing here and cannot be the IDP or application hostname.'):
            host = ask('Redirect hostname', 'For example core.vchrist.at, only if it is NOT your application host.', convert=hostname)
            config['redirects'][host] = ask('Destination URL', 'The complete HTTPS destination, for example https://app.example.org/.', convert=https_url)

    print('\nStep 5: DNS and certificate ownership')
    config['public_ips'] = ask('Public IP addresses', 'Copy this server\'s public IPv4 address from your hosting console '
                              '(https://console.hetzner.com/ -> project -> server -> Networking). Separate addresses with commas. '
                              'All A records must match; remove AAAA records because these service units listen on IPv4.',
                              ','.join(config.get('public_ips', [])), convert=address_list)
    mode = choice('TLS ownership', 'Choose letsencrypt for automatic public certificates and renewal. Choose files for your existing '
                  'PEM certificate/key on THIS server. SNode.C terminates TLS directly in both modes.',
                  ('letsencrypt', 'files'), config.get('tls', {}).get('mode', 'letsencrypt' if 'acme_email' in config else None))
    old_tls = config.get('tls', {})
    config['tls'] = {'mode': mode}
    if mode == 'letsencrypt':
        config['acme_email'] = ask('ACME contact email', 'A real address for your certificate account. No mailbox password is required.',
                                   config.get('acme_email', ''), convert=email)
        config['accept_acme_terms'] = yes('Accept the ACME terms?', 'Review the subscriber agreement at https://letsencrypt.org/repository/. '
                                             'Choose yes only if you accept it.', config.get('accept_acme_terms'))
    elif mode == 'files':
        config['tls']['certificate'] = ask('Full-chain certificate PEM path', 'Copy your CA-issued certificate and intermediate chain '
                'to this server. Use an absolute path such as /etc/ssl/my-idp/fullchain.pem. It must cover ALL configured hostnames.',
                old_tls.get('certificate', ''), convert=nonempty)
        config['tls']['private_key'] = ask('TLS private-key PEM path', 'Use the corresponding unencrypted key file on the server '
                '(for unattended TLS startup), mode 600. Enter its PATH, not the key contents.',
                old_tls.get('private_key', ''), convert=nonempty)
        print('Renew these files using your CA process; validate them and restart both SNode.C services after replacement. This tool will not install Certbot.')

    print('\nStep 6: Optional Google login')
    if yes('Enable Google login?', 'Local password/TOTP login is always available. Choose yes to configure Google federation.',
           bool(config.get('google_client_id')) if 'google_client_id' in config else None):
        print('Open https://console.cloud.google.com/auth/overview and select/create your project.\n'
              'Configure Branding and Audience; for testing add your test users. Open Clients, create a Web application client.\n'
              'Add this exact Authorized redirect URI:\n' + https_origin(config['hostname'], config['idp_port']) + '/auth/federated/google/callback\n'
              'Copy the client ID and secret from that Web client. Do not use an Android/Desktop client.\n'
              'Help: https://developers.google.com/identity/protocols/oauth2/web-server')
        config['google_client_id'] = ask('Google client ID', 'Enter the full ID ending in .apps.googleusercontent.com.',
                                          config.get('google_client_id', ''), convert=nonempty)
        config['google_client_secret'] = ask('Google client secret', 'Copy the secret from the same client. Input is hidden and saved '
                                               'only in protected configuration; Enter keeps an existing secret.',
                                               config.get('google_client_secret', ''), secret=True, convert=nonempty)
    else:
        config['google_client_id'], config['google_client_secret'] = '', ''

    print('\nStep 7: Password recovery email')
    default = 'smtp' if config.get('mail') else ('command' if config.get('smtp_command') else ('disabled' if 'smtp_command' in config else None))
    delivery = choice('Mail delivery', 'Choose smtp to configure a dedicated msmtp transport, command to keep a working local '
                      'mail command, or disabled to explicitly disable recovery email. SMTP settings come from your mail provider\'s '
                      'outgoing-mail/SMTP settings page. Use an app password if the provider requires one.',
                      ('smtp', 'command', 'disabled'), default)
    if delivery == 'smtp':
        previous = config.get('mail', {})
        mail = dict(host=ask('SMTP hostname', 'Outgoing SMTP server from your mail provider, e.g. smtp.example.org.',
                            previous.get('host', ''), convert=hostname))
        mail['tls'] = choice('SMTP encryption', 'Use your provider\'s setting: starttls usually uses port 587; implicit TLS usually 465. '
                             'Certificate checking stays enabled.', ('starttls', 'implicit'), previous.get('tls'))
        mail['port'] = ask('SMTP port', 'Use the port documented by the provider.',
                           previous.get('port'), convert=int)
        mail['from'] = ask('Sender email address', 'An address your SMTP account is authorized to send from. It becomes the From header.',
                           previous.get('from', ''), convert=email)
        mail['username'] = ask('SMTP username', 'Usually your complete mailbox address; leave empty (or enter - to clear a saved username) only for an authorized unauthenticated relay.',
                               previous.get('username', ''), convert=lambda value: '' if value == '-' else single_line(value))
        mail['password'] = ask('SMTP password/app password', 'Find/create this in your provider\'s account security or SMTP settings. '
                               'Input is hidden; do not use a Google OAuth client secret here.', previous.get('password', ''),
                               secret=True, convert=nonempty) if mail['username'] else ''
        mail['test_to'] = ask('Test recipient', 'An inbox you can open now. The script will send a test and ask you to confirm delivery.',
                              previous.get('test_to'), convert=email)
        config['mail'], config['smtp_command'] = mail, ''
    else:
        config.pop('mail', None)
        config['smtp_command'] = ask('Existing mail command', 'A trusted fixed command that reads an RFC mail message on stdin. '
                                    'It runs as snodec-idp with /home hidden, e.g. /usr/bin/msmtp -t. Do not put passwords in arguments.',
                                    config.get('smtp_command', ''), convert=nonempty) if delivery == 'command' else ''
    validate(config)


def install_packages(*packages):
    manager = 'apt-get' if shutil.which('apt-get') else 'dnf'
    print('Installing explicit deployment dependencies: ' + ', '.join(packages))
    subprocess.run([manager, 'install', '-y', *packages], check=True)


def retry(label, action):
    complete = False
    while not complete:
        try:
            action()
            complete = True
        except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
            # Never print subprocess output, commands containing secrets, or config objects.
            detail = (Path(error.cmd[0] if isinstance(error.cmd, (list, tuple)) else error.cmd).name
                      + ' failed with exit status ' + str(error.returncode) + '; inspect service journals or correct settings on rerun') if isinstance(error, subprocess.CalledProcessError) else str(error)
            print(label + ': ' + detail)
            if not yes('Retry this step?', 'Correct the reported problem in another terminal, then choose yes. '
                       'Choose no to stop; saved configuration and existing accounts/keys remain for rerunning.'):
                raise RuntimeError(label + ' incomplete; rerun the setup after correcting the problem') from None



def check_listeners(config):
    listeners = run('ss', '-H', '-ltnp')
    print(listeners)
    owners_by_port = {80: 'snodec-idp', config['idp_port']: 'snodec-idp'}
    if config.get('example'):
        owners_by_port[config['example']['port']] = 'snodec-idp-example'
    for line in listeners.splitlines():
        fields = line.split()
        if len(fields) < 5:
            raise ValueError('Cannot parse listener inventory from ss')
        port = int(fields[3].rsplit(':', 1)[1])
        if port in owners_by_port:
            pid = run('systemctl', 'show', owners_by_port[port], '--property=MainPID', '--value').strip()
            owners = re.findall(r'pid=(\d+)', line)
            if pid == '0' or not owners or set(owners) != {pid}:
                raise ValueError('Port ' + str(port) + ' is occupied outside its managed SNode.C service. '
                                 'Resolve ownership before retrying; unrelated services will not be stopped.')


def network_setup(config):
    retry('DNS validation', lambda: check_dns(config))
    check_listeners(config)
    ports = [80, config['idp_port']] + ([config['example']['port']] if config.get('example') else [])
    print('SNode.C serves the Internet directly. Allow inbound TCP ports: ' + ', '.join(map(str, ports)) + '. Preserve SSH access.\n'
          'For hosting firewalls: https://console.hetzner.com/ -> project -> Firewalls -> attached firewall.\n'
          'Instructions: https://docs.hetzner.com/cloud/firewalls/getting-started/creating-a-firewall/\n'
          'Final checks include a browser on another machine; this server cannot prove Internet reachability.')
    firewall = choice('Host firewall management', 'Choose ufw or firewalld to add HTTP/HTTPS allowances to an ALREADY ACTIVE firewall. '
                      'Choose manual if using nftables/iptables or managing rules elsewhere. No firewall is enabled or flushed.',
                      ('ufw', 'firewalld', 'manual'))
    if firewall == 'ufw':
        if 'Status: active' not in run('ufw', 'status'):
            raise ValueError('UFW is not active; choose manual on rerun or configure it yourself without losing SSH')
        if yes('Allow HTTP/HTTPS in active UFW?', 'Adds the listed TCP ports only; existing SSH rules are untouched.'):
            for port in ports:
                run('ufw', 'allow', str(port) + '/tcp')
    elif firewall == 'firewalld':
        run('firewall-cmd', '--state')
        print(run('firewall-cmd', '--get-active-zones'))
        zone = ask('Public network firewall zone', 'Select the zone of the server\'s public network interface from the output above.',
                   convert=nonempty)
        if zone not in run('firewall-cmd', '--get-zones').split():
            raise ValueError('Unknown firewalld zone')
        if yes('Allow HTTP/HTTPS in this zone?', 'Adds the listed runtime/permanent TCP ports only; SSH remains untouched.'):
            for port in ports:
                run('firewall-cmd', '--zone=' + zone, '--add-port=' + str(port) + '/tcp')
                run('firewall-cmd', '--permanent', '--zone=' + zone, '--add-port=' + str(port) + '/tcp')
    input('Apply any provider/manual firewall rules now, then press Enter to continue: ')


def test_mail(config):
    recipient = config['mail']['test_to'] if config.get('mail') else ask('Test recipient email', 'An inbox you can read now.', convert=email)
    message = EmailMessage()
    message['To'] = recipient
    message['Subject'] = 'SNode.C IDP deployment mail test'
    message.set_content('Mail transport test from ' + https_origin(config['hostname'], config['idp_port']) + '. No credentials are included.')
    if not shutil.which('systemd-run'):
        raise ValueError('Install systemd-run to test mail in the service sandbox')
    command = '/usr/bin/msmtp --file=' + str(CONFIG / 'mail/msmtprc') + ' -t' if config.get('mail') else config['smtp_command']
    # Use the same account and sandbox as the real IDP, including hidden homes.
    subprocess.run(['systemd-run', '--quiet', '--pipe', '--wait', '--collect', '--property=User=snodec-idp',
                    '--property=Group=snodec-idp', '--property=WorkingDirectory=' + str(DATA),
                    '--property=ProtectHome=yes', '--property=ProtectSystem=strict', '--property=PrivateTmp=yes',
                    '--property=NoNewPrivileges=yes', '/bin/sh', '-c', command],
                   input=message.as_bytes(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    if not yes('Did the test message arrive?', 'Check your inbox and spam folder. A successful SMTP submission alone does not prove receipt.'):
        raise ValueError('Mail receipt not confirmed; inspect the provider delivery logs and SMTP settings')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify_http(config):
    opener = urllib.request.build_opener(NoRedirect)
    for host, origin in http_targets(config).items():
        try:
            response = opener.open('http://' + host + '/auth/login', timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.status not in (301, 302, 303, 307, 308) or response.headers.get('Location') != origin + '/auth/login':
                raise ValueError('HTTP must redirect to the same HTTPS host/path: ' + host)
    with urllib.request.urlopen(https_origin(config['hostname'], config['idp_port']) + '/health', timeout=15) as response:
        if json.load(response).get('status') != 'ok':
            raise ValueError('IDP HTTPS health failed')
    if config.get('example'):
        with urllib.request.urlopen(https_origin(config['example']['hostname'], config['example']['port']) + '/', timeout=15) as response:
            if response.status != 200:
                raise ValueError('Application HTTPS homepage failed')
    for host, target in config.get('redirects', {}).items():
        try:
            response = opener.open(https_origin(host, config['idp_port']) + '/', timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.status != 303 or response.headers.get('Location') != target:
                raise ValueError('Configured HTTPS redirect failed: ' + host)



def checked_step(report, path, label, action):
    report['checks'][label] = 'pending'
    write(path, json.dumps(report, indent=2) + '\n')
    try:
        retry(label, action)
        report['checks'][label] = 'passed'
    except BaseException:
        report['checks'][label] = 'failed or interrupted'
        raise
    finally:
        write(path, json.dumps(report, indent=2) + '\n')


def interactive(path):
    if os.geteuid() != 0 or not sys.stdin.isatty():
        raise ValueError('Interactive setup requires root in a terminal')
    if path.exists() and path.stat().st_mode & 0o077:
        raise ValueError('Protect saved configuration first: chmod 600 ' + str(path))
    config = json.loads(path.read_text()) if path.exists() else {}
    print('Steps 1–3: The shell bootstrap installs published packages. This helper configures their deployment.\n'
          'Secrets are hidden at prompts and saved in mode-600 JSON. Enter keeps saved values.\n'
          'Without saved configuration, no deployment defaults are supplied; examples are not answers. Ctrl-C stops safely.\n'
          'If a step fails, correct the issue and retry, or rerun this command to change saved settings.')
    configured = False
    while not configured:
        try:
            collect_config(config)
            configured = True
        except ValueError as error:
            print('Configuration needs correction: ' + str(error))
    print('\nStep 8: Save protected configuration for ' + ', '.join(validate(config)))
    if not yes('Save and proceed?', 'This writes ' + str(path) + ', installs selected certificate/mail tools and may '
               'restart the configured services. Existing database keys and accounts are retained.'):
        raise RuntimeError('Stopped before saving or deployment')
    if path.exists():
        write(path.with_name(path.name + '.previous-' + str(time.time_ns())), path.read_text())
    write(path, json.dumps(config, indent=2) + '\n')
    report_path = path.with_name('deployment-report.json')
    report = {'hosts': validate(config), 'checks': {}, 'complete': False}
    write(report_path, json.dumps(report, indent=2) + '\n')
    mode = config.get('tls', {}).get('mode', 'letsencrypt')
    if mode == 'letsencrypt':
        checked_step(report, report_path, 'Install Certbot', lambda: install_packages('certbot'))
    if config.get('mail'):
        checked_step(report, report_path, 'Install SMTP transport', lambda: install_packages('msmtp'))
    checked_step(report, report_path, 'Network setup', lambda: network_setup(config))
    report['checks']['dns'] = 'passed from server resolver'
    write(report_path, json.dumps(report, indent=2) + '\n')
    print('\nStep 9: Provision persistent data, TLS and services')
    checked_step(report, report_path, 'Deployment', lambda: deploy(config))
    print('\nStep 10: Verify this deployment')
    checked_step(report, report_path, 'HTTPS and redirects', lambda: verify_http(config))
    report['checks']['https'] = 'passed from server; external browser test still required'
    if mode == 'letsencrypt':
        checked_step(report, report_path, 'Certificate renewal dry-run', lambda: run('certbot', 'renew', '--cert-name', 'snodec-idp', '--dry-run'))
        checked_step(report, report_path, 'HTTPS after renewal', lambda: verify_http(config))
        report['checks']['renewal'] = 'dry-run passed'
    else:
        report['checks']['renewal'] = choice('Certificate renewal',
            'For your certificate provider, configure and test renewal followed by restarting the SNode.C services. '
            'Record passed only after verifying it; this helper cannot test another provider automatically.',
            ('passed', 'failed', 'pending')) + ' (operator report)'
        write(report_path, json.dumps(report, indent=2) + '\n')
    if config.get('mail') or config.get('smtp_command'):
        checked_step(report, report_path, 'Send and confirm test email', lambda: test_mail(config))
        report['checks']['mail'] = 'test submitted; receipt confirmed by operator'
    else:
        report['checks']['mail'] = 'disabled by operator'
    print('Open the application in a browser on ANOTHER machine (outside the server network).\n'
          'The following answers are recorded as operator reports, not automated authentication tests.')
    app = https_origin(config['example']['hostname'], config['example']['port']) if config.get('example') else 'https://' + urlsplit(next(iter(config['clients'].values()))[0]).netloc
    browser_checks = {
        'external HTTPS': 'Open ' + app + ' and ' + https_origin(config['hostname'], config['idp_port']) + '/health; check trusted certificates and redirects.',
        'registration and MFA': 'Click Sign in, create a local account, scan its QR code with an authenticator, enter a TOTP and reach the protected application.',
        'logout and login': 'Sign out, then sign in again and confirm the protected application requires authentication.',
    }
    if config.get('google_client_id'):
        browser_checks['Google login'] = 'Use Google sign-in, complete consent and IDP TOTP, and confirm return to the application.'
    if config.get('mail') or config.get('smtp_command'):
        browser_checks['password recovery'] = 'Choose reset password, receive the email, follow the link, change the password and sign in again.'
    for name, instructions in browser_checks.items():
        report['checks'][name] = choice(name, instructions, ('passed', 'failed', 'pending')) + ' (operator report)'
        write(report_path, json.dumps(report, indent=2) + '\n')
    report['complete'] = all(not value.startswith(('failed', 'pending')) for value in report['checks'].values())
    write(report_path, json.dumps(report, indent=2) + '\n')
    print(('Deployment checks complete.' if report['complete'] else 'Deployment has FAILED/PENDING checks; do not treat it as verified.')
          + '\nReport: ' + str(report_path) + '\nRerun setup to correct saved choices. Preserve /etc/snodec-idp, '
          '/var/lib/snodec-idp and your certificate storage in backups.')
    return report['complete']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', nargs='?', type=Path, default=CONFIG / 'deployment.json', help='Protected deployment JSON file')
    parser.add_argument('--interactive', action='store_true', help='Explain, collect, provision and verify an interactive deployment')
    parser.add_argument('--check', action='store_true', help='Validate configuration without modifying the machine')
    args = parser.parse_args()
    status = 0
    if args.interactive:
        if args.check:
            parser.error('--interactive and --check cannot be combined')
        os.umask(0o077)
        status = 0 if interactive(args.config) else 2
    else:
        config = json.loads(args.config.read_text())
        hosts = validate(config)
        if args.check:
            print('Valid deployment configuration; HTTPS hosts: ' + ', '.join(hosts))
        else:
            if args.config.stat().st_mode & 0o077:
                raise ValueError('Deployment configuration must not be group/world accessible (chmod 600)')
            os.umask(0o077)
            deploy(config)
    return status


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.CalledProcessError, EOFError) as error:
        # Do not echo command output, environment or configuration secrets.
        detail = 'External command failed; inspect service journals and rerun setup.' if isinstance(error, subprocess.CalledProcessError) else str(error)
        raise SystemExit(detail)
    except KeyboardInterrupt:
        raise SystemExit('Stopped by operator; existing accounts and keys were not deleted.')
