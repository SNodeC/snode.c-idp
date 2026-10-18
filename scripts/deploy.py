#!/usr/bin/env python3
"""Explicit systemd/Nginx deployment. Package installation never calls this file."""
import argparse
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit

MARKER = '# Managed by snodec-idp-deploy\n'
CONFIG = Path('/etc/snodec-idp')
DATA = Path('/var/lib/snodec-idp')
SITE = Path('/etc/nginx/conf.d/snodec-idp.conf')
WEBROOT = Path('/var/www/snodec-idp-acme')
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
    if parsed.port not in (None, 443):
        raise ValueError('Public deployment uses HTTPS port 443')
    return value


def validate(config):
    allowed = {'hostname', 'acme_email', 'accept_acme_terms', 'clients', 'redirects',
               'google_client_id', 'google_client_secret', 'smtp_command', 'example'}
    if set(config) - allowed:
        raise ValueError('Unknown deployment configuration field')
    hostname(config['hostname'])
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', config['acme_email']):
        raise ValueError('An ACME contact email is required')
    if config.get('accept_acme_terms') is not True:
        raise ValueError('Set accept_acme_terms to true after reviewing the ACME terms')
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
        if set(example) != {'hostname', 'client_id'}:
            raise ValueError('example requires hostname and client_id only')
        host = hostname(example['hostname'])
        if host in hosts or 'https://' + host + '/auth/callback' not in config['clients'].get(example['client_id'], []):
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


def nginx_config(config, tls):
    hosts = validate(config)
    result = MARKER + 'server {\n    listen 80;\n    listen [::]:80;\n    server_name ' + ' '.join(hosts) + ';\n'
    result += '    location ^~ /.well-known/acme-challenge/ { root ' + str(WEBROOT) + '; }\n'
    result += '    location / { return 308 https://$host$request_uri; }\n}\n'
    if tls:
        groups = [(sorted({config['hostname'], *config.get('redirects', {})}), 8083)]
        if config.get('example'):
            groups.append(([config['example']['hostname']], 8084))
        for names, port in groups:
            result += ('server {\n    listen 443 ssl;\n    listen [::]:443 ssl;\n    server_name ' + ' '.join(names) + ';\n'
                       '    ssl_certificate ' + str(CERT / 'fullchain.pem') + ';\n'
                       '    ssl_certificate_key ' + str(CERT / 'privkey.pem') + ';\n'
                       '    ssl_protocols TLSv1.2 TLSv1.3;\n'
                       '    location / {\n        proxy_pass http://127.0.0.1:' + str(port) + ';\n'
                       '        proxy_set_header Host $host;\n        proxy_set_header Origin $http_origin;\n'
                       '        proxy_set_header X-Forwarded-Proto https;\n    }\n}\n')
    return result


def install_site(content):
    previous = SITE.read_text() if SITE.exists() else None
    if previous is not None and not previous.startswith(MARKER):
        raise ValueError('Refusing to overwrite an unmanaged Nginx site')
    write(SITE, content, 0o644)
    try:
        run('nginx', '-t')
    except subprocess.CalledProcessError:
        if previous is None:
            SITE.unlink()
        else:
            write(SITE, previous, 0o644)
        raise
    run('systemctl', 'enable', '--now', 'nginx')
    run('systemctl', 'reload', 'nginx')


def preflight(config):
    hosts = validate(config)
    if os.geteuid() != 0:
        raise ValueError('Deployment must run as root; --check needs no privilege')
    for binary in ('nginx', 'certbot', 'systemctl', 'systemd-sysusers', 'openssl', 'auth_idp'):
        if not shutil.which(binary):
            raise ValueError('Install required program: ' + binary)
    if config.get('example') and not shutil.which('minimal-mfa-app'):
        raise ValueError('Install snodec-idp-example before deploying it')
    if SITE.exists() and not SITE.read_text().startswith(MARKER):
        raise ValueError('Nginx site file is not owned by this deployment')
    effective = run('nginx', '-T')
    for section in effective.split('# configuration file '):
        if not section.startswith(str(SITE) + ':'):
            for names in re.findall(r'\bserver_name\s+([^;]+);', section):
                if set(names.split()) & set(hosts):
                    raise ValueError('A requested hostname is already owned by another Nginx site')
    if (DATA / 'auth.db').exists() and not all((DATA / 'keys' / key).is_file() for key in ('private.pem', 'totp.key')):
        raise ValueError('Restore original database keys before deployment')
    # Use the distribution's existing renewal scheduler, not a competing timer.
    timers = run('systemctl', 'list-unit-files', '--type=timer', '--no-legend')
    timer = next((name for name in ('certbot.timer', 'certbot-renew.timer') if name in timers), None)
    if timer is None:
        raise ValueError('Install the distribution Certbot renewal timer')
    return timer


def deploy(config):
    timer = preflight(config)
    CONFIG.mkdir(parents=True, exist_ok=True, mode=0o755)
    CONFIG.chmod(0o755)
    # Snapshot account data and keys before modifying generated configuration.
    if (DATA / 'auth.db').exists():
        backup = DATA / 'backups' / str(time.time_ns())
        backup.mkdir(parents=True, mode=0o700)
        with sqlite3.connect(DATA / 'auth.db') as source, sqlite3.connect(backup / 'auth.db') as target:
            source.backup(target)
        shutil.copytree(DATA / 'keys', backup / 'keys')
        shutil.copytree(CONFIG, backup / 'configuration')
        if SITE.exists():
            shutil.copy2(SITE, backup / 'nginx.conf')
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
    origin = 'https://' + config['hostname']
    values = dict(IDP_BASE_URL=origin, IDP_ISSUER=origin, IDP_PORT='8083', DB_PATH=str(DATA / 'auth.db'),
                  IDP_PRIVATE_KEY_PATH=str(DATA / 'keys/private.pem'), TOTP_KEY_PATH=str(DATA / 'keys/totp.key'),
                  IDP_CLIENTS=json.dumps(config['clients']), HOST_REDIRECTS=json.dumps(config.get('redirects', {})),
                  OAUTH_GOOGLE_CLIENT_ID=config.get('google_client_id', ''),
                  OAUTH_GOOGLE_CLIENT_SECRET=config.get('google_client_secret', ''), SMTP_COMMAND=config.get('smtp_command', ''),
                  PROTECTED_WEBAPP_URL='https://' + example['hostname'] if example else '')
    write(CONFIG / 'idp.env', environment(values))
    write(CONFIG / 'empty.conf', '', 0o644)
    write(CONFIG / 'public.pem', public, 0o644)
    services = ['snodec-idp']
    if example:
        write(CONFIG / 'example.env', environment(dict(IDP_BASE_URL=origin, APP_CLIENT_ID=example['client_id'],
              APP_CALLBACK_URL='https://' + example['hostname'] + '/auth/callback', APP_PORT='8084', IDP_PUBLIC_KEY_PATH=str(CONFIG / 'public.pem'))))
        services.append('snodec-idp-example')
    elif (CONFIG / 'example.env').exists():
        run('systemctl', 'disable', '--now', 'snodec-idp-example')
        (CONFIG / 'example.env').unlink()
    WEBROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
    WEBROOT.chmod(0o755)
    install_site(nginx_config(config, (CERT / 'fullchain.pem').exists()))
    write(Path('/etc/letsencrypt/renewal-hooks/deploy/snodec-idp'),
          '#!/bin/sh\nset -eu\nnginx -t\nsystemctl reload nginx\n', 0o755)
    previous_umask = os.umask(0o022)
    try:
        run('certbot', 'certonly', '--non-interactive', '--agree-tos', '--email', config['acme_email'],
            '--webroot', '-w', str(WEBROOT), '--cert-name', 'snodec-idp', '--renew-with-new-domains',
            '-d', ','.join(validate(config)))
    finally:
        os.umask(previous_umask)
    install_site(nginx_config(config, True))
    run('systemctl', 'daemon-reload')
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
    print('Deployed ' + origin + '; renewal scheduler: ' + timer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config', type=Path, help='Protected deployment JSON file')
    parser.add_argument('--check', action='store_true', help='Validate configuration without modifying the machine')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    hosts = validate(config)
    if args.check:
        print('Valid deployment configuration; HTTPS hosts: ' + ', '.join(hosts))
    else:
        if args.config.stat().st_mode & 0o077:
            raise ValueError('Deployment configuration must not be group/world accessible (chmod 600)')
        os.umask(0o077)
        deploy(config)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        # Do not echo command output, environment or configuration secrets.
        raise SystemExit(str(error))
