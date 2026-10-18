#!/usr/bin/env bash
# Deploy core.snodec.org from the SNode.C binary package repository.
# Run ON THE ROOT SERVER, after reviewing this file:
#   sudo bash deploy-core-snodec-org.sh
# Use an interactive terminal. This script installs packages and, after explicit
# confirmation, starts the public deployment. It does not build source or run CI.
# This walkthrough chooses Let's Encrypt explicitly. For certificates from another
# provider or an existing TLS proxy, use your own certificate/proxy setup instead
# of step 9's Let's Encrypt helper. Installing the IDP does not install Certbot.
# The package's snodec-idp-deploy remains the single implementation of deployment:
# this walkthrough does not independently generate Nginx, keys or service units.
set -euo pipefail
umask 077

if [[ "$EUID" != 0 || ! -t 0 ]]; then
    printf '%s\n' 'Run as root in an interactive terminal: sudo bash deploy-core-snodec-org.sh' >&2
    exit 1
fi

# STEP 1 — Wait for signed packages for this server's exact OS and architecture.
# Check https://github.com/SNodeC/Packages/blob/main/docs/status/snodec-idp.md
# A green build for a different distribution/architecture is not sufficient.
# Repository preparation and installation below fail if the target is unavailable;
# do not substitute a different distribution's packages. No source build is needed.
# Keep the provider firewall/SSH access available while deploying.
printf '%s\n' 'Step 1: Confirm package availability for this server.'
cat /etc/os-release
uname -m
read -r -p 'Press Enter once the packages for this target are published: ' _

# STEP 2 — Prepare the signed binary repository, without installing all projects.
# Bootstrap HTTPS download tools using the OS repositories. Rocky additionally
# needs CRB/EPEL for the documented dependencies, including Certbot.
# The shared installer detects the installed OS/release/architecture and configures
# its signing key and repository. --prepare refreshes indexes only.
# See https://github.com/SNodeC/Packages/blob/main/docs/installation/README.md
# and https://github.com/SNodeC/Packages/blob/main/keys/README.md for trust/setup.
printf '%s\n' 'Step 2: Configure the SNode.C binary repository.'
. /etc/os-release
case "$ID" in
    debian|ubuntu)
        apt-get update
        apt-get install -y ca-certificates curl
        ;;
    rocky|fedora)
        dnf install -y ca-certificates curl
        if [[ "$ID" == rocky ]]; then
            dnf install -y dnf-plugins-core epel-release
            dnf config-manager --set-enabled crb
        fi
        ;;
    *) printf 'Unsupported server distribution: %s\n' "$ID" >&2; exit 1 ;;
esac
installer_dir=$(mktemp -d /tmp/snodec-idp-install.XXXXXX)
trap 'rm -rf -- "$installer_dir"' EXIT
curl --fail --silent --show-error --location \
    https://raw.githubusercontent.com/SNodeC/Packages/main/install/install.sh \
    --output "$installer_dir/install.sh"
sh "$installer_dir/install.sh" --prepare

# STEP 3 — Install the IDP and styled browser example, plus their dependencies.
# Inspect the package manager's proposed versions before accepting installation.
# Development packages are unnecessary for running these two applications.
# Installation supplies the IDP services but does not provision or start them;
# distribution dependency packages such as Nginx may have their own install hooks.
printf '%s\n' 'Step 3: Install the server and browser example.'
case "$ID" in
    debian|ubuntu) apt-get install snodec-idp snodec-idp-example ;;
    rocky|fedora) dnf install snodec-idp snodec-idp-example ;;
esac

# STEP 4 — Choose distinct IDP and application hostnames in step 8's JSON editor.
# hostname stays core.snodec.org. Replace app.example.org everywhere with the
# chosen application hostname: both example.hostname and clients' callback URL.
# The callback for this example is exactly https://APPLICATION_HOST/auth/callback.
# core.vchrist.at can be the application OR a redirect hostname, never both.
# If using it as the application, remove its entry from redirects. Otherwise set
# its redirect destination to the actual application URL. Omit unused redirects.
# To deploy only the IDP, remove example and register your real application's
# exact HTTPS callback under clients. The installed example will then stay unused.
printf '%s\n' 'Step 4: Choose the application hostname and any hostname redirects.'

# STEP 5 — Confirm public DNS and networking before requesting certificates.
# core.snodec.org already has DNS: verify its A/AAAA records reach THIS server.
# Do the same for the application and every configured redirect hostname. Each is
# included in the certificate, so one unreachable name can prevent issuance.
# Allow inbound TCP 80 and 443 in both the provider and host firewalls. Port 80
# serves ACME HTTP-01 challenges and redirects other requests to HTTPS; port 443
# serves HTTPS. Leave private backend ports 8083/8084 closed to the Internet.
# Check existing listeners with: ss -ltnp
# Reconcile existing Apache/Nginx sites for these names first. The deployment
# helper refuses exact Nginx hostname collisions and unrelated managed-path files.
# It does not change DNS, firewall rules or SELinux policy. On enforcing SELinux,
# authorize Nginx loopback proxy access according to your policy before deployment.
printf '%s\n' 'Step 5: Verify DNS, ports 80/443 and existing web-server ownership.'

# STEP 6 — Prepare Google login, if wanted, before editing the JSON.
# In Google Cloud, configure OAuth branding/audience and create a Web application
# OAuth client. Add this exact Authorized redirect URI:
#   https://core.snodec.org/auth/federated/google/callback
# This is Google's callback to the IDP, NOT the application's /auth/callback.
# Enter google_client_id and google_client_secret in step 8. With a testing
# audience, add the intended testers in Google. Leave both fields empty to disable
# Google; local password/TOTP login remains available. Never paste secrets into
# shell arguments, repository files or logs. Google users also enroll IDP TOTP.
printf '%s\n' 'Step 6: Prepare the Google Web OAuth client and callback URI.'

# STEP 7 — Configure real outgoing mail for password recovery.
# Install/configure a mail delivery program, for example msmtp, with your SMTP
# server, TLS, sender and credentials. It must read a complete message on stdin.
# Example smtp_command: /usr/bin/msmtp -t
# Use a system configuration readable by the snodec-idp service user, not a
# personal home-directory configuration: its systemd sandbox hides home directories.
# The helper creates that service user during deployment; after creating it,
# grant only the necessary access and test mail delivery as that user.
# Empty smtp_command disables delivery. The helper does not configure an SMTP
# account, install msmtp, or retrieve reset emails for you.
printf '%s\n' 'Step 7: Prepare SMTP delivery; enter its fixed command in the JSON.'

# STEP 8 — Create or edit the protected deployment configuration.
# An existing configuration is preserved and opened for editing, never replaced
# with defaults. Keep hostname=core.snodec.org; fill the application/redirect values
# from steps 4/5, your real acme_email, Google credentials and smtp_command.
# Set accept_acme_terms=true only after reviewing Let's Encrypt's agreement:
# https://letsencrypt.org/repository/
# The installed template deliberately has placeholder hosts/email and false terms
# acceptance. Replace them. --check validates syntax, not DNS, Google or SMTP.
# Do not edit generated idp.env/example.env/Nginx files: this JSON is their input.
printf '%s\n' 'Step 8: Edit /etc/snodec-idp/deployment.json.'
install -d -m 755 /etc/snodec-idp
if [[ ! -e /etc/snodec-idp/deployment.json ]]; then
    install -m 600 /usr/share/snodec-idp/deployment.example.json /etc/snodec-idp/deployment.json
fi
chmod 600 /etc/snodec-idp/deployment.json
# EDITOR may be an executable name/path (without command-line options).
"${EDITOR:-vi}" /etc/snodec-idp/deployment.json

# STEP 9 — Validate, explicitly choose Let's Encrypt and install Certbot, then deploy.
# Certbot is a deployment choice, not a required IDP package dependency. The helper
# used here supports Let's Encrypt; it does not import certificates from another CA.
# It creates service users, initial signing/TOTP keys and persistent data; configures
# loopback IDP/example listeners and Nginx; obtains a Let's Encrypt certificate for
# all configured hosts; starts services; enables the existing Certbot renewal timer;
# and installs a hook to validate/reload Nginx after successful renewal.
# Existing keys/accounts are preserved. A database without its original keys is
# rejected. Provisioning is not an all-or-nothing transaction: inspect errors before
# retrying. This command restarts configured services on subsequent deployments.
# Never delete /var/lib/snodec-idp or /etc/letsencrypt to retry a failed deployment.
printf '%s\n' 'Step 9: Validate the configuration.'
/usr/sbin/snodec-idp-deploy /etc/snodec-idp/deployment.json --check
read -r -p "Use Let's Encrypt, install Certbot and deploy now [yes/NO]: " deploy_answer
if [[ "$deploy_answer" != yes ]]; then
    printf '%s\n' 'Stopped before deployment. Installed packages and edited configuration are retained.'
    exit 0
fi
# Install the chosen certificate tooling explicitly, only after confirmation.
case "$ID" in
    debian|ubuntu) apt-get install certbot ;;
    rocky|fedora) dnf install certbot ;;
esac
/usr/sbin/snodec-idp-deploy /etc/snodec-idp/deployment.json

# STEP 10 — Verify HTTPS, renewal and all browser flows.
# HTTP below should return 308 with Location: https://core.snodec.org/auth/login.
# Health must succeed with a valid public TLS certificate; never use curl -k.
# The Certbot dry-run exercises renewal against its staging service; it does not
# replace the live certificate. This is a real network check, not a simulation.
# Also verify the configured application/redirect hostnames in the browser.
printf '%s\n' 'Step 10: Check HTTPS and certificate renewal.'
curl --silent --show-error --dump-header - --output /dev/null http://core.snodec.org/auth/login
curl --fail --silent --show-error https://core.snodec.org/health
printf '\n'
systemctl --no-pager status snodec-idp nginx
systemctl list-timers --all --no-pager 'certbot*'
certbot renew --cert-name snodec-idp --dry-run
# In a browser: open the application, select sign-in, create an account, enroll
# TOTP with an authenticator, and complete login back to /private. Test logout and
# re-login, Google login if enabled, and password reset with actual delivered mail.
# Do not consider deployment complete until these external flows work.
# Troubleshooting: journalctl -u snodec-idp -u snodec-idp-example -u nginx
# Back up /etc/snodec-idp, /var/lib/snodec-idp (SQLite online backup or stop first)
# and /etc/letsencrypt together. Preserve the signing and TOTP keys with the DB.
# For upgrades, update the selected packages and rerun snodec-idp-deploy against
# the same protected JSON. Package upgrades alone do not restart IDP services.
printf '%s\n' 'Automated checks finished. Complete the browser and real-email checks described in step 10.'
