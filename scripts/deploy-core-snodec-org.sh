#!/usr/bin/env bash
# Interactive package deployment for core.snodec.org (hostnames remain configurable).
# Download and run only this script. It fetches its pinned Python helper below,
# using the same source installed as snodec-idp-deploy before package rebuilds.
# Run ON THE SERVER: sudo bash deploy-core-snodec-org.sh [--suite sid]
# Guide: https://github.com/SNodeC/snode.c-idp/blob/main/docs/package-deployment.md
# No CI, release tag, source compilation or public deployment is started until you
# execute this file. Secrets are collected later with hidden Python getpass prompts.
set -euo pipefail
export LC_ALL=C
umask 077
if [[ "$EUID" != 0 || ! -t 0 ]]; then
    printf '%s\n' 'Run as root in an interactive terminal: sudo bash deploy-core-snodec-org.sh' >&2
    exit 1
fi
# STEP 1 — Detect the installed distribution. The shared repository installer checks
# target availability before repository configuration. Never use another OS's suite.
# Check https://github.com/SNodeC/Packages/blob/main/status/snodec-idp.md if unavailable.
. /etc/os-release
printf 'Server: %s (%s)\n' "$PRETTY_NAME" "$(uname -m)"
# STEP 2 — Install download/runtime tools. iproute provides the listener inspection.
# Rocky needs CRB/EPEL for its documented native dependencies. SSH rules are untouched.
case "$ID" in
    debian|ubuntu)
        apt-get update
        apt-get install -y ca-certificates curl python3 iproute2
        ;;
    rocky|fedora)
        dnf install -y ca-certificates curl python3 iproute
        if [[ "$ID" == rocky ]]; then
            dnf install -y dnf-plugins-core epel-release
            dnf config-manager --set-enabled crb
        fi
        ;;
    *) printf 'Unsupported server distribution: %s\n' "$ID" >&2; exit 1 ;;
esac
installer_directory=$(mktemp -d /tmp/snodec-idp-install.XXXXXX)
trap 'rm -rf -- "$installer_directory"' EXIT
# Pin the helper by Git blob ID, independent of branch/tag movement. When deploy.py
# changes, update this value using: git hash-object scripts/deploy.py
helper_blob=429d471a321ebe30646f1002690e7be55d74cb77
curl --fail --silent --show-error --location --header 'Accept: application/vnd.github.raw+json' \
    "https://api.github.com/repos/SNodeC/snode.c-idp/git/blobs/$helper_blob" \
    --output "$installer_directory/deploy.py"
for installer in install.sh snodec-idp.sh; do
    curl --fail --silent --show-error --location \
        "https://raw.githubusercontent.com/SNodeC/Packages/main/install/$installer" \
        --output "$installer_directory/$installer"
done
# STEP 3 — The project installer configures the signed repository and installs only
# server/example components and dependencies. The example can be left disabled in
# the following prompts. Certbot and SMTP tools are selected explicitly later.
sh "$installer_directory/snodec-idp.sh" --component server --component example "$@"
# The SAME deployment helper now performs steps 4–10 interactively:
# STEP 4 — Explain and collect IDP/application hostnames, exact OAuth callbacks and
# public HTTPS ports (e.g. IDP 8088/application 443) and optional redirects. Existing client registrations survive unless explicitly changed.
# STEP 5 — Ask for public IPs, resolve every DNS name, inspect listeners, offer changes
# to active UFW/firewalld, and guide provider-firewall integration.
# External actions pause for confirmation; DNS/HTTPS are checked, not merely listed.
# STEP 6 — Explain Google Cloud Branding/Audience/Clients, show the exact callback,
# collect the client ID and hidden secret, or explicitly disable Google federation.
# STEP 7 — Explain SMTP settings, securely collect them and configure a dedicated
# msmtp transport, retain an existing mail command, or explicitly disable email.
# STEP 8 — Use /etc/snodec-idp/deployment.json as the only configuration source.
# Saved values are editable defaults (secrets hidden); absent JSON gives no defaults.
# Examples are explanations only. Validate/save mode-600 JSON and back up old JSON.
# STEP 9 — Install Certbot ONLY for Let's Encrypt or validate existing certificates;
# use standalone ACME validation on port 80. SNode.C serves public HTTPS directly.
# Provision persistent keys/data, private systemd TLS credentials and services.
# STEP 10 — Check HTTPS/redirects/renewal, send a real test email as the service user,
# ask the operator to complete browser flows, and write a pass/fail/pending report.
# Run the downloaded helper; the EXIT trap removes all temporary downloads.
# Rerun this same entry point to adjust saved JSON; the installed helper is untouched.
python3 "$installer_directory/deploy.py" --interactive
