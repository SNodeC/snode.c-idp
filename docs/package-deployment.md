<!-- snodec:begin page-header -->
<a id="banner"></a><a id="page-overview"></a>
<p><picture><source media="(max-width: 640px)" srcset="media/nav/banner-documentation-compact.svg"><img src="media/nav/banner-documentation.svg" alt="SNode.C IDP — Documentation" width="100%"></picture></p>
<p><a href="README.md#banner" title="Up to Documentation"><picture><source media="(prefers-color-scheme: dark)" srcset="media/nav/up-documentation-dark.svg"><img src="media/nav/up-documentation-light.svg" alt="Up to Documentation" title="Up to Documentation" width="160" height="28"></picture></a><a href="https://github.com/VolkerChristian#banner" title="Volker Christian account"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/account-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/account-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/account-dark.svg"><img align="right" src="media/nav/account-light.svg" alt="Volker Christian account" title="Volker Christian account"></picture></a><a href="https://github.com/SNodeC#banner" title="SNode.C organization"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/organization-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/organization-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/organization-dark.svg"><img align="right" src="media/nav/organization-light.svg" alt="SNode.C organization" title="SNode.C organization"></picture></a><a href="../README.md#banner" title="SNode.C IDP repository"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/repository-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/repository-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/repository-dark.svg"><img align="right" src="media/nav/repository-light.svg" alt="SNode.C IDP repository" title="SNode.C IDP repository"></picture></a><br clear="all"></p>
<!-- snodec:end page-header -->

# Install and deploy the packaged IDP

This is the ten-step binary-package deployment procedure for `core.snodec.org`, its browser application and optional redirect hostnames. It follows the [project-specific Packages installation guides](https://github.com/SNodeC/Packages/blob/main/docs/installation/README.md#banner). Availability is per distribution and architecture; check step 1 before installing.

The [interactive shell script](../scripts/deploy-core-snodec-org.sh) executes these ten steps using the same [deployment helper](../scripts/deploy.py) installed by the server package. It asks explained questions, saves configuration, provisions services and records verification results. External provider actions (DNS, Google credentials, hosting firewall) pause for you to complete them; the script cannot administer those accounts without access.

Download **only the shell script** from the reviewed commit onto your server:

```sh
# Replace REVISION with the full commit ID containing the reviewed setup.
revision=REVISION
mkdir -p snodec-idp-setup
cd snodec-idp-setup
curl --fail --show-error --location \
  "https://raw.githubusercontent.com/SNodeC/snode.c-idp/$revision/scripts/deploy-core-snodec-org.sh" \
  -o deploy-core-snodec-org.sh
# Review the script before running as root.
sudo bash deploy-core-snodec-org.sh
```

The shell installs Python and download tools, fetches its pinned matching helper automatically, and runs the interactive setup. You do not download or execute Python separately. Temporary downloads are removed on exit; a failed download stops setup before the project installer runs. Rerun the same shell script to adjust saved configuration.

**Install packages rebuilt with direct TLS before using this procedure.** The former loopback/Nginx packages (including `2.0.2-5~trixie`) cannot provide this deployment. Updating the downloaded helper alone is insufficient; it rejects their service units. Wait for the corrected packages to be published, then use a published commit containing the matching script and helper. On Debian Sid, append `--suite sid` to the shell invocation; use `--suite forky` if Forky is misdetected. Neither option upgrades the OS.

The ten steps below explain what the script does, which answers it needs and which external actions you must complete. Commands within those steps are for manual installation or verification; do not repeat installation commands while the script is handling them. Commands use `sudo`; omit it when logged in as root. If `curl` is missing when downloading the script, install it and `ca-certificates` using your distribution's commands in step 2.

## Package selection

| Package | Installer component | Installs |
| --- | --- | --- |
| `snodec-idp` | `server` | IDP executable, systemd unit, deployment helper and configuration example |
| `snodec-idp-client-dev` | `client-dev` | Client library, headers and `snodec-auth` CMake package |
| `snodec-idp-server-dev` | `server-dev` | Embeddable IDP library and its client development dependency |
| `snodec-idp-example` | `example` | Optional styled application, static assets and systemd unit |

This walkthrough selects `server` and `example`. Development packages are unnecessary for running them. Client development does not install the IDP server. Certificate tooling is an operator choice: Certbot is not an IDP package dependency. The helper supports Let's Encrypt or existing PEM certificates. SNode.C serves HTTPS directly; neither Nginx nor Certbot is a package dependency.

## 1. Check package availability

On the server, identify the installed OS and architecture:

```sh
cat /etc/os-release
uname -m
```

Check [SNode.C IDP availability](https://github.com/SNodeC/Packages/blob/main/status/snodec-idp.md) for that exact target. A successful build for another target is insufficient. Use the matching distribution guide linked from [Packages installation](https://github.com/SNodeC/Packages/blob/main/docs/installation/README.md#banner). IDP packages support native Linux targets, including Raspberry Pi OS; there is no IDP OpenWrt recipe. The deployment helper requires a systemd host.

## 2. Prepare download tools

The script installs these prerequisites automatically before downloading its helper. For manual setup, on Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install ca-certificates curl python3 iproute2
```

On Fedora/Rocky:

```sh
sudo dnf install ca-certificates curl python3 iproute
```

On Rocky, also enable the dependency repositories described by the [Rocky repository guide](https://github.com/SNodeC/Packages/blob/main/docs/repositories/rocky-linux.md#banner):

```sh
sudo dnf install dnf-plugins-core epel-release
sudo dnf config-manager --set-enabled crb
```

The script handles the project installer and its shared repository helper internally. The manual equivalent is shown in step 3. See the [signing-key guide](https://github.com/SNodeC/Packages/blob/main/keys/README.md#banner) for repository trust details.

## 3. Install the IDP and browser application

The script selects the `server` and `example` components using the project-specific package installer. For manual package installation only, the equivalent is:

```sh
(
  set -eu
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  base=https://raw.githubusercontent.com/SNodeC/Packages/main/install
  for script in install.sh snodec-idp.sh; do
    curl -fsSL "$base/$script" -o "$tmp/$script"
  done
  sudo sh "$tmp/snodec-idp.sh" --component server --component example
)
```

It configures the signed repository, refreshes indexes and installs the selected components and dependencies. On Debian Sid, append `--suite sid` to the installer invocation; use `--suite forky` if Forky is misdetected. This selects the installed release's repository; it does not upgrade the OS. The interactive setup lets you leave the installed example disabled and register an application you already run. For manual IDP-only installation, omit `--component example` and omit `example` from step 8's configuration.

Verify both installed packages on Debian/Ubuntu:

```sh
dpkg-query -W -f='${Package} ${Version} ${Status}\n' snodec-idp snodec-idp-example
```

Or on Fedora/Rocky:

```sh
rpm -q snodec-idp snodec-idp-example
```

Installing the IDP packages does not provision or start their services. Repository-only preparation remains available as `install.sh --prepare`, but is unnecessary before the project-specific installer.

## 4. Choose the application hostname and redirects

`core.snodec.org` serves the IDP on configurable port **8088**, and `core.vchrist.at` serves the application on configurable port **443**. Both listeners use the same server IP directly. The example callback is exactly `https://core.vchrist.at/auth/callback`. For another application port, include that port in the callback. Keep distinct hostnames: browser cookies are not isolated by port.

`core.vchrist.at` can serve the application **or** redirect to it. If it is the application hostname, remove its entry from `redirects`; one hostname cannot have both roles. Otherwise set its redirect destination to the real application URL. Enter your actual hostnames at the prompts; names such as `app.example.org` are explanatory examples.

## 5. Verify DNS, ports and web-server ownership

Point the A records for the IDP, application and any redirect hostname to this server's public IPv4 address. These packaged services bind IPv4 (`0.0.0.0`); remove AAAA records for these names unless you separately configure and verify IPv6 listeners. All configured hostnames need certificate coverage.

Allow inbound TCP **80, 443 and 8088** through provider and host firewalls for this example. Substitute your selected HTTPS ports if different. The IDP owns port 80 and redirects recognized hostnames to their configured HTTPS origins, preserving path and query. Unknown hostnames receive 404. On the IDP HTTPS port, optional `redirects` instead send the configured fixed destination with status 303.

Copy the public IPv4 address from [Hetzner Console](https://console.hetzner.com/) → project → server → Networking. The wizard records `public_ips`, checks every DNS answer and inspects listeners with `ss -ltnp`. Unrelated owners of any required port are rejected; no unrelated service is stopped. Neither application uses a reverse proxy.

The wizard offers the selected TCP ports to an **already active** UFW or selected firewalld zone after confirmation. It never enables or flushes a firewall and leaves SSH rules alone. Configure nftables/iptables and the [Hetzner firewall](https://docs.hetzner.com/cloud/firewalls/getting-started/creating-a-firewall/) yourself when applicable. The wizard pauses for provider changes before continuing.

Choose certificate ownership explicitly:

| `tls.mode` | Setup action | Renewal owner |
| --- | --- | --- |
| `letsencrypt` | Explicitly install Certbot and obtain a certificate covering all configured hosts using standalone HTTP-01 on port 80 | Distribution Certbot timer; hooks stop/start the IDP and restart services after renewal |
| `files` | Validate your full-chain PEM and unencrypted private key: trust, expiry, names and key match | Your CA tooling, followed by restarting the SNode.C services |

For `files`, supply absolute paths such as `/etc/ssl/my-idp/fullchain.pem` and `/etc/ssl/my-idp/privkey.pem`, without spaces or shell characters. Keep the private key mode 600. Systemd `LoadCredential` provides private copies to the unprivileged service accounts; do not make keys world-readable. Certbot is not installed in this mode.

With Let's Encrypt, issuance and renewal briefly stop the IDP to free port 80 for Certbot, then start it again. The application stays running, although authentication needs the IDP. The renewal deploy hook refreshes service credentials by restarting the active services. Switching certificate ownership does not delete existing certificates or disable a shared timer; review obsolete lineages yourself.

## 6. Prepare Google login

Open [Google Auth Platform](https://console.cloud.google.com/auth/overview), select or create a project, then configure Branding and Audience. Under Clients, create a **Web application** client with this exact authorized redirect URI:

```text
https://core.snodec.org:8088/auth/federated/google/callback
```

Use the selected IDP port in this URI; the wizard prints the exact value. This is Google's callback to the IDP, separate from your application's `/auth/callback`. Enter its client ID and secret when prompted; the secret input is hidden. If the Google audience is in testing, configure the intended test users. Choose no at the Google-login prompt to retain local login without federation; in manual configuration, leave both Google fields empty.

The IDP requests `openid email profile`. Google identities still require IDP TOTP enrollment; equal-email local accounts are not automatically linked. See [Google federation](local-deployment.md#12-optional-google-login) for account-flow details.

## 7. Prepare outgoing email

Choose `smtp`, `command` or `disabled` in the wizard:

- **smtp:** obtain the outgoing SMTP hostname, port and encryption setting from your mail provider. STARTTLS commonly uses 587; implicit TLS commonly uses 465. Enter the actual provider settings, an authorized sender, username and password/app password, plus an inbox you can read for a test. Password input is hidden. The wizard explicitly installs `msmtp` and writes `/etc/snodec-idp/mail/msmtprc`, readable only by root and the service group (mode 640, directory 750). TLS certificate verification remains enabled; the sender is configured explicitly.
- **command:** retain or supply a working, trusted command such as `/usr/bin/msmtp -t`. Install/configure your chosen transport yourself before continuing. It must accept an RFC email message on stdin and work as `snodec-idp` with home directories hidden. Keep passwords out of command arguments.
- **disabled:** explicitly disable recovery mail. Reset links are not exposed in the browser as a substitute.

For a provider requiring app passwords, create one in its account security settings; an OAuth client secret is not an SMTP password. An authorized unauthenticated relay can use an empty username; enter `-` to clear a saved username. The test runs under the service account and relevant systemd sandbox restrictions, then asks whether the message arrived, including the spam folder. Submission alone is not successful delivery.

## 8. Configure the deployment

**`/etc/snodec-idp/deployment.json` is the sole configuration source.** Existing values are shown as editable defaults; Enter accepts them. Secret prompts hide input and show only “Enter keeps saved value”. Without that JSON, there are no prefilled deployment answers: examples are explanations, and required inputs and choices must be supplied explicitly. The wizard does not copy the packaged example into place.

The wizard validates and saves configuration after asking you to proceed. It protects the JSON with mode 600 and preserves an existing file as `deployment.json.previous-TIMESTAMP`. To configure manually, create `/etc/snodec-idp/deployment.json` with mode 600 and use the following fields; the packaged example is a reference only.

| Field | Meaning |
| --- | --- |
| `hostname` | Public IDP DNS name, e.g. `core.snodec.org` |
| `idp_port` | Public IDP HTTPS port, e.g. `8088`; cannot be 80 or the example port |
| `public_ips` | List of this server's public IPv4 addresses; checked against all configured names |
| `clients` | Client IDs mapped to lists of exact HTTPS callbacks; no wildcard callbacks |
| `example` | Optional object with `hostname`, `port` (e.g. `443`) and `client_id`; exact callback includes a nonstandard port |
| `redirects` | Optional hostname-to-HTTPS-destination mapping |
| `tls` | Object containing `mode`: `letsencrypt` or `files`; files additionally needs `certificate` and `private_key` paths |
| `acme_email`, `accept_acme_terms` | Required in Let's Encrypt mode; real contact email and explicit acceptance of [ACME terms](https://letsencrypt.org/repository/) |
| `google_client_id`, `google_client_secret` | Both populated for Google, otherwise empty |
| `mail` | Optional managed SMTP object with `host`, numeric `port`, `tls` (`starttls` or `implicit`), `username`, `password`, `from`, `test_to` |
| `smtp_command` | Fixed mail command, or empty; cannot be used together with `mail` |

Existing JSON needs explicit `idp_port` and `example.port` values. The wizard asks for missing values; it does not invent defaults. Noninteractive configurations without `tls` retain Let's Encrypt behavior, and `public_ips` is optional outside the wizard. That compatibility does not supply first-run interactive defaults. On rerun the wizard preserves complete saved callback lists; replacing a list or redirects is explicit. You may edit JSON to remove obsolete clients.

Do not commit secrets or pass them in shell arguments. `idp.env`, `example.env`, msmtp configuration and systemd TLS credential drop-ins, and the public-key export are generated outputs; edit the JSON or rerun the wizard to change them. Protect previous JSON copies and account backups as secrets.

## 9. Provision certificates, persistent state and services

The wizard installs Certbot explicitly only when you choose Let's Encrypt. For manual Let's Encrypt deployment on Debian/Ubuntu:

```sh
sudo apt-get install certbot
```

Or on Fedora/Rocky:

```sh
sudo dnf install certbot
```

Certbot must provide `certbot.timer` or `certbot-renew.timer`. In files mode, skip Certbot installation and provide the settings from steps 5 and 8. For managed SMTP, install `msmtp` explicitly too (`apt-get install msmtp` or `dnf install msmtp`).

Validate and deploy:

```sh
sudo snodec-idp-deploy /etc/snodec-idp/deployment.json --check
sudo snodec-idp-deploy /etc/snodec-idp/deployment.json
```

`--check` validates configuration only; it does not verify DNS, networking or external credentials. Actual deployment requires rebuilt direct-TLS executables and service units, checks prerequisites and listener ownership, creates service users and initial keys/data, obtains or checks certificates, writes environment files and credential drop-ins, then starts services. Let's Encrypt mode enables the installed Certbot renewal timer. Both programs terminate TLS themselves. The IDP also serves HTTP-to-HTTPS redirects on port 80.

Re-running setup preserves keys and accounts and restarts configured services. A database without its original signing or TOTP key is rejected. Existing-account updates first save a SQLite backup, keys and configuration under `/var/lib/snodec-idp/backups/`. Deployment is not a complete rollback transaction: earlier provisioning steps may remain after an error. Inspect errors and journals before retrying; never delete account data or keys to recover from a setup failure.

## 10. Verify HTTPS, renewal and browser flows

The wizard automatically checks trusted HTTPS, HTTP redirects, configured hostname redirects, IDP health and the example homepage. In Let's Encrypt mode it runs a renewal dry-run. With another certificate owner, configure/test renewal and record its result explicitly. Enabled mail delivery sends a real test and requires receipt confirmation.

Open the application on **another machine**, outside the server network. Follow each explained browser check and answer `passed`, `failed` or `pending`; do not mark a check passed without performing it. The report at `/etc/snodec-idp/deployment-report.json` distinguishes automated checks from operator reports. Failures/interruption are recorded. Any failed or pending browser/renewal check leaves `complete: false` and returns exit status 2. A server-side health response alone never completes browser verification.

For manual checks (Certbot commands apply only to Let's Encrypt):

```sh
curl -I http://core.snodec.org/auth/login
curl --fail https://core.snodec.org:8088/health
sudo systemctl --no-pager status snodec-idp snodec-idp-example
sudo systemctl list-timers --all --no-pager 'certbot*'
sudo certbot renew --cert-name snodec-idp --dry-run
```

Expect HTTP 308 with `https://core.snodec.org:8088/auth/login` as its location and a successful public HTTPS health response without bypassing certificate verification. The renewal dry-run contacts Certbot's staging service; it does not replace the live certificate, but its pre/post hooks also briefly stop/start the IDP. Check HTTPS again afterwards. Verify HTTPS and redirect behavior on the other configured hosts as well.

Open the application in a browser and complete registration, TOTP enrollment, login back to `/private`, logout/relogin, Google login if enabled, and password reset using actual delivered mail. Check account settings and configured hostname redirects. The [local account-flow walkthrough](local-deployment.md) describes the UI flows; use your public hostnames here instead of localhost URLs. The helper's health check cannot prove Google consent or mail delivery.

For troubleshooting:

```sh
sudo journalctl -u snodec-idp -u snodec-idp-example
```

## Upgrades, backups and removal

Upgrade with the normal package manager, then re-run deployment to apply configuration and restart against the updated binaries. Installation and upgrade do not start/restart this service automatically. The local deployment command has permission to restart the configured services.

Preserve `/etc/snodec-idp`, `/var/lib/snodec-idp`, and your certificate storage (`/etc/letsencrypt` for Let's Encrypt). Use SQLite’s online backup API or stop the IDP before copying its database. Signing and TOTP encryption keys are inseparable from account recovery; retain them with each database backup. Protect backups as secrets and apply your own retention policy.

To stop serving the deployment, disable `snodec-idp` and, if used, `snodec-idp-example`. Revoke/delete its certificate through Certbot when appropriate. Removing a package does not erase accounts, keys or configuration. If migrating an older proxy deployment, stop and remove only its dedicated proxy configuration after checking it does not serve unrelated applications. The corrected setup does not remove existing proxy installations automatically.

## Build and CI contract

```sh
cmake -S . -B build/codex/packages -G Ninja \
  -DCMAKE_INSTALL_PREFIX=/usr -DAUTH_BUILD_EXAMPLE=ON
cmake --build build/codex/packages --parallel
ctest --test-dir build/codex/packages --output-on-failure
(cd build/codex/packages && cpack -G DEB) # RPM on an RPM build host
```

Native packaging uses the installed SNode.C development packages and normal distribution dependency discovery. Package inventories derive from CPack components. CI starts only for version tags, explicit manual release builds, or authenticated dependent-build requests after SNode.C publication. Ordinary documentation/source branch pushes do not start package builds. Source changes become package releases through matching `vMAJOR.MINOR.PATCH` tags.

CI builds unsigned artifacts; DistributionPackages validates their repository, workflow, run, target and capture, then signs and publishes them. Runtime credentials, ACME state and signing secrets never enter the IDP build workflow. Check the published target status before deploying; a source merge or successful build alone does not establish signed package availability. Documentation updates do not require a release tag or workflow dispatch.
