<!-- snodec:begin page-header -->
<a id="banner"></a><a id="page-overview"></a>
<p><picture><source media="(max-width: 640px)" srcset="media/nav/banner-documentation-compact.svg"><img src="media/nav/banner-documentation.svg" alt="SNode.C IDP — Documentation" width="100%"></picture></p>
<p><a href="README.md#banner" title="Up to Documentation"><picture><source media="(prefers-color-scheme: dark)" srcset="media/nav/up-documentation-dark.svg"><img src="media/nav/up-documentation-light.svg" alt="Up to Documentation" title="Up to Documentation" width="160" height="28"></picture></a><a href="https://github.com/VolkerChristian#banner" title="Volker Christian account"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/account-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/account-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/account-dark.svg"><img align="right" src="media/nav/account-light.svg" alt="Volker Christian account" title="Volker Christian account"></picture></a><a href="https://github.com/SNodeC#banner" title="SNode.C organization"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/organization-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/organization-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/organization-dark.svg"><img align="right" src="media/nav/organization-light.svg" alt="SNode.C organization" title="SNode.C organization"></picture></a><a href="../README.md#banner" title="SNode.C IDP repository"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/repository-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/repository-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/repository-dark.svg"><img align="right" src="media/nav/repository-light.svg" alt="SNode.C IDP repository" title="SNode.C IDP repository"></picture></a><br clear="all"></p>
<!-- snodec:end page-header -->

# Install and deploy the packaged IDP

This is the ten-step binary-package deployment procedure for `core.snodec.org`, its browser application and optional redirect hostnames. It follows the [project-specific Packages installation guides](https://github.com/SNodeC/Packages/blob/main/docs/installation/README.md#banner). Availability is per distribution and architecture; check step 1 before installing.

The [commented shell script](../scripts/deploy-core-snodec-org.sh) follows the same ten steps. Review it, copy it to the root server and run `sudo bash deploy-core-snodec-org.sh` in an interactive terminal. It preserves existing configuration, opens an editor and asks before explicitly installing Certbot and deploying with Let's Encrypt. On Debian Sid, append `--suite sid`; use `--suite forky` if Forky is misdetected. You can instead execute the individual steps below. Commands use `sudo`; omit it when already logged in as root.

## Package selection

| Package | Installer component | Installs |
| --- | --- | --- |
| `snodec-idp` | `server` | IDP executable, systemd unit, deployment helper and configuration example |
| `snodec-idp-client-dev` | `client-dev` | Client library, headers and `snodec-auth` CMake package |
| `snodec-idp-server-dev` | `server-dev` | Embeddable IDP library and its client development dependency |
| `snodec-idp-example` | `example` | Optional styled application, static assets and systemd unit |

This walkthrough selects `server` and `example`. Development packages are unnecessary for running them. Client development does not install the IDP server. Certificate tooling is an operator choice: Certbot is not an IDP package dependency. The helper used here specifically implements Let's Encrypt; certificates from another provider or an existing TLS proxy require separately configured deployment.

## 1. Check package availability

On the server, identify the installed OS and architecture:

```sh
cat /etc/os-release
uname -m
```

Check [SNode.C IDP availability](https://github.com/SNodeC/Packages/blob/main/status/snodec-idp.md) for that exact target. A successful build for another target is insufficient. Use the matching distribution guide linked from [Packages installation](https://github.com/SNodeC/Packages/blob/main/docs/installation/README.md#banner). IDP packages support native Linux targets, including Raspberry Pi OS; there is no IDP OpenWrt recipe. The deployment helper requires a systemd host.

## 2. Prepare download tools

On Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install ca-certificates curl
```

On Fedora/Rocky:

```sh
sudo dnf install ca-certificates curl
```

On Rocky, also enable the dependency repositories described by the [Rocky repository guide](https://github.com/SNodeC/Packages/blob/main/docs/repositories/rocky-linux.md#banner):

```sh
sudo dnf install dnf-plugins-core epel-release
sudo dnf config-manager --set-enabled crb
```

The next step downloads both installer files into the same directory. `snodec-idp.sh` delegates platform detection, signing-key configuration and repository setup to `install.sh`. See the [signing-key guide](https://github.com/SNodeC/Packages/blob/main/keys/README.md#banner) for repository trust details.

## 3. Install the IDP and browser application

Run the project-specific installer with explicit components:

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

It configures the signed repository, refreshes indexes and installs the selected components and dependencies. On Debian Sid, append `--suite sid` to the installer invocation; use `--suite forky` if Forky is misdetected. This selects the installed release's repository; it does not upgrade the OS. For IDP-only deployment, omit `--component example` and remove `example` from step 8's configuration.

Verify both installed packages on Debian/Ubuntu:

```sh
dpkg-query -W -f='${Package} ${Version} ${Status}\n' snodec-idp snodec-idp-example
```

Or on Fedora/Rocky:

```sh
rpm -q snodec-idp snodec-idp-example
```

Installing the IDP packages does not provision or start their services. Distribution dependency packages such as Nginx may have their own installation hooks. Repository-only preparation remains available as `install.sh --prepare`, but is unnecessary before the project-specific installer.

## 4. Choose the application hostname and redirects

`core.snodec.org` serves the IDP. Choose a distinct application hostname: cookies are not isolated by port. The example callback must be exactly `https://APPLICATION_HOST/auth/callback`.

`core.vchrist.at` can serve the application **or** redirect to it. If it is the application hostname, remove its entry from `redirects`; one hostname cannot have both roles. Otherwise set its redirect destination to the real application URL. Do not leave `app.example.org` from the template in the production configuration.

## 5. Verify DNS, ports and web-server ownership

Verify the existing A/AAAA records for `core.snodec.org` reach this root server. Check the application and every redirect hostname too: all configured names are included in the certificate. Remove incorrect AAAA records rather than relying on IPv4 fallback.

Allow inbound TCP 80 and 443 through both provider and host firewalls. Port 80 handles ACME HTTP-01 validation and redirects other requests to HTTPS. Keep backend ports 8083/8084 private; services bind to loopback. Inspect existing listeners with `sudo ss -ltnp` and ensure those internal ports are available.

The helper manages `/etc/nginx/conf.d/snodec-idp.conf`. It rejects unrelated content there and exact hostname collisions with other Nginx sites. Reconcile any existing Apache/Nginx ownership of the requested hosts first. DNS, firewall rules and unrelated sites remain operator-managed. On SELinux-enforcing hosts, authorize Nginx loopback proxy connections according to local policy (commonly `httpd_can_network_connect`); the helper does not change SELinux policy.

## 6. Prepare Google login

For Google login, configure OAuth branding/audience and create a Web application OAuth client with this exact authorized redirect URI:

```text
https://core.snodec.org/auth/federated/google/callback
```

This is Google's callback to the IDP, separate from your application's `/auth/callback`. Retain the client ID and secret for step 8. If the Google audience is in testing, configure the intended test users. Leave both Google fields empty to disable federation while retaining local login.

The IDP requests `openid email profile`. Google identities still require IDP TOTP enrollment; equal-email local accounts are not automatically linked. See [Google federation](local-deployment.md#12-optional-google-login) for account-flow details.

## 7. Prepare outgoing email

Install and configure a mail delivery program such as `msmtp` with your SMTP server, TLS, sender and credentials. The fixed command, for example `/usr/bin/msmtp -t`, must accept the complete message on stdin. Enter it as `smtp_command` in step 8.

Use a system configuration accessible to the `snodec-idp` service user; its sandbox hides home directories. The deployment helper creates that user during provisioning. After it exists, grant only the required access and verify delivery as that user. The helper does not install/configure an SMTP account or mail program. Empty `smtp_command` disables delivery; reset links are never exposed in the browser as a substitute for email.

## 8. Configure the deployment

Create the configuration directory:

```sh
sudo install -d -m 755 /etc/snodec-idp
```

**On first setup only**, copy the template; do not overwrite an existing deployment configuration:

```sh
sudo install -m 600 /usr/share/snodec-idp/deployment.example.json \
  /etc/snodec-idp/deployment.json
```

Then edit it:

```sh
sudoedit /etc/snodec-idp/deployment.json
sudo chmod 600 /etc/snodec-idp/deployment.json
```

Set every applicable field:

- `hostname`: `core.snodec.org`.
- `acme_email`: your real contact email. Set `accept_acme_terms` to `true` after reviewing [Let's Encrypt's subscriber agreement](https://letsencrypt.org/repository/).
- `clients`: client IDs mapped to exact HTTPS callback URL lists. For the example, register `https://APPLICATION_HOST/auth/callback` under `minimal-mfa-app`. Wildcard callbacks are unsupported.
- `example`: set `hostname` to the chosen application host and `client_id` to `minimal-mfa-app`. Remove this object for IDP-only deployment.
- `redirects`: optional hostname-to-HTTPS-URL mapping, such as `core.vchrist.at` to the application URL. Remove it if that host serves the application instead.
- `google_client_id` and `google_client_secret`: both populated to enable Google, or both empty.
- `smtp_command`: the fixed mail command from step 7, or empty to disable delivery.

Do not commit secrets or pass them in shell arguments. This JSON is the operator-maintained input; `idp.env`, `example.env`, Nginx configuration and the public-key export are generated outputs. Edit the JSON and rerun deployment to change them.

## 9. Explicitly install Certbot and deploy with Let's Encrypt

For this Let's Encrypt deployment, install Certbot yourself on Debian/Ubuntu:

```sh
sudo apt-get install certbot
```

Or on Fedora/Rocky:

```sh
sudo dnf install certbot
```

Certbot must provide `certbot.timer` or `certbot-renew.timer`. If you use another certificate provider, configure that deployment separately: this helper does not import external certificates.

Validate and deploy:

```sh
sudo snodec-idp-deploy /etc/snodec-idp/deployment.json --check
sudo snodec-idp-deploy /etc/snodec-idp/deployment.json
```

`--check` validates configuration only; it does not verify DNS, networking or external credentials. Actual deployment checks prerequisites and hostname ownership, creates service users and initial keys/data, configures loopback listeners and Nginx, obtains certificates for all configured names, starts services and enables the existing Certbot renewal timer. HTTP redirects with status 308 to HTTPS except for ACME challenges. A renewal deploy hook validates/reloads Nginx.

Re-running setup preserves keys and accounts and restarts configured services. A database without its original signing or TOTP key is rejected. Existing-account updates first save a SQLite backup, keys and configuration under `/var/lib/snodec-idp/backups/`. A failed Nginx syntax check restores the previous site file, but deployment is not a complete rollback transaction: earlier provisioning steps may remain. Inspect errors and journals before retrying; never delete account data or keys to recover from a setup failure.

## 10. Verify HTTPS, renewal and browser flows

```sh
curl -I http://core.snodec.org/auth/login
curl --fail https://core.snodec.org/health
sudo systemctl --no-pager status snodec-idp nginx
sudo systemctl list-timers --all --no-pager 'certbot*'
sudo certbot renew --cert-name snodec-idp --dry-run
```

Expect HTTP 308 with an HTTPS location and a successful public HTTPS health response without bypassing certificate verification. The renewal dry-run contacts Certbot's staging service; it does not replace the live certificate. Verify HTTPS and redirect behavior on the other configured hosts as well.

Open the application in a browser and complete registration, TOTP enrollment, login back to `/private`, logout/relogin, Google login if enabled, and password reset using actual delivered mail. Check account settings and configured hostname redirects. The [local account-flow walkthrough](local-deployment.md) describes the UI flows; use your public hostnames here instead of localhost URLs. The helper's health check cannot prove Google consent or mail delivery.

For troubleshooting:

```sh
sudo journalctl -u snodec-idp -u snodec-idp-example -u nginx
```

## Upgrades, backups and removal

Upgrade with the normal package manager, then re-run deployment to apply configuration and restart against the updated binaries. Installation and upgrade do not start/restart this service automatically. The local deployment command has permission to restart the configured services.

Preserve `/etc/snodec-idp`, `/var/lib/snodec-idp`, and `/etc/letsencrypt`. Use SQLite’s online backup API or stop the IDP before copying its database. Signing and TOTP encryption keys are inseparable from account recovery; retain them with each database backup. Protect backups as secrets and apply your own retention policy.

To stop serving the deployment, disable `snodec-idp` and, if used, `snodec-idp-example`; remove only the managed Nginx site and validate/reload Nginx. Revoke/delete its certificate through Certbot when appropriate. Removing a package does not erase accounts, keys or configuration.

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
