<!-- snodec:begin page-header -->
<a id="banner"></a><a id="page-overview"></a>
<p><picture><source media="(max-width: 640px)" srcset="media/nav/banner-documentation-compact.svg"><img src="media/nav/banner-documentation.svg" alt="SNode.C IDP — Documentation" width="100%"></picture></p>
<p><a href="README.md#banner" title="Up to Documentation"><picture><source media="(prefers-color-scheme: dark)" srcset="media/nav/up-documentation-dark.svg"><img src="media/nav/up-documentation-light.svg" alt="Up to Documentation" title="Up to Documentation" width="160" height="28"></picture></a><a href="https://github.com/VolkerChristian#banner" title="Volker Christian account"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/account-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/account-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/account-dark.svg"><img align="right" src="media/nav/account-light.svg" alt="Volker Christian account" title="Volker Christian account"></picture></a><a href="https://github.com/SNodeC#banner" title="SNode.C organization"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/organization-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/organization-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/organization-dark.svg"><img align="right" src="media/nav/organization-light.svg" alt="SNode.C organization" title="SNode.C organization"></picture></a><a href="../README.md#banner" title="SNode.C IDP repository"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/repository-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/repository-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/repository-dark.svg"><img align="right" src="media/nav/repository-light.svg" alt="SNode.C IDP repository" title="SNode.C IDP repository"></picture></a><br clear="all"></p>
<!-- snodec:end page-header -->

# Install and deploy the packaged IDP

The package build and deployment tooling is prepared locally. Packages must be built, signed and published before the repository installation commands below can succeed. No public release or root-server deployment is implied by this guide.

## Package selection

| Package | Installs |
| --- | --- |
| `snodec-idp` | IDP executable, systemd unit, deployment helper and configuration example |
| `snodec-idp-client-dev` | Client library, headers and `snodec-auth` CMake package |
| `snodec-idp-server-dev` | Embeddable IDP library and its client development dependency |
| `snodec-idp-example` | Optional styled application, static assets and systemd unit |

Server installation does not require development packages or the example. Client development does not install the IDP server. The `auth-client`, `auth-idp` and `auth_idp` CMake install component names remain compatible; CPack maps them to distribution package names.

## Before deployment

Use a supported native Linux distribution with systemd, Nginx and Certbot. IDP packages use the native DistributionPackages targets, including Raspberry Pi OS; there is no IDP OpenWrt recipe. Set DNS A/AAAA records for every public hostname to this server. Port 80 must reach Nginx for HTTP-01 challenges, and port 443 must be reachable by browsers. Remove incorrect AAAA records rather than relying on IPv4 fallback.

The helper manages only `/etc/nginx/conf.d/snodec-idp.conf`. It rejects an existing unrelated file there and exact hostname collisions in other Nginx sites. If Apache or another service owns ports 80/443, arrange the web-server integration before running setup. Existing unrelated Nginx sites remain operator-owned. Firewall and DNS changes are not performed by the helper.

Keep the IDP and application on separate hostnames: browser cookies are not isolated by port. The service listeners bind to `127.0.0.1:8083` and `127.0.0.1:8084`. Ensure those internal ports are available.

## Install published packages

Configure the signed repository using the [Packages installation guide](https://github.com/SNodeC/Packages/blob/main/docs/installation/README.md#banner). Choose the installer’s `--prepare` mode when you want to select packages explicitly.

On Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install snodec-idp snodec-idp-example
```

On Fedora/Rocky Linux:

```sh
sudo dnf install snodec-idp snodec-idp-example
```

The IDP package requires Nginx, Certbot, Python, OpenSSL and systemd. On SELinux-enforcing hosts, authorize Nginx’s loopback proxy connections according to your local policy (commonly `httpd_can_network_connect`); the helper does not disable SELinux or change global policy. Certbot must provide `certbot.timer` or `certbot-renew.timer`.

## Configure one deployment

```sh
sudo install -d -m 755 /etc/snodec-idp
sudo install -m 600 /usr/share/snodec-idp/deployment.example.json \
  /etc/snodec-idp/deployment.json
sudoedit /etc/snodec-idp/deployment.json
```

Edit the supplied JSON:

- `hostname`: the IDP hostname, e.g. `core.snodec.org`.
- `acme_email`: your real contact email. Set `accept_acme_terms` to `true` only after reviewing Let’s Encrypt’s subscriber agreement.
- `clients`: client IDs mapped to exact HTTPS callback URL lists. There are no wildcard callbacks.
- `redirects`: optional hostname-to-HTTPS-URL mapping, e.g. `core.vchrist.at` to your application. These hosts receive certificates too; redirects remain owned by the IDP host application.
- `example`: optional object with a distinct application `hostname` and registered `client_id`. Remove this object to deploy only the IDP.
- `google_client_id` and `google_client_secret`: both nonempty to enable Google.
- `smtp_command`: trusted fixed mail command reading the complete message on stdin, e.g. `/usr/bin/msmtp -t`. Configure delivery credentials separately with permissions readable by the service account. Empty disables email delivery; no reset link is exposed in the browser.

Do not commit this file or pass secrets as command-line arguments. It is the operator-maintained input; `idp.env`, `example.env`, Nginx configuration and public-key export are generated outputs. Change the JSON and re-run deployment rather than editing generated files.

For Google, create a Web application OAuth client and register exactly:

```text
https://core.snodec.org/auth/federated/google/callback
```

This differs from your application callback. Configure Google’s branding/audience and production requirements in your Google account. The IDP requests `openid email profile`. A Google identity still needs IDP TOTP enrollment; equal-email local accounts are not automatically linked. See [Google federation](local-deployment.md#12-optional-google-login).

## Validate and deploy

```sh
sudo snodec-idp-deploy /etc/snodec-idp/deployment.json --check
sudo snodec-idp-deploy /etc/snodec-idp/deployment.json
```

`--check` validates configuration only. Actual deployment checks prerequisites and hostname ownership, creates service users and initial keys, writes generated configuration, enables HTTP-01 handling, obtains a Let’s Encrypt certificate, enables HTTPS and starts the services. HTTP redirects with status 308 to the same hostname/path over HTTPS, except the challenge directory.

The helper uses the distribution’s existing Certbot renewal timer and installs a deploy hook that validates/reloads Nginx after renewal. Certbot retains ownership of its certificate/account/renewal files. Re-running setup reuses existing keys and certificates; a database without its original signing or TOTP key is rejected.

If a later operation fails, inspect the reported error and service journal before retrying. A failed Nginx syntax check restores the previous site file. Deployment is not a complete multi-service rollback transaction: previously completed provisioning steps remain, and can be retried. Existing-account updates first save a SQLite backup, keys and configuration under `/var/lib/snodec-idp/backups/`.

## Verify the public deployment

```sh
curl -I http://core.snodec.org/auth/login
curl --fail https://core.snodec.org/health
sudo systemctl status snodec-idp nginx
sudo systemctl list-timers --all | grep certbot
sudo certbot renew --cert-name snodec-idp --dry-run
```

Verify the application homepage, protected-page redirect, registration, TOTP activation, successful callback, logout/relogin, password recovery email and Google login in a browser. Confirm configured redirect hostnames return their destination and unconfigured hosts are not routed to the IDP. Existing unrelated Nginx hosts retain their own behavior. The helper checks public IDP HTTPS health; it cannot complete Google consent, read delivered mail or prove the full user flow automatically.

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

CI builds unsigned artifacts; DistributionPackages validates their repository, workflow, run, target and capture, then signs and publishes them. Runtime credentials, ACME state and signing secrets never enter the IDP build workflow. Before enabling the dependency chain, merge its DistributionPackages integration and the IDP workflow, then deliberately create the IDP’s initial matching release tag. No tag or build dispatch was created during implementation.
