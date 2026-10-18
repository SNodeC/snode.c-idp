<a id="banner"></a>
<p><picture><source media="(max-width: 640px)" srcset="docs/media/nav/banner-documentation-compact.svg"><img src="docs/media/nav/banner-documentation.svg" alt="SNode.C IDP — Identity and MFA" width="100%"></picture></p>

<!-- snodec:begin organization -->
<p><a href="https://github.com/VolkerChristian#banner" title="Volker Christian account"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="docs/media/nav/account-icon-dark.svg"><source media="(max-width: 640px)" srcset="docs/media/nav/account-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="docs/media/nav/account-dark.svg"><img align="right" src="docs/media/nav/account-light.svg" alt="Volker Christian account" title="Volker Christian account"></picture></a><a href="https://github.com/SNodeC#banner" title="SNode.C organization"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="docs/media/nav/organization-icon-dark.svg"><source media="(max-width: 640px)" srcset="docs/media/nav/organization-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="docs/media/nav/organization-dark.svg"><img align="right" src="docs/media/nav/organization-light.svg" alt="SNode.C organization" title="SNode.C organization"></picture></a><a href="#banner" title="SNode.C IDP repository"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="docs/media/nav/repository-icon-dark.svg"><source media="(max-width: 640px)" srcset="docs/media/nav/repository-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="docs/media/nav/repository-dark.svg"><img align="right" src="docs/media/nav/repository-light.svg" alt="SNode.C IDP repository" title="SNode.C IDP repository"></picture></a><br clear="all"></p>
<!-- snodec:end organization -->

# SNode.C Identity Provider

Jan Nicolas Eberwein’s C++ identity provider and client integration for [SNode.C](https://github.com/SNodeC/snode.c), maintained here as a fork of [jan-eberwein/auth](https://github.com/jan-eberwein/auth).

The project provides an IDP with password login, TOTP, OAuth2 Authorization Code flow with PKCE, RS256 tokens, SQLite persistence, and Google federation, plus a client library for SNode.C applications.

## Documentation

- [Documentation index](docs/README.md#banner)
- [Package installation and HTTPS deployment](docs/package-deployment.md#banner)
- [Styled example application](examples/minimal-mfa-app/README.md#banner)
- [Packaging integration checklist](docs/package-deployment-plan.md#banner)

For a public server such as `core.snodec.org`, use the **[detailed ten-step deployment guide](docs/package-deployment.md#banner)** for installation, certificates, Google login, email setup and verification.

For source-based development on localhost, start with the **[step-by-step local deployment walkthrough](docs/local-deployment.md)** to build and run the full IDP and browser application, create accounts, enroll MFA, exercise login/logout and recovery, and back up the deployment.

Read the **[IDP and client guide](docs/idp-and-client-guide.md)** for configuration, native and Docker deployment, a complete minimal client application, API details, account workflows, operations, and troubleshooting. It documents the inspected source revision and known limitations, including differences from older project documentation. Read its compatibility and limitations sections before deployment.

To embed the complete IDP, use the **[IdpMiddleware router](docs/idp-middleware.md)** with explicit constructor configuration. The standalone server uses the same implementation, selects its IDP VHost from the issuer URL, and supports an optional [`HOST_REDIRECTS` mapping](docs/idp-and-client-guide.md#host-routing-and-client-redirects) for additional hostnames.

## Quick start

To install and deploy the IDP and optional styled browser application, **download and run only the shell script** using the [ten-step deployment guide](docs/package-deployment.md#banner). It installs Python and the published packages, downloads its matching helper automatically, and guides you through hostnames, certificates, Google login, email and verification. Certbot is installed only if you choose Let’s Encrypt.

The setup uses `/etc/snodec-idp/deployment.json`: saved values are editable defaults, secret input stays hidden, and a first deployment without that file has no prefilled answers. Installing packages alone does not configure or start the IDP.

For client-library development from source, use the commands below.

The 2.0 API shares one `OAuthClient` between middleware and callback handling, requires MFA, and checks live IDP sessions. Upgrade applications and the IDP together; see the guide for schema and configuration migration.

Use an installed compatible SNode.C framework. The auth code uses its public `Log.h` API; the guide records the tested framework revision and dependency requirements.

To build only the relying-party client library from this checkout:

```bash
cmake -S . -B /tmp/codex/build/snodec-idp/client -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/absolute/path/to/compatible/snodec-install \
  -DCMAKE_INSTALL_PREFIX=/tmp/codex/build/snodec-idp/install-client \
  -DAUTH_CLIENT_ONLY=ON
cmake --build /tmp/codex/build/snodec-idp/client --parallel
cmake --install /tmp/codex/build/snodec-idp/client --component auth-client
```

Applications consume the installed package with:

```cmake
find_package(snodec-auth 2 REQUIRED)
target_link_libraries(my_application PRIVATE snodec-auth::auth-client)
```

Set `AUTH_CLIENT_ONLY=OFF` in a separate build directory to build the IDP too. Building does not configure or start an IDP. Follow the guide for signing keys, persistent storage, issuer/callback configuration, and launch instructions. The repository also includes a Dockerfile and Compose configuration.

## Development

Follow the [repository development conventions](AGENTS.md) for dependency discovery, build locations, formatting and authentication invariants.

## License

MIT — Copyright © 2025/2026 Jan Nicolas Eberwein & Volker Chr. (SNode.C). See individual source files for their notices.
