# SNode.C Identity Provider

Jan Nicolas Eberwein’s C++ identity provider and client integration for [SNode.C](https://github.com/SNodeC/snode.c), maintained here as a fork of [jan-eberwein/auth](https://github.com/jan-eberwein/auth).

The project provides an IDP with password login, TOTP, OAuth2 Authorization Code flow with PKCE, RS256 tokens, SQLite persistence, and Google federation, plus a client library for SNode.C applications.

## Documentation

Start with the **[step-by-step local deployment walkthrough](docs/local-deployment.md)** to build and run the full IDP and browser application, create accounts, enroll MFA, exercise login/logout and recovery, and back up the deployment.

Read the **[IDP and client guide](docs/idp-and-client-guide.md)** for configuration, native and Docker deployment, a complete minimal client application, API details, account workflows, operations, and troubleshooting. It documents the inspected source revision and known limitations, including differences from older project documentation. Read its compatibility and limitations sections before deployment.

To embed the complete IDP, use the **[IdpMiddleware router](docs/idp-middleware.md)** with explicit constructor configuration. The standalone server uses the same implementation, selects its IDP VHost from the issuer URL, and supports an optional [`HOST_REDIRECTS` mapping](docs/idp-and-client-guide.md#host-routing-and-client-redirects) for additional hostnames.

## Quick start

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

## License

MIT — Copyright © 2025/2026 Jan Nicolas Eberwein & Volker Chr. (SNode.C). See individual source files for their notices.
