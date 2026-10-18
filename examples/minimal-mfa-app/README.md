<!-- snodec:begin page-header -->
<a id="banner"></a><a id="page-overview"></a>
<p><picture><source media="(max-width: 640px)" srcset="../../docs/media/nav/banner-examples-compact.svg"><img src="../../docs/media/nav/banner-examples.svg" alt="SNode.C IDP — Examples" width="100%"></picture></p>
<p><a href="../../README.md#banner" title="Up to SNode.C IDP"><picture><source media="(prefers-color-scheme: dark)" srcset="../../docs/media/nav/up-snode-c-idp-dark.svg"><img src="../../docs/media/nav/up-snode-c-idp-light.svg" alt="Up to SNode.C IDP" title="Up to SNode.C IDP" width="160" height="28"></picture></a><a href="https://github.com/VolkerChristian#banner" title="Volker Christian account"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="../../docs/media/nav/account-icon-dark.svg"><source media="(max-width: 640px)" srcset="../../docs/media/nav/account-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="../../docs/media/nav/account-dark.svg"><img align="right" src="../../docs/media/nav/account-light.svg" alt="Volker Christian account" title="Volker Christian account"></picture></a><a href="https://github.com/SNodeC#banner" title="SNode.C organization"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="../../docs/media/nav/organization-icon-dark.svg"><source media="(max-width: 640px)" srcset="../../docs/media/nav/organization-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="../../docs/media/nav/organization-dark.svg"><img align="right" src="../../docs/media/nav/organization-light.svg" alt="SNode.C organization" title="SNode.C organization"></picture></a><a href="../../README.md#banner" title="SNode.C IDP repository"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="../../docs/media/nav/repository-icon-dark.svg"><source media="(max-width: 640px)" srcset="../../docs/media/nav/repository-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="../../docs/media/nav/repository-dark.svg"><img align="right" src="../../docs/media/nav/repository-light.svg" alt="SNode.C IDP repository" title="SNode.C IDP repository"></picture></a><br clear="all"></p>
<!-- snodec:end page-header -->

# Styled MFA example application

This is the browser application used in the local IDP walkthrough. Public HTML and CSS live in `public/`; the protected page lives in `pages/private/`, outside the public directory. `JwtAuthMiddleware` runs before the private static-file handler. The OAuth callback remains an explicit route.

## Build and run

Build with the IDP checkout:

```sh
cmake -S . -B build/codex/example -G Ninja \
  -DCMAKE_PREFIX_PATH=/path/to/snodec-install -DAUTH_BUILD_EXAMPLE=ON
cmake --build build/codex/example --parallel
```

Or build this directory against an installed client development package:

```sh
cmake -S examples/minimal-mfa-app -B build/codex/example-client -G Ninja
cmake --build build/codex/example-client --parallel
```

Run from this directory so the static directories resolve. Provide the public verification key exported by your IDP:

```sh
export IDP_PUBLIC_KEY_PATH=/absolute/path/to/idp-public.pem
../../build/codex/example/examples/minimal-mfa-app/minimal-mfa-app \
  MinimalMfaApp local --host 127.0.0.1
```

Open `http://localhost:8084/` and choose **Sign in with MFA**. The local IDP must register client `minimal-mfa-app` with callback `http://localhost:8084/auth/callback`. See the [local walkthrough](../../docs/local-deployment.md#banner) for account creation, enrollment, recovery and logout.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `IDP_BASE_URL` | `http://localhost:8083` | Public IDP origin |
| `APP_CLIENT_ID` | `minimal-mfa-app` | Registered client ID |
| `APP_CALLBACK_URL` | `http://localhost:8084/auth/callback` | Exact registered callback; example path is fixed at `/auth/callback` |
| `IDP_PUBLIC_KEY_PATH` | `idp-public.pem` | IDP public verification key |
| `APP_PORT` | `8084` | Internal listener port |

`/account` and `/sign-out` redirect to the configured IDP settings and logout pages. Logout is confirmed on the IDP; revocation is checked on subsequent protected requests. The example never receives your IDP password, Google client secret or signing private key.

The optional `snodec-idp-example` package installs the executable, static assets and a dormant service unit. Follow the [existing package deployment instructions](../../docs/package-deployment.md#banner): download and run the single shell script, then choose to deploy the styled example. The script installs the packages and configures its separate HTTPS hostname and service; Certbot is installed explicitly only when choosing Let’s Encrypt. Installing it does not start a listener.
