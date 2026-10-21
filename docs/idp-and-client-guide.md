<!-- snodec:begin page-header -->
<a id="banner"></a><a id="page-overview"></a>
<p><picture><source media="(max-width: 640px)" srcset="media/nav/banner-documentation-compact.svg"><img src="media/nav/banner-documentation.svg" alt="SNode.C IDP — Documentation" width="100%"></picture></p>
<p><a href="README.md#banner" title="Up to Documentation"><picture><source media="(prefers-color-scheme: dark)" srcset="media/nav/up-documentation-dark.svg"><img src="media/nav/up-documentation-light.svg" alt="Up to Documentation" title="Up to Documentation" width="160" height="28"></picture></a><a href="https://github.com/VolkerChristian#banner" title="Volker Christian account"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/account-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/account-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/account-dark.svg"><img align="right" src="media/nav/account-light.svg" alt="Volker Christian account" title="Volker Christian account"></picture></a><a href="https://github.com/SNodeC#banner" title="SNode.C organization"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/organization-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/organization-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/organization-dark.svg"><img align="right" src="media/nav/organization-light.svg" alt="SNode.C organization" title="SNode.C organization"></picture></a><a href="../README.md#banner" title="SNode.C IDP repository"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/repository-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/repository-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/repository-dark.svg"><img align="right" src="media/nav/repository-light.svg" alt="SNode.C IDP repository" title="SNode.C IDP repository"></picture></a><br clear="all"></p>
<!-- snodec:end page-header -->

# Jan Eberwein’s SNode.C IDP and client integration

This is the guide for [SNodeC/snode.c-idp](https://github.com/SNodeC/snode.c-idp),
Volker Christian’s fork of [Jan Nicolas Eberwein’s implementation](https://github.com/jan-eberwein/auth).
It describes the hardened 2.0 client API and IDP. The original behavior was inspected
at `ea1e02de005d0919701f37292dbf7c74101f0fd9`; `ed3b897` restored compatibility with
current SNode.C and documented the authentication defects subsequently addressed here.

**Upgrade both the IDP and its applications together.** This changes the client API,
configuration, and authentication schema. Old sessions, pending codes, refresh
credentials, and password-reset links are invalidated on migration. User accounts
and their passwords remain. Rebuild consumers against the installed 2.0 package.

The initial hardening was tested offline. A subsequent user-authorized integration
run started isolated loopback IDP/client processes and TLS proxies with disposable
keys and accounts. No existing deployment or user database was used. The live-test
section below separates verified local behavior from unavailable external services.

For public deployment on `core.snodec.org` using the binary repository, follow the **[ten-step package deployment guide](package-deployment.md#banner)** and its **[interactive script](../scripts/deploy-core-snodec-org.sh)**. For source-based localhost development and account-flow details, follow the **[local deployment walkthrough](local-deployment.md)**.

## Architecture and trust boundaries

The IDP owns accounts and live sessions in SQLite. A short-lived server-side login
transaction holds the validated client, callback, state, nonce, PKCE challenge,
and identity established by password or Google authentication. Its random cookie
binds it to the browser. Login forms carry only a transaction reference and the
user's submitted credentials; posted user IDs and OAuth parameters cannot choose
which account or client is authenticated. A replaced/expired transaction rejects
old forms. There is one pending IDP login per browser cookie; restart an older tab
if a newer login replaced its transaction.

TOTP completes that pending primary-authenticated transaction. An authorization
code is single-use, lasts two minutes, and is bound to its client, exact callback,
PKCE challenge and live session. Refresh rotation uses the same session authority.
Replaying a used refresh token revokes that session and its remaining grants.
SSO reuses the browser's existing session, so logout revokes every application
grant issued from it. Enrollment started from a session also requires that
session to remain active until completion. An expired registration/enrollment
transaction can be restarted by signing in with the registered password.

The application's shared `OAuthClient` owns its local login transactions. Its
middleware creates random state, nonce and a cryptographic PKCE verifier. A
separate HttpOnly transaction cookie allows multiple pending application logins.
The callback consumes matching state, exchanges the code through the server-side
SNode.C HTTP client, and validates the returned access and ID tokens, nonce and
subject/session agreement. It sets an HttpOnly access-token cookie and redirects
to the saved local path. There is no JavaScript token exchange, token display,
PKCE-verifier cookie, or unverified identity cookie.

Both application middleware entry points require verified MFA and an online check
of the issuing session for every protected request. Invalid tokens, password-only
tokens, revoked sessions and unavailable IDPs are denied. An already-authorized,
in-flight request is not retroactively canceled. An old application that only
checks JWT signatures cannot gain this behavior until upgraded.

The outbound HTTP implementation uses SNode.C's asynchronous HTTP/TLS client,
certificate-chain and hostname/IP verification, connection/read/write timeouts,
bounded response bodies/headers, and no automatic redirects or reconnect/retry.
HTTP is accepted only for the exact hosts `localhost` and `127.0.0.1`; use HTTPS
for network deployments. DNS hostnames and IPv4 are supported by this transport.

## Components

| Source | Responsibility |
|---|---|
| `src/apps/auth_idp/IdpServer.cpp` | Standalone host: environment configuration, IDP VHost and redirect lookup, listener and event loop |
| `src/auth/IdpMiddleware.*` | Complete reusable IDP router, instance-owned state, page rendering and configured email delivery |
| `src/auth/AuthStore.*` | Login transactions, session/grant relationships, reset consumption and TOTP migration |
| `src/database/sqlite/SqliteDatabase.*` | Schema migration, prepared statements and database lifetime |
| `src/auth/OAuthClient.*` | Application login transaction, exchange and authorization policy |
| `src/auth/JwtAuthMiddleware.h` | Redirecting browser adapter |
| `src/auth/OAuth2CallbackHandler.h` | Browser callback adapter |
| `src/auth/AuthMiddleware.*` | Non-redirecting API adapter using the same policy |
| `src/auth/JwtSigner.*` | Signing-key ownership, matching JWKS/key ID, access/ID token creation |
| `src/auth/JwtVerifier.*` | Signature and typed-claim checks; Google identity verification |
| `src/auth/HttpExchange.*` | Shared outbound transport for exchange, introspection and Google |
| `src/auth/Security.h`, `HttpEncode.h` | Cryptographic random tokens, codecs and endpoint validation |
| `src/auth/SecretEncryptor.h`, `Totp.*`, `QrCodeGenerator.*` | Encrypted TOTP storage, verification and enrollment QR codes |

The client package does not link the IDP's SQLite, signing, TOTP or QR components.
It now needs the SNode.C HTTP client/TLS transport and nlohmann JSON as public
dependencies. The public `Log.h` API is used; there is no old logging macro shim.

For embedding the complete IDP in an application, see
[IdpMiddleware configuration, ownership and installation](idp-middleware.md).

## Build and install

Requirements: C++20 compiler, CMake 3.18 or newer, OpenSSL 3, nlohmann JSON 3.11
or newer, and an installed compatible SNode.C framework. The full IDP also needs
SQLite. Offline tests additionally need Python 3. Use `-DBUILD_TESTING=OFF` for a
production build without test tools.

The tested framework revision is
`ba57feee0e62e6780abb778fff54a29f443d5439`. The Dockerfile pins this commit.
Native builds consume an installed framework through CMake's public components:
`http-server-express-legacy-in`, `http-client`, and `net-in-stream-tls`.
The logger target is discovered transitively; `logger` is not a standalone component.

From this checkout:

```bash
cmake -S . -B /tmp/codex/build/snodec-idp/full -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/absolute/path/to/snodec-install \
  -DCMAKE_INSTALL_PREFIX=/tmp/codex/build/snodec-idp/install \
  -DAUTH_CLIENT_ONLY=OFF -DBUILD_TESTING=ON
cmake --build /tmp/codex/build/snodec-idp/full --parallel
ctest --test-dir /tmp/codex/build/snodec-idp/full --output-on-failure
cmake --install /tmp/codex/build/snodec-idp/full
```

For an application-only installation, use a separate build:

```bash
cmake -S . -B /tmp/codex/build/snodec-idp/client -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/absolute/path/to/snodec-install \
  -DCMAKE_INSTALL_PREFIX=/tmp/codex/build/snodec-idp/install-client \
  -DAUTH_CLIENT_ONLY=ON -DBUILD_TESTING=OFF
cmake --build /tmp/codex/build/snodec-idp/client --parallel
cmake --install /tmp/codex/build/snodec-idp/client --component auth-client
```

Installed application headers live under `include/snodec-auth/auth`.
`find_package(snodec-auth 2 REQUIRED)` discovers its transitive dependencies.
Do not use another developer's source checkout as an include path.

Formatting is explicit: `cmake --build <build-dir> --target format`. Ordinary
compilation does not rewrite sources. Follow `AGENTS.md` for changed-range
formatting, vendor exclusions, and temporary/persistent build locations.

## IDP configuration

| Variable | Meaning |
|---|---|
| `IDP_BASE_URL` | Public origin, including scheme and optional port, with no trailing slash or path; default `http://localhost:8083` |
| `IDP_ISSUER` | Must equal `IDP_BASE_URL`; defaults to it |
| `HOST_REDIRECTS` | Optional JSON object mapping additional exact hostnames to fixed client URLs; absent, empty or `{}` enables no redirects |
| `IDP_PORT` | Defaults to the port in `IDP_BASE_URL`; HTTPS must match that origin. Local HTTP permits 0–65535 (0 requests an ephemeral port) |
| `HTTP_REDIRECTS` | Optional hostname-to-HTTPS-origin JSON for the separate HTTP redirect listener; absent or `{}` disables it |
| `HTTP_PORT` | Redirect listener port, default 80 when enabled; must differ from the IDP port |
| `IDP_CLIENTS` | JSON object mapping client IDs to arrays of exact callback URLs; default `{}` permits no OAuth clients |
| `DB_PATH` | SQLite file; default `snodec_auth.db` |
| `IDP_PRIVATE_KEY_PATH` | Existing RSA private PEM; provision an RSA key of at least 2048 bits |
| `TOTP_KEY_PATH` | Required existing file containing exactly 32 binary bytes |
| `OAUTH_GOOGLE_CLIENT_ID`, `OAUTH_GOOGLE_CLIENT_SECRET` | Both must be nonempty to enable Google |
| `SMTP_COMMAND` | Operator-controlled mail command reading the complete message from stdin, including its `To` header; example `msmtp -t` |
| `AUTH_REVISION` | CMake/Docker build metadata, not a runtime authentication setting |

There are no automatic private-network/localhost redirect exceptions. Register
loopback callbacks explicitly for development. Apple/Meta placeholder login,
`SETUP_CLAIM_TOKEN`, and `IDP_ALLOWED_REDIRECT_URIS` are removed. There is no `/setup`
route or administrator-role system; registration creates ordinary accounts.

Example configuration for native development:

```bash
export IDP_BASE_URL=http://localhost:8083
export IDP_ISSUER=http://localhost:8083
export IDP_PORT=8083
export IDP_CLIENTS='{"minimal-mfa-app":["http://localhost:8081/auth/callback"]}'
export DB_PATH=/absolute/path/to/data/auth.db
export IDP_PRIVATE_KEY_PATH=/absolute/path/to/keys/private_key.pem
export TOTP_KEY_PATH=/absolute/path/to/keys/totp.key
```

Provision keys deliberately before a new native deployment. These commands are
instructions, not actions executed against an existing deployment:

```bash
umask 077
mkdir -p /absolute/path/to/keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out /absolute/path/to/keys/private_key.pem
openssl pkey -in /absolute/path/to/keys/private_key.pem -pubout \
  -out /absolute/path/to/keys/public_key.pem
openssl rand -out /absolute/path/to/keys/totp.key 32
```

Start the installed `auth_idp` binary only after configuration and backups are
ready. Use HTTPS at the public boundary. The public origin determines Secure
cookie attributes, browser Origin checks and listener transport. HTTPS selects
SNode.C TLS directly; pass `IdpServer tls --cert /path/fullchain.pem --cert-key /path/privkey.pem`.
The [package deployment guide](package-deployment.md#banner) configures this automatically.
The application callback URL is configured explicitly, never reconstructed from
untrusted Host or forwarding headers.

## Host routing and client redirects

The existing `auth_idp` executable mounts the complete `IdpMiddleware` inside
SNode.C/Express's `VHost` middleware. The IDP hostname comes from the configured
issuer/base URL; there is no second IDP hostname setting that can disagree with
it. For example, `https://core.snodec.org:8088` serves IDP routes only for
`core.snodec.org`.

Additional hostnames can redirect to fixed client URLs. Configure them in the
same environment file as the IDP:

```bash
export IDP_BASE_URL=https://core.snodec.org:8088
export IDP_ISSUER=https://core.snodec.org:8088
export HOST_REDIRECTS='{
  "core.vchrist.at": "https://client.example.org/",
  "another.example.org": "https://another-client.example.org/landing?from=idp"
}'
```

Replace the example client URLs with your actual destinations. After the IDP
VHost, one application handler looks up the request hostname in this mapping and sends the configured redirect or a final 404. There is no fixed
limit on the number of entries.
There is no hello-page implementation and no new executable. In Docker Compose,
put the same variables in `.env` (without shell `export`). The native launcher
sources `idp.env`; it does not reload configuration dynamically. Restart after
changing the mapping.

Rules and behavior:

- Keys are exact DNS-style hostnames or IPv4 host strings, without scheme, port,
  path, wildcard, empty label or trailing dot. Names are at most 253 characters
  with labels of at most 63 characters.
- Duplicate JSON keys, duplicates differing only in case, and keys conflicting
  with the IDP hostname are rejected at startup, before database initialization.
- Destinations must be absolute URLs accepted by the existing endpoint validator:
  HTTPS, or HTTP for exact `localhost`/`127.0.0.1`. Credentials, fragments, control
  characters and relative URLs are rejected. Include `/` before any query string.
- Every request to a configured redirect hostname receives **303 See Other**,
  with the exact configured destination in `Location`. Incoming paths, queries and bodies are
  not appended or forwarded. A browser follows a POST redirect as a GET.
- Redirect responses set `Cache-Control: no-store` and `Referrer-Policy:
  no-referrer`, and do not run IDP routes or issue IDP cookies.
- Unmatched VHosts and unmatched IDP paths/methods fall through to subsequent
  routers. The standalone application’s final fallback returns **404**; the IDP
  middleware does not send that response or apply its headers/origin checks to
  unmatched requests. `X-Forwarded-Host` does not select a VHost.
- The installed SNode.C VHost matcher uses exact, case-sensitive host strings and
  ignores an optional request port when configured with a bare hostname. Use
  lowercase hostnames consistently in configuration and the request `Host`.
  This feature does not modify the framework's matching semantics.

`HOST_REDIRECTS` is separate from OAuth callback registration (`IDP_CLIENTS`) and
account-return navigation. Successful OAuth
logins still return to their registered callbacks. Redirect destinations should
be client endpoints that terminate the redirect, not a cycle of redirect hosts.

### Compatibility and deployment

All IDP endpoint paths, client APIs, accounts, keys, session handling and existing
environment defaults are retained. No URL was renamed by this change. With the
local settings, the IDP is still `http://localhost:8083` and the already-deployed
application is still `http://localhost:8084`; the generic walkthrough uses 8081.
An omitted/empty `HOST_REDIRECTS` preserves the existing single-IDP setup.

Requests using an unrelated alias or IP as `Host` do not reach the IDP. DNS must point each configured hostname to this server. HTTPS now uses a direct TLS listener, and its port must match the public origin. For native startup provide the certificate/key through SNode.C's `IdpServer tls` options; the package helper supplies them through systemd credentials.

Dockerfile and Compose health checks share `scripts/healthcheck.sh`. It connects to loopback while retaining the configured public origin for Host, SNI and certificate verification. For manual direct HTTPS checks:

```bash
curl --fail https://core.snodec.org:8088/health
curl -i https://core.vchrist.at:8088/any/path
```

The second command assumes `core.vchrist.at` is a redirect hostname in `HOST_REDIRECTS`, rather than the application's own hostname. It returns 303 with the configured fixed destination. The IDP TLS certificate must cover every redirect hostname too.

`HTTP_REDIRECTS` controls a separate optional plaintext listener: exact hostname keys map to HTTPS origins, and incoming paths/queries are preserved with status 308. Unknown hosts receive 404. `HTTP_PORT` defaults to 80. This is distinct from fixed-destination `HOST_REDIRECTS` on the IDP listener. The package helper derives both maps from `deployment.json`; operators do not maintain duplicate generated configuration. Local HTTP development does not enable this additional listener by default.

## Complete minimal application

This application uses the shared client policy; it does not implement its own MFA
check, token parser, transaction cache or callback exchange. The public PEM must
be copied through a trusted deployment process from the IDP's signing key.

### `main.cpp`

```cpp
#include "auth/JwtAuthMiddleware.h"
#include "auth/OAuth2CallbackHandler.h"
#include "core/SNodeC.h"
#include "express/legacy/in/WebApp.h"

#include <memory>

int main(int argc, char** argv) {
    core::SNodeC::init(argc, argv);
    const express::legacy::in::WebApp app("MinimalMfaApp");
    auto client = std::make_shared<snodec::auth::OAuthClient>(
        "http://localhost:8083",
        "minimal-mfa-app",
        "http://localhost:8081/auth/callback",
        snodec::auth::middleware::loadPublicKey("idp-public.pem"));
    snodec::auth::middleware::JwtAuthMiddleware auth(client);
    snodec::auth::callback::OAuth2CallbackHandler callback(client);

    app.get("/auth/callback", callback);
    app.use("/private", auth);
    app.get("/private", [] APPLICATION(req, res) {
        res->set("Content-Type", "text/plain").send("Authenticated with MFA\n");
    });
    app.get("/", [client] APPLICATION(req, res) {
        client->authorize(req->cookie("access_token"), [res](bool accepted, const auto&) {
            res->set("Cache-Control", "no-store");
            if (accepted) {
                res->redirect(303, "/private");
            } else {
                res->send("<a href='/private'>Sign in with MFA</a>");
            }
        });
    });
    app.listen(8081, [](const auto&, const auto&) {});
    return core::SNodeC::start();
}
```

### `CMakeLists.txt`

```cmake
cmake_minimum_required(VERSION 3.18)
project(minimal-mfa-app LANGUAGES CXX)
find_package(snodec-auth 2 REQUIRED)
add_executable(minimal-mfa-app main.cpp)
target_compile_features(minimal-mfa-app PRIVATE cxx_std_20)
target_link_libraries(minimal-mfa-app PRIVATE snodec-auth::auth-client)
```

Configure the example in its own source directory:

```bash
cmake -S /absolute/path/to/minimal-mfa-app \
  -B /tmp/codex/build/snodec-idp/example -G Ninja \
  -DCMAKE_PREFIX_PATH='/absolute/path/to/auth-install;/absolute/path/to/snodec-install'
cmake --build /tmp/codex/build/snodec-idp/example --parallel
```

Run it from a directory containing `idp-public.pem` when you choose to test a
live deployment. The application server must reach the IDP for code exchange
and each authorization check; the browser must reach both public origins.
A production callback must use the registered HTTPS URL.

## Client API and lifetime

Construct one shared `OAuthClient(issuer, clientId, callbackUrl, publicKeyPem)`
and give that same instance to `JwtAuthMiddleware`, `OAuth2CallbackHandler`, or
`AuthMiddleware`. Independent instances do not share pending transactions.
Handlers retain the client; keep configured application objects alive through
pending requests. A process restart discards local pending logins; start again.
Multiple application workers need routing that returns a callback to the worker
that initiated it. A shared multi-process transaction store is not implemented.

`JwtAuthMiddleware` starts sign-in for browser GET/HEAD requests without a valid
credential, including expired or revoked access cookies. It clears the rejected
access cookie while setting a fresh OAuth transaction cookie. An explicit
Authorization header or a non-GET/HEAD request receives 401 on authentication
failure; state-changing requests are not replayed through login.
`AuthMiddleware(client).handler()` always uses the non-redirecting response style.
Both apply the same MFA and live-session policy. The browser client requests
`acr_values=urn:snodec:acr:mfa`; MFA-verified ID tokens report the same value in
`acr`, derived from the actual session assurance. The IDP completes TOTP verification or enrollment
before issuing a code for that request, including when an existing password-only
session is reused. Required enrollment cannot be skipped. The original callback,
state, nonce and PKCE challenge remain attached to the same transaction. A
successful step-up replaces the weaker session; it never marks an unverified
session as MFA-verified. Requests without `acr_values` retain optional MFA at the
IDP; clients still reject password-only tokens. Unknown assurance values are
rejected. No new deployment setting is needed.

Failed callbacks remain 401,
preventing automatic retries when the completed login itself is rejected.
Cookie-authenticated mutations require an Origin matching the configured callback
origin. Bearer-authenticated requests do not use ambient cookie authentication.

After success, `UserContext` contains `id`, `username`, `email`, `scopes`, and
`mfaVerified`; `hasScope()` checks scope membership. Browser middleware also sets
request attributes `X-User-Id`, `X-Username`, `X-Email`, and `X-MfaVerified`.
These are server-side request attributes, not trusted incoming HTTP headers.
Use `AuthMiddleware::getUser(req)` within the request lifetime.

`JwtVerifier` remains a cryptographic primitive. Calling `verify()` alone does
not provide online revocation or enforce MFA. It rejects incorrect purpose,
algorithm, signature, issuer, audience, typed times, or missing session identity.
Use the middleware for authorization. `OAuthClient` accepts an injectable
`HttpExchange` for offline tests; production uses the shipped SNode.C transport.

The access cookie is named `access_token`, HttpOnly, SameSite=Lax, and Secure on
HTTPS. It expires after five minutes. This minimal browser adapter does not
silently refresh; the IDP can reauthorize an existing session on the next login.
The token endpoint supports rotating refresh tokens for separately implemented
clients; those clients must retain and replace each refresh token securely.

## Account and protocol endpoints

For clickable local browser URLs, diagnostic URLs and form/protocol endpoints,
see the [local URL inventory](local-deployment.md#browser-urls-and-service-endpoints).
It distinguishes the walkthrough's application port 8081 from the running demo's
port 8084; both use IDP port 8083.

| Method and path | Behavior |
|---|---|
| GET `/`, `/dashboard`, `/settings` | Landing page and authenticated account pages |
| GET/POST `/auth/login`, `/auth/register` | Start/continue a browser-bound transaction; password verification or account creation |
| POST `/auth/mfa` | Verify TOTP for the user established by that transaction |
| GET `/auth/enroll/totp` | Enrollment from a new registration or an authenticated account |
| POST `/auth/enroll/totp/verify`, `/auth/enroll/totp/skip` | Consume enrollment; submitted account IDs/secrets do not establish authority |
| GET/POST `/settings/mfa/disable` | Confirmation and password/TOTP checks before disabling MFA |
| POST `/settings/profile`, `/settings/password` | Account profile and password changes |
| GET/POST `/settings/delete` | Confirmation and account deletion |
| GET `/auth/logout` | Confirmation only; GET does not revoke a session |
| POST `/auth/logout` | Revoke current IDP session and its grants |
| GET/POST `/auth/forgot-password`, `/auth/reset-password` | Email-only recovery and single-use reset consumption |
| GET `/oauth2/authorize` | Registered exact callback, code response and S256 PKCE required |
| POST `/oauth2/token` | Code redemption or refresh rotation |
| POST `/oauth2/introspect` | Live status; present the same access token in the Bearer header and `token` form field, plus `client_id` |
| GET `/oauth2/userinfo` | Valid live Bearer access token with OpenID scope; identity fields restricted by scope |
| GET `/.well-known/openid-configuration`, `/.well-known/jwks.json` | Supported protocol metadata and matching signing key |
| GET `/auth/federated/google`, `/auth/federated/google/callback` | Google authentication bound to the current transaction |
| GET `/api/qrcode`, `/auth/help/authenticator`, `/health` | QR output, help, and process/build metadata |

Browser mutations require the configured origin and, for login/enrollment forms,
the current transaction reference. Token/introspection requests are server-side
and reject ambient browser cookies. Credentials and sensitive pages use no-store
headers and a `strict-origin` referrer policy. Browser responses prohibit framing
and base-URI changes. Form destinations are not restricted to the IDP by CSP,
because OAuth authorization must return to registered application callbacks.

Passwords use the existing PBKDF2 implementation and upgrade legacy hashes on a
successful password login. Disabling MFA, changing/resetting a password, changing
TOTP credentials, or deleting an account revokes affected sessions through database
triggers; foreign keys remove their grants. New registrations may remain
password-only at the IDP, but protected applications in this guide require MFA.
Enroll it through account settings before accessing those applications.

Access tokens and ID tokens are distinct RS256 JWTs with distinct token purposes.
ID tokens carry the requested nonce. A shared signer produces the JWKS key ID and
token header. JSON is parsed/serialized with nlohmann JSON rather than substring
extraction or interpolation. This is the implemented code-flow subset, not a
claim of OpenID certification or support for every optional OIDC feature.

## Google and email

Register the exact Google callback:
`https://your-idp-origin/auth/federated/google/callback`. Configure both Google
credentials. The IDP uses random state, nonce and PKCE, exchanges the code with
Google, fetches its signing keys, and validates the signed identity's issuer,
audience, expiry, nonce and verified-email claim. It identifies accounts by
Google's stable subject. A local email collision fails safely; it does not link
accounts based solely on an email string. Existing email-linked Google accounts
need a deliberate authenticated migration/linking procedure; no automatic merge
or new linking UI is provided. Apple and Meta are not supported.

Email delivery must read the stored recipient from the message headers. Configure
an appropriate installed tool such as `msmtp -t`; the command is trusted operator
configuration, not supplied by users. The stock runtime image does not configure
an SMTP service. Missing/failing delivery deletes the reset credential and returns
the same generic browser response. Reset tokens are hashed in SQLite, expire in
15 minutes and are consumed atomically. Reset URLs never appear in HTTP responses
or application logs. Email delivery currently invokes the configured command
synchronously; the Google HTTP exchange no longer invokes shell commands.

## Docker and operational lifecycle

Copy `.env.example` to `.env`, set real origins, register callbacks and configure
Google/email only if needed. Compose exposes direct HTTPS on `IDP_PORT` (8088 by
default); include that same port in `IDP_BASE_URL`. Set `TLS_CERTIFICATE` and
`TLS_PRIVATE_KEY` to existing host PEM files, mounted read-only. Arrange restricted
file ownership/group permissions so the container's `authidp` user can read them;
never make the key world-readable. Renew certificates externally and recreate the
container to refresh file mounts (`docker compose up -d --force-recreate`). Compose
does not provision ACME, port-80 redirects or the example application; the
[package deployment guide](package-deployment.md#banner) handles the full systemd setup.
The Dockerfile builds the
pinned SNode.C source in one stage, the auth package in another, and runs the
binary as `authidp`. It includes the current CMake/formatting modules and disables
test builds in the image. `Dockerfile.fork-legacy` is historical and unsupported.

Operator commands, not executed during this work:

```bash
export AUTH_REVISION="$(git rev-parse HEAD)"
docker compose -p jan-idp build
docker compose -p jan-idp up -d
docker compose -p jan-idp logs --tail=100 auth-idp
# Stop without deleting named volumes:
docker compose -p jan-idp stop
```

Do not label a dirty source build with a clean revision. Native CMake builds derive
a revision with a dirty marker from Git; source archives/Docker builds without Git
metadata require an explicit `AUTH_REVISION`, otherwise health reports `unknown`.
The framework commit is pinned, but base-image tags and distribution packages are
not a byte-for-byte reproducible build guarantee.

The entrypoint creates keys only for a new database. Missing the public PEM does
not cause it to replace an existing private key. An existing database with a
missing signing or TOTP key fails startup; restore/provision the appropriate key.
Compose persists `/app/data` and `/app/keys`. `docker compose down -v` deletes the
named volumes and must not be used as an ordinary stop command.

Before upgrading, stop writers or take a consistent SQLite backup and save the
matching RSA and TOTP keys separately with restrictive permissions. Never copy
only a live WAL database's main file. Keep a verified backup before migration:
SQLite `user_version=2` marks the hardened schema. Migration invalidates legacy
authentication artifacts without granting MFA to old sessions. Plaintext legacy
TOTP records are encrypted transactionally; a missing/wrong key or malformed
record aborts rather than silently writing or accepting plaintext.

Back up the database, private/public signing PEMs, the binary TOTP key, deployment
configuration and source/dependency revisions. Restore them as a matched set.
The bundled `scripts/backup.sh` and `scripts/update.sh` retain historical site paths
and volume names; do not use them unchanged as a generic backup/update service.
In particular, a PEM-only backup omits `totp.key`. No restore automation is provided.

The signer and application verification key are loaded at startup. RSA rotation
requires coordinated application updates/restarts; multi-key overlap is not
implemented. TOTP-key rotation requires decrypting and reencrypting records with
the old/new key; replacing its file alone loses access to existing secrets.

`/health` reports process status, CMake version and build revision. It is not proof
of working email, Google, database recovery or end-to-end login. Rate limits are
process-local. Keep clocks synchronized for JWT/TOTP checks. Restrict logs and key
access even though authentication credential logging has been removed.

## Verification and troubleshooting

Offline CTest covers server transactions and grants, replay/client/redirect/PKCE
rejection, session revocation, token purpose and claim validation, client state and
nonce checks, fail-closed authorization, reset handling and migration. Encoding
checks cover RFC 6238 SHA-1 vectors and independently parse PNG chunks/zlib/pixels.
No test starts the IDP or an HTTP listener. Full/client-only builds and the installed
consumer example passed with warnings treated as errors (full Debug and
client-only Release, GCC 16.2.0, OpenSSL 3.6.5). All three CTest tests passed.
The [hardening record](authentication-hardening-plan.md#implementation-and-verification-record)
lists the exercised boundaries and remaining integration checks. Docker was not
available; YAML inspection does not validate Compose interpolation or an image build.

Validation artifacts are under `/tmp/codex/build/snodec-idp/hardening/`; remove them
when no longer needed. Earlier compatibility evidence is under `current-head/`
and `warning-cleanup/` in the same parent. These are development installations,
not the user's system installation or a deployment.

Local Chromium flows, proxy/cookie behavior, real SNode.C TLS connections, a mail
command sink and an isolated SQLite backup/restore have now been exercised. Real
Google login, external SMTP delivery and Docker image/startup checks remain
unverified: no provider/mail configuration or Docker executable was available.
These tests are not a penetration test or an exhaustive security audit.

| Symptom | Check |
|---|---|
| Old constructor/setter no longer compiles | Migrate to one shared `OAuthClient`; rebuild against package version 2 |
| Unregistered redirect | Exact `IDP_CLIENTS` client ID, scheme, hostname, port and path; no implicit exceptions |
| Startup rejects configuration | Matching issuer/base origin, existing RSA PEM and exactly 32-byte TOTP key |
| Callback rejected | Matching state cookie, initiating worker, transaction age, nonce, PKCE and configured callback URL |
| Stale login form | A newer IDP login replaced that browser transaction; restart the old tab |
| Password-only account signs in to an MFA application | Complete the enrollment offered by the IDP, then return automatically to the application; clients must send `acr_values=urn:snodec:acr:mfa` |
| Protected request denied despite a valid JWT signature | IDP reachability, live session, revocation, token purpose and MFA claim |
| HTTP 403 on form submission | Browser Origin must match the configured public origin; proxies must preserve it |
| Reset email missing | Installed delivery command/configuration; absence never exposes a reset link |
| Existing Google email fails | Subject-based linking deliberately rejects an unlinked local email collision |
| Key/file errors after upgrade | Restore matching keys; never generate substitutes for encrypted existing data |
| Shared libraries not found | Installed SNode.C runtime library paths are discoverable by the loader |

Protocol references: [OAuth security BCP (RFC 9700)](https://www.rfc-editor.org/rfc/rfc9700.html),
[OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html), and
[Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect).

## Explicit local integration tests

These tests start listeners only when invoked explicitly. They are not registered
with CTest. They bind IPv4 loopback on fresh ports, create disposable RSA/TOTP
keys and test accounts, capture reset mail locally, and stop their own services.
Always supply a **fresh** work directory; they refuse an existing test database.
Do not point them at deployment data or keys.

Build the test clients against your installed auth package:

```bash
cmake -S tests/live -B /tmp/codex/build/snodec-idp/online/client -G Ninja \
  -DCMAKE_PREFIX_PATH='/absolute/path/to/auth-install;/absolute/path/to/snodec-install' \
  -DCMAKE_CXX_FLAGS='-Wall -Wextra -Wconversion -Werror'
cmake --build /tmp/codex/build/snodec-idp/online/client --parallel
python3 -m venv /tmp/codex/build/snodec-idp/online/venv
/tmp/codex/build/snodec-idp/online/venv/bin/pip install requests playwright
PLAYWRIGHT_BROWSERS_PATH=/tmp/codex/build/snodec-idp/online/browsers \
  /tmp/codex/build/snodec-idp/online/venv/bin/playwright install chromium
```

OpenSSL's command-line tool generates test certificates. Chromium's system
runtime libraries must be installed. Run the same flow suite once with HTTP and
once with the `--https` option and a different fresh work directory:

```bash
PLAYWRIGHT_BROWSERS_PATH=/tmp/codex/build/snodec-idp/online/browsers \
  /tmp/codex/build/snodec-idp/online/venv/bin/python tests/live.py \
  --https --work-dir /tmp/codex/build/snodec-idp/online/https-run \
  --idp /absolute/path/to/auth_idp \
  --client /tmp/codex/build/snodec-idp/online/client/live-client
python3 tests/live_tls.py \
  --probe /tmp/codex/build/snodec-idp/online/client/live-transport \
  --work-dir /tmp/codex/build/snodec-idp/online/tls-run
```

Test both actual application executables with direct TLS and HTTP redirects too:

```bash
python3 tests/live_direct_tls.py \
  --idp /absolute/path/to/auth_idp \
  --app /absolute/path/to/minimal-mfa-app \
  --work-dir /tmp/codex/build/snodec-idp/online/direct-tls-run
```

The HTTPS suite uses direct IDP TLS and local proxies for its test client adapters,
trusts only its generated certificate
for requests and native clients, and permits that certificate's SPKI in Chromium.
It does not disable native TLS verification. The separate transport suite checks
both valid trust and rejection of an untrusted certificate or wrong hostname.
The two application origins use `localhost` and `127.0.0.1`: cookies are scoped by
host, not port, so separate applications on one hostname must avoid cookie-name
collisions in deployment.

The flow suite covers browser registration/TOTP, HttpOnly/SameSite/Secure cookies,
return to the original mounted route, both middleware adapters, SSO and logout,
password and MFA failures, direct/stale/swapped transaction rejection, CSRF,
reset delivery/consumption, password/MFA/account-deletion revocation, OAuth/refresh
replay, disabled providers, database backup with live restored password/TOTP
login, and IDP outage denial. The transport suite covers HTTP/TLS success,
certificate trust/hostname rejection, redirects, body limits, disconnect and
read timeout. Each group runs independently of preceding failures and writes
`results.json`; teardown runs even after a failure.

Live testing exposed four defects missed by the offline suite, now corrected:

- `no-referrer` made Chromium submit `Origin: null`. `strict-origin` preserves
  the usable origin without sending credential-bearing URL paths or queries.
- `form-action 'self'` blocked the cross-origin OAuth redirect after a form POST.
  The conflicting CSP clause is removed; exact callback registration, Origin
  checks, frame protection and base-URI protection remain.
- Mounted middleware saved the rewritten `url`; it now saves `originalUrl`.
- TLS handshake failures occur before HTTP context creation. Completion now
  follows transport disconnect, retaining the existing once-only callback guard.

Results and isolated build/runtime artifacts are retained under
`/tmp/codex/build/snodec-idp/online/`. Remove that directory after review to delete
test credentials, databases, browser downloads and development builds together.

## Explicit VHost integration checks

The existing HTTP/HTTPS suites exercise authentication through the standalone
server's IDP VHost. The additional routing suite uses the same executable and
disposable loopback fixtures, not a second implementation:

```bash
/absolute/path/to/python-with-requests tests/live_vhost.py \
  --idp /absolute/path/to/auth_idp \
  --work-dir /tmp/codex/build/snodec-idp/vhost/routing-run
```

The work directory must not exist. The suite checks default paths, unknown-host
rejection, many fixed redirects, GET/HEAD/POST behavior, invalid/duplicate/conflicting
configuration and the shared container health-probe script against a public IDP
hostname. Each check reports independently; all fixture processes are stopped.
Testing the probe natively does not constitute a Docker image startup test.

### Returning from account settings

Applications use `OAuthClient::accountUrl("/private")` to open account settings.
The helper builds `/settings?client_id=...&return=...` at the IDP, deriving the
application origin from its configured callback URL. The supplied local path can
include a query string. The example application's `/account` route uses this
helper, so **Back to application** leads to `/private`, not its public home page.

This is an application-specific navigation interface, not an OAuth/OIDC parameter
extension. The IDP accepts only HTTP(S) URLs whose scheme, host and effective port
match an existing callback registration for the supplied client ID. HTTPS is
required outside loopback. Paths need no separate registration; OAuth callback
matching remains exact. The client ID is caller-supplied, not proof of application
identity: callers can choose any registered client and a matching callback origin. The effective
navigation allowlist is therefore the set of registered callback origins.
Unknown clients and destinations that do not match the supplied registration are
rejected before account mutations. Return URLs are navigation only: no token or code is
attached when the browser follows the link.

The validated destination travels through IDP links, form actions and redirects,
including enrollment, profile changes, password changes and reauthentication.
It is request-local, so authenticated settings tabs from different applications
keep their own return destinations. Authentication still uses one browser-wide
pending transaction. Account login, registration, enrollment and federation
requests carrying a return destination receive HTTP 409 while an application
OAuth sign-in is pending; they
neither consume nor replace that transaction. Finish the application sign-in in
its original tab, then retry account settings. This does not provide concurrent
independent login transactions. The existing Google authentication transaction
carries navigation across the external provider round trip.

For password recovery, `OAuthClient::begin` supplies the optional `app_return`
authorization parameter using the original application path. This is a SNode.C
navigation parameter, not an OIDC parameter or an alternative OAuth callback.
The IDP validates its origin through the same registered-client policy, retains
it in the existing authorization transaction, and copies it into the recovery
form and email using `client_id` and `return`. Each recovery request validates
that destination again. These query values carry navigation only; the single-use
reset token remains the authority for changing a password. They are not a
cryptographic binding between the reset token and a particular application.

After reset, "Sign in to application" opens the original application destination
and starts a fresh OAuth sign-in when required. It does not reuse an expired
transaction or sign the user in automatically. The email works in a different
browser without the initiating cookies. Older clients that omit `app_return`
retain standalone recovery behavior. Direct visits to the IDP
without a return destination show no application-return link.

The destination must not contain credentials, secret tokens or a fragment.
On returning, the application enforces its normal authentication policy; a revoked
or expired session starts its usual login flow. The global `PROTECTED_WEBAPP_URL`
environment variable and `IdpConfig::protectedAppUrl` member have been removed.
Remove the obsolete variable from existing service environment files when
upgrading; deployment no longer generates it. Existing client registrations and
deployment JSON need no new fields. Legacy `/settings?return=...` links without
a matching `client_id` now return HTTP 400; update those links to use the helper.
