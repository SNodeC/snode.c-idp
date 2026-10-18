# Embedding the complete IDP

`auth/IdpMiddleware.h` exposes `snodec::auth::IdpMiddleware`, an Express router
containing the complete IDP: account pages, registration, password/TOTP login,
settings, recovery mail, OAuth endpoints, Google federation, discovery, JWKS and
health. The existing `auth_idp` executable now constructs and mounts this router;
there is no second implementation of its routes.

The application owns configuration loading, SNode.C initialization, listeners and
the event loop. The middleware reads no environment variables and starts no
listeners. Construction validates configuration, opens and initializes SQLite,
loads the signing key and validates/migrates encrypted TOTP storage. It can throw
if configuration, keys, storage or existing encrypted data are invalid.

## Constructor configuration

Pass an `IdpConfig` by value. The instance retains its own immutable copy; the
caller's configuration can be destroyed immediately after construction.

| Member | Requirement / meaning | Standalone environment mapping |
|---|---|---|
| `issuer` | Required public origin, without path or trailing slash; also the base URL for all IDP links | `IDP_ISSUER` and `IDP_BASE_URL`, which must agree |
| `clients` | Required JSON object mapping client IDs to arrays of exact callback URLs; explicitly use an empty object if no clients are registered | `IDP_CLIENTS` |
| `databasePath` | Required SQLite database path; parent directory must exist | `DB_PATH` |
| `privateKeyPath` | Required existing RSA private PEM path | `IDP_PRIVATE_KEY_PATH` |
| `totpKeyPath` | Required existing 32-byte binary encryption-key path; preserve it with the database | `TOTP_KEY_PATH` |
| `protectedAppUrl` | Optional application navigation link; empty hides it | `PROTECTED_WEBAPP_URL` |
| `smtpCommand` | Optional trusted operator command reading a complete reset message on stdin; empty disables reset delivery | `SMTP_COMMAND` |
| `googleClientId` | Optional Google OAuth client ID; both Google fields must be nonempty to enable login | `OAUTH_GOOGLE_CLIENT_ID` |
| `googleClientSecret` | Optional Google OAuth client secret | `OAUTH_GOOGLE_CLIENT_SECRET` |

HTTPS is required except for exact loopback hostnames supported by the existing
transport (`localhost` and `127.0.0.1`). The issuer has one authority in this API:
there is no separate base URL that could disagree with it. Listener port and bind
address belong to the host application, not `IdpConfig`. The standalone executable
retains its existing environment defaults, `IDP_PORT`, framework command-line
options and instance name `IdpServer`.

The existing authentication policy remains unchanged, including mandatory MFA at
protected clients, exact callback registration, five-attempt/60-second login and
MFA rate limiting, origin checks, token lifetimes and live-session revocation.
See the [IDP and client reference](idp-and-client-guide.md).

## Mounting and lifetime

After initializing SNode.C and creating an Express WebApp, mount the router:

```cpp
snodec::auth::IdpConfig config;
config.issuer = "http://localhost:8083";
config.clients = {{"minimal-mfa-app", {"http://localhost:8081/auth/callback"}}};
config.databasePath = "/absolute/path/to/data/auth.db";
config.privateKeyPath = "/absolute/path/to/keys/private_key.pem";
config.totpKeyPath = "/absolute/path/to/keys/totp.key";
config.protectedAppUrl = "http://localhost:8081";
// Optional: configure smtpCommand and both Google credentials here.
app.use(snodec::auth::IdpMiddleware(std::move(config)));
```

Include `auth/IdpMiddleware.h` and `<utility>`. The host then calls `app.listen(...)`
and `core::SNodeC::start()` as usual. The complete existing host is
[`IdpServer.cpp`](../src/apps/auth_idp/IdpServer.cpp).

Mount at the origin root. Generated links, redirects, cookie paths and protocol
endpoints are origin-root paths; a URL-prefix deployment such as `/idp` is not
supported by this extraction. Host selection remains the application's
responsibility. The existing standalone host now uses
[VHost routing and configurable client redirects](idp-and-client-guide.md#host-routing-and-client-redirects).
The middleware itself adds no hostname policy, TLS listeners or certificate provisioning.

Unmatched paths and HTTP methods fall through to the next mounted router without
IDP response headers or origin checks. Only matched IDP handlers apply those
policies and send responses. Mount the application's final 404 handler after all
routers; the middleware does not own the fallback response.

Each construction owns independent configuration, database connection,
authentication store, signer, rate limiters and uptime. Router copies share the
same instance; constructing another middleware creates another instance. Mounted
handlers retain shared ownership, so mounting a temporary as above is supported.
Pending asynchronous Google requests retain the same state until their callbacks
finish. No state points into the constructor's stack, and the state does not own
its router, avoiding an ownership cycle. Use the normal single SNode.C event-loop
thread; the SQLite wrapper is not independently thread-safe.

Independent IDPs should have distinct origins, database/key files and browser
cookie hosts. Browser cookies do not distinguish ports. The isolation test uses
separate HTTP client cookie jars when exercising two loopback ports; that does not
make two IDPs on the same browser hostname independent deployments.

## Installed CMake package

Build and install the full configuration (`AUTH_CLIENT_ONLY=OFF`) as documented
in the deployment guide. The full installation now exports the server library:

```cmake
find_package(snodec-auth 2 REQUIRED)
target_link_libraries(my_idp PRIVATE snodec-auth::auth-idp)
```

The server export includes its SQLite and QR static-library dependencies. Public
consumers only need the middleware header; implementation/storage headers remain
internal. A full `cmake --install` installs both client and server exports. For
component installation, install `auth-client` and `auth-idp` into the same prefix;
the standalone executable's existing component name is `auth_idp`.

`AUTH_CLIENT_ONLY=ON` still produces only `snodec-auth::auth-client` and does not
build or export the IDP. Use distinct installation prefixes for full and
client-only packages to avoid retaining stale exports from a previous full
installation. Existing relying-party source and configuration are unchanged.

## Verification

The offline authentication test includes constructor-configuration rejection.
The existing explicit HTTP and HTTPS suites exercise the standalone executable
through the extracted router, covering the browser/account/OAuth flows.

The additional installed-package consumer in `tests/live_idp.cpp` mounts two
middleware instances after destroying the constructor configuration and temporary
router objects. Its driver checks issuer/key/database separation, cross-instance
session rejection, independent rate limiting, reset-mail routing and logout.
It also checks exact per-instance client registration and disabled Google login.
A downstream router verifies that unmatched VHosts, paths and methods fall through
without IDP headers, and owns the test fallback 404. Matched IDP routes retain
origin checks and reject cookies on back-channel requests using SNode.C’s parsed
cookie collection.
It deliberately sets conflicting environment variables to verify that the
middleware uses constructor configuration exclusively.

Build the [installed test consumers](idp-and-client-guide.md#explicit-local-integration-tests)
against a full installation, then run:

```bash
/absolute/path/to/python-with-requests tests/live_idp.py \
  --server /absolute/path/to/installed-test-build/live-idp \
  --work-dir /tmp/codex/build/snodec-idp/middleware/isolation-run
```

The work directory must not exist. This explicit test starts two loopback
listeners in one process, uses disposable keys/accounts and local mail capture,
and stops that process afterward. It is not a CTest side effect. Real Google
login still requires provider credentials and was not exercised by the local
isolation test; asynchronous callback ownership is preserved in the implementation.

For this extraction, all three offline CTests, all seven HTTP flow groups, all
seven HTTPS flow groups and the five isolation/lifetime checks passed. Full and
client-only builds and installed consumers compiled with warnings treated as
errors; the embedding example above compiled against the installed full package.
No schema or client protocol change is introduced by the extraction.

Source updates do not automatically reinstall or restart an existing deployment.
Rebuild and deliberately restart the host when choosing to deploy a new revision.
