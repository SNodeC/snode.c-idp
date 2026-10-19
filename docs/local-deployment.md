<!-- snodec:begin page-header -->
<a id="banner"></a><a id="page-overview"></a>
<p><picture><source media="(max-width: 640px)" srcset="media/nav/banner-documentation-compact.svg"><img src="media/nav/banner-documentation.svg" alt="SNode.C IDP — Documentation" width="100%"></picture></p>
<p><a href="README.md#banner" title="Up to Documentation"><picture><source media="(prefers-color-scheme: dark)" srcset="media/nav/up-documentation-dark.svg"><img src="media/nav/up-documentation-light.svg" alt="Up to Documentation" title="Up to Documentation" width="160" height="28"></picture></a><a href="https://github.com/VolkerChristian#banner" title="Volker Christian account"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/account-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/account-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/account-dark.svg"><img align="right" src="media/nav/account-light.svg" alt="Volker Christian account" title="Volker Christian account"></picture></a><a href="https://github.com/SNodeC#banner" title="SNode.C organization"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/organization-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/organization-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/organization-dark.svg"><img align="right" src="media/nav/organization-light.svg" alt="SNode.C organization" title="SNode.C organization"></picture></a><a href="../README.md#banner" title="SNode.C IDP repository"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/repository-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/repository-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/repository-dark.svg"><img align="right" src="media/nav/repository-light.svg" alt="SNode.C IDP repository" title="SNode.C IDP repository"></picture></a><br clear="all"></p>
<!-- snodec:end page-header -->

# Local IDP and browser application: complete walkthrough

For a public server installed from binary packages, follow the [ten-step package deployment guide](package-deployment.md#banner) and its [interactive script](../scripts/deploy-core-snodec-org.sh). This page retains the separate source-based localhost development workflow.

This walkthrough deploys Jan Nicolas Eberwein’s SNode.C IDP from this fork and a
minimal SNode.C application on one Linux machine. It covers the implemented
account and browser flows, including failures and recovery. Building alone starts
no services; the explicit commands in step 6 start them.

The application delegates login to the IDP and requires both MFA and a live IDP
session. Registering an account or passing a password check alone does not grant
access to the application.

| Component | Address | Purpose |
|---|---|---|
| IDP | `http://localhost:8083` | Accounts, password/TOTP, sessions and OAuth |
| Application | `http://localhost:8081` | Public homepage |
| Protected page | `http://localhost:8081/private` | Requires authenticated MFA session |
| Application callback | `http://localhost:8081/auth/callback` | Server-side code exchange; do not open manually |
| Account settings | `http://localhost:8083/settings` | Profile, password, MFA and deletion |

Use these exact hostnames throughout. `localhost` and `127.0.0.1` are different
origins and cookie hosts. HTTP is supported for loopback development; remote
browser access needs HTTPS. Both servers below explicitly bind to loopback.
No Google account, Docker, external SMTP service or client secret is needed.

## Browser URLs and service endpoints

The URLs below use this walkthrough's application port **8081** and IDP port
**8083**. The running development-machine demo uses application port **8084**,
because ports 8081 and 8082 belong to the MQTT bridge. Its application URLs are
http://localhost:8084/, http://localhost:8084/private and
`http://localhost:8084/auth/callback`; all IDP URLs below are unchanged. Follow
the matching application port consistently when configuring callbacks.

### Pages to open in your browser

| Page | URL | Purpose |
|---|---|---|
| Application homepage | http://localhost:8081/ | Start application login |
| Protected application | http://localhost:8081/private | Requires an MFA-authenticated live session |
| IDP homepage | http://localhost:8083/ | Identity provider landing page |
| Account dashboard | http://localhost:8083/dashboard | Authenticated account overview |
| Login | http://localhost:8083/auth/login | Sign in to the IDP |
| Registration | http://localhost:8083/auth/register | Create an account |
| Account settings | http://localhost:8083/settings | Change username, email, password and MFA |
| Enroll authenticator | http://localhost:8083/auth/enroll/totp | Requires an appropriate registration or authenticated session |
| Authenticator help | http://localhost:8083/auth/help/authenticator | TOTP setup instructions |
| Disable MFA | http://localhost:8083/settings/mfa/disable | Confirmation with credential checks |
| Forgot password | http://localhost:8083/auth/forgot-password | Request a password-reset email |
| Logout | http://localhost:8083/auth/logout | Confirmation page; submit to sign out |
| Delete account | http://localhost:8083/settings/delete | Account-deletion confirmation |

Password-reset links have the form
`http://localhost:8083/auth/reset-password?token=...`. Use the complete link from
the captured email; opening the path without a valid token cannot reset a
password. Captured messages are files under `$DEMO_DIR/mail/` (by default
`~/.local/share/snodec-idp-demo/mail/`), not a web inbox. Registration does not
send welcome or email-verification messages. Reset delivery is captured locally
until an external mail transport is configured.

Bookmark the protected application page, not its callback. When starting from
the application, follow the IDP's login/register links to preserve that login
transaction. Settings and account-management pages require an IDP session.

### Diagnostic URLs

| URL | Purpose |
|---|---|
| http://localhost:8083/health | Service health and build version |
| http://localhost:8083/.well-known/openid-configuration | Authentication protocol metadata |
| http://localhost:8083/.well-known/jwks.json | Public signing key |

### Form and protocol endpoints

These endpoints are invoked by forms or authentication clients. They are not
standalone pages to bookmark. GET endpoints below also need the appropriate
parameters or credentials; a POST endpoint is not invoked by opening its URL.

| Method | URL | Purpose |
|---|---|---|
| GET | `http://localhost:8081/auth/callback` | Application login callback with code and state |
| GET | `http://localhost:8083/oauth2/authorize` | Begin authorization with registered callback and PKCE parameters |
| POST | `http://localhost:8083/oauth2/token` | Server-side code exchange or refresh rotation |
| POST | `http://localhost:8083/oauth2/introspect` | Server-side token/session validation |
| GET | `http://localhost:8083/oauth2/userinfo` | User information with a valid live Bearer token and appropriate scope |
| POST | `http://localhost:8083/auth/mfa` | Submit the login transaction's TOTP code |
| POST | `http://localhost:8083/auth/enroll/totp/verify` | Confirm enrollment |
| POST | `http://localhost:8083/auth/enroll/totp/skip` | Skip enrollment; protected application access still requires MFA |
| POST | `http://localhost:8083/settings/profile` | Submit profile changes |
| POST | `http://localhost:8083/settings/password` | Submit password changes |
| GET | `http://localhost:8083/api/qrcode` | Generate QR output with parameters |
| GET | `http://localhost:8083/auth/federated/google` | Google login; unconfigured in the default local demo |
| GET | `http://localhost:8083/auth/federated/google/callback` | Google callback; unconfigured in the default local demo |

The login, registration, forgot-password, reset-password, logout, disable-MFA
and delete-account pages also submit POST requests to their corresponding paths.
Use their forms so required credentials, transaction references and browser-origin
checks are preserved. See the [endpoint reference](idp-and-client-guide.md#account-and-protocol-endpoints)
for the protocol contract.

## 1. Prerequisites and source locations

You need a C++20 compiler, CMake 3.18+, Ninja, Git, pkg-config, OpenSSL 3 development
files, SQLite development files, nlohmann JSON 3.11+, Python 3 and curl. The
framework also uses Brotli and libmagic. On Ubuntu 24.04 the package set used by
the repository's Docker build, with tools for this walkthrough, is:

```bash
sudo apt-get update
sudo apt-get install build-essential cmake ninja-build git pkg-config \
  libssl-dev libsqlite3-dev libbrotli-dev libmagic-dev nlohmann-json3-dev \
  ca-certificates python3 curl openssl
```

Use your existing source checkouts. On the development machine they are:

```bash
export IDP_REPO=/home/voc/projects/snodec/checkouts/idp-client-guide
export SNODEC_REPO=/home/voc/projects/snodec/snode.c
export DEMO_DIR="$HOME/.local/share/snodec-idp-demo"
export SNODEC_BUILD="$SNODEC_REPO/build/codex/idp-demo"
export SNODEC_PREFIX="$SNODEC_BUILD/install"
export AUTH_BUILD="$IDP_REPO/build/codex/local-demo"
export AUTH_PREFIX="$AUTH_BUILD/install"
export APP_BUILD="$IDP_REPO/build/codex/local-demo-app"

git -C "$IDP_REPO" status --short
git -C "$IDP_REPO" rev-parse HEAD
git -C "$SNODEC_REPO" rev-parse HEAD
```

Adjust the first two paths on another machine. The repositories are
[SNodeC/snode.c-idp](https://github.com/SNodeC/snode.c-idp) and
[SNodeC/snode.c](https://github.com/SNodeC/snode.c). Use the hardened API 2 version
of this fork, not the original upstream IDP. The live-tested framework revision
is `ba57feee0e62e6780abb778fff54a29f443d5439`; the tested IDP code is commit
`38513de31df8840203eb6a737c6a96f52f43be68`. Record your actual revisions when testing
newer code. Do not reset an existing checkout with local changes to reproduce a
version.

Keep this terminal open through setup. Later terminals repeat the path exports
above. Persistent builds live under `build/codex`; runtime data lives in
`DEMO_DIR`, outside temporary storage.

## 2. Build the framework and full IDP

The standalone server hosts the complete [IdpMiddleware router](idp-middleware.md).
It reads the environment file used below and passes those values to the router;
the router itself does not read environment variables.

Initialize framework submodules, configure, build and install into a private
prefix. Installation here does not alter the system installation:

```bash
git -C "$SNODEC_REPO" submodule update --init --recursive
cmake -S "$SNODEC_REPO" -B "$SNODEC_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_INSTALL_PREFIX="$SNODEC_PREFIX" \
  -DSNODEC_BUILD_APPS=OFF -DSNODEC_BUILD_TESTS=OFF
cmake --build "$SNODEC_BUILD" --parallel
cmake --install "$SNODEC_BUILD"

cmake -S "$IDP_REPO" -B "$AUTH_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_PREFIX_PATH="$SNODEC_PREFIX" \
  -DCMAKE_INSTALL_PREFIX="$AUTH_PREFIX" \
  -DCMAKE_INSTALL_RPATH="$SNODEC_PREFIX/lib" \
  -DAUTH_CLIENT_ONLY=OFF -DBUILD_TESTING=ON
cmake --build "$AUTH_BUILD" --parallel
ctest --test-dir "$AUTH_BUILD" --output-on-failure
cmake --install "$AUTH_BUILD"
```

Stop at any failed command and resolve it before continuing. CTest runs the offline
suite; it does not start an IDP. The resulting IDP is
`$AUTH_PREFIX/bin/auth_idp`. The same installation provides the client package.
An existing compatible framework installation can replace step 2's framework
build: set `SNODEC_PREFIX` to its installation prefix.

## 3. Create persistent runtime directories and keys

For a **new deployment only**:

```bash
umask 077
mkdir -p "$DEMO_DIR"/{keys,data,mail,app,config,state}
chmod 700 "$DEMO_DIR"
touch "$DEMO_DIR/config/empty.conf"
```

Generate the signing key and TOTP encryption key once. The guarded block refuses
to overwrite keys or initialize over a database:

```bash
if [ -e "$DEMO_DIR/keys/private_key.pem" ] || \
   [ -e "$DEMO_DIR/keys/public_key.pem" ] || \
   [ -e "$DEMO_DIR/keys/totp.key" ] || \
   [ -e "$DEMO_DIR/data/auth.db" ]; then
  echo 'Existing deployment found: preserve its keys and database; skip generation.'
else
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
    -out "$DEMO_DIR/keys/private_key.pem" &&
  openssl pkey -in "$DEMO_DIR/keys/private_key.pem" -pubout \
    -out "$DEMO_DIR/keys/public_key.pem" &&
  openssl rand -out "$DEMO_DIR/keys/totp.key" 32
fi
openssl pkey -in "$DEMO_DIR/keys/private_key.pem" -check -noout
test "$(wc -c < "$DEMO_DIR/keys/totp.key")" -eq 32
```

If generation fails partway through, investigate before proceeding; the guard
also protects partial output. A pre-existing deployment must have its original,
matching keys. Replacing `totp.key` makes stored authenticators unreadable.
Replacing the signing key requires updating every application's trusted public
key and invalidates old signatures. Neither operation is a normal restart step.

## 4. Configure the IDP and local recovery mail

Create a local mail capture program. It stores reset messages privately instead
of sending email. Anyone who can read these files can use an unexpired reset
link, so this is for a single-user local development deployment.

```bash
cat > "$DEMO_DIR/capture-mail.py" <<'PY'
import os
import sys
import time
from pathlib import Path

mail = Path(os.environ["DEMO_DIR"]) / "mail"
mail.mkdir(mode=0o700, exist_ok=True)
(mail / (str(time.time_ns()) + ".eml")).write_bytes(sys.stdin.buffer.read())
PY

cat > "$DEMO_DIR/idp.env" <<'ENV'
export IDP_PORT=8083
export IDP_BASE_URL=http://localhost:8083
export IDP_ISSUER=http://localhost:8083
export HOST_REDIRECTS='{}'
export IDP_CLIENTS='{"minimal-mfa-app":["http://localhost:8081/auth/callback"]}'
export DB_PATH="$DEMO_DIR/data/auth.db"
export IDP_PRIVATE_KEY_PATH="$DEMO_DIR/keys/private_key.pem"
export IDP_PUBLIC_KEY_PATH="$DEMO_DIR/keys/public_key.pem"
export TOTP_KEY_PATH="$DEMO_DIR/keys/totp.key"
export SMTP_COMMAND="python3 \"$DEMO_DIR/capture-mail.py\""
export OAUTH_GOOGLE_CLIENT_ID=
export OAUTH_GOOGLE_CLIENT_SECRET=
ENV
chmod 600 "$DEMO_DIR/idp.env"
```

The standalone server selects its IDP VHost from `IDP_BASE_URL`.
`HOST_REDIRECTS` optionally maps other hostnames to fixed client URLs; `{}` keeps
the single-IDP setup. See [host routing and redirects](idp-and-client-guide.md#host-routing-and-client-redirects)
for multiple hostnames, matching rules and TLS/health-check requirements.
The local URLs and OAuth callback paths remain unchanged.

`DEMO_DIR` must be exported before sourcing this file. The IDP does not load this
shell file automatically. `IDP_CLIENTS` is the exact allowlist of client IDs and
callback URLs; no implicit localhost exception exists. `IDP_ISSUER` and
`IDP_BASE_URL` must agree, with no trailing slash. Applications open account
settings with `OAuthClient::accountUrl(localReturn)`, which supplies their client
ID and return URL. Account navigation accepts paths on that client's registered
callback origins; OAuth callbacks still require an exact registered URL.

For actual email, install and configure a mail submission program and replace
`SMTP_COMMAND` with its fixed command, for example `msmtp -t`. It must read the
recipient from the message's `To` header and return success only after accepting
delivery. Credentials belong in protected mail-tool configuration, not source
control. See the [msmtp manual](https://marlam.de/msmtp/msmtp.html). No SMTP server
or delivery account is bundled. A missing or failing command produces the same
generic reset response and invalidates the undelivered reset credential.

## 5. Create and build the browser application

Copy the complete **`main.cpp` and `CMakeLists.txt`** from
[Complete minimal application](idp-and-client-guide.md#complete-minimal-application)
into `$DEMO_DIR/app/`. That section is the canonical source; use it unchanged for
this walkthrough. Its issuer, client ID, callback and listen port already match
this setup. It has three routes: `/`, `/private`, and `/auth/callback`.

Give the application only the public signing key, then build:

```bash
cp "$DEMO_DIR/keys/public_key.pem" "$DEMO_DIR/app/idp-public.pem"
cmake -S "$DEMO_DIR/app" -B "$APP_BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$AUTH_PREFIX;$SNODEC_PREFIX"
cmake --build "$APP_BUILD" --parallel
```

The application uses the installed `snodec-auth` package. It does not read the IDP
database, private signing key or TOTP encryption key. Its relative public-key
filename makes the working directory in step 6 significant.

## 6. Start both services

**Terminal A: IDP.** Repeat the path exports from step 1, then:

```bash
umask 077
source "$DEMO_DIR/idp.env"
export XDG_CONFIG_HOME="$DEMO_DIR/config"
export XDG_STATE_HOME="$DEMO_DIR/state"
cd "$DEMO_DIR"
"$AUTH_PREFIX/bin/auth_idp" \
  --config-file "$DEMO_DIR/config/empty.conf" \
  IdpServer local --host 127.0.0.1
```

The first successful startup initializes SQLite. There is no bootstrap admin
account or default password. Configure the environment before invoking the IDP,
even for `--help`: initialization loads keys/database before framework argument
handling. Leave this terminal running.

**Terminal B: application.** Repeat the path exports from step 1, then:

```bash
export XDG_CONFIG_HOME="$DEMO_DIR/config"
export XDG_STATE_HOME="$DEMO_DIR/state"
cd "$DEMO_DIR/app"
"$APP_BUILD/minimal-mfa-app" \
  --config-file "$DEMO_DIR/config/empty.conf" \
  MinimalMfaApp local --host 127.0.0.1
```

**Terminal C: checks.**

```bash
curl --fail http://localhost:8083/health
curl --fail http://localhost:8083/.well-known/openid-configuration
curl --fail http://localhost:8081/
ss -ltnp 'sport = :8083 or sport = :8081'
```

Expect successful responses and loopback listeners. A healthy IDP alone does not
prove MFA works; continue with the browser steps. If a shared library cannot be
found, check the installation prefix and RPATH; for this private installation you
can explicitly export `LD_LIBRARY_PATH="$SNODEC_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"`
in the affected terminal before starting the process.

## 7. Create your first account and enter the application

1. Open **http://localhost:8081/** in your browser.
2. Click **Sign in with MFA**. `/private` redirects to the IDP login page.
3. Follow **Register** from that page, preserving the application login flow.
4. Choose a unique username (3–64 characters), a unique email address (at most
   254 characters, containing `@`), and a password (8–128 characters). Confirm
   the password. For mail capture, an address such as `alice@example.test` works.
5. Leave two-factor authentication enabled on registration.
6. Scan the enrollment QR code using a TOTP authenticator, or enter the displayed
   Base32 secret manually. The authenticator must use the QR's TOTP parameters.
7. Enter the current six-digit code and activate MFA. Keep the machine and
   authenticator clocks synchronized.
8. The browser returns through the application callback to `/private`, which
   displays **Authenticated with MFA**.

The local email address is **not verified for ownership** during registration.
This creates an ordinary account; there are no administrative roles or approval
steps. The QR/secret is a credential: do not publish it or put it in screenshots.

You can also register directly at http://localhost:8083/auth/register. That flow
finishes at the IDP; open the application and click its sign-in link afterward.
If enrollment expires, log in with the newly registered username and password to
resume the account flow; do not register a duplicate account.

## 8. Login, SSO, logout and expiry

### Normal login

After signing out, visit `/private` again. Enter the account's **username** and
password at the IDP, then its current TOTP code. Successful MFA returns to the
application. Incorrect passwords or codes do not authenticate; retry through the
current form. Repeated failures are rate-limited (five attempts per 60-second
window for the relevant limiter). A rejection need not use HTTP 429.

### Single sign-on

While the same browser has a valid MFA-authenticated IDP session, beginning a new
application login can return without another password/TOTP prompt. A second
browser profile or private window starts a separate session. Password-only IDP
sessions never become MFA sessions merely because an application requests login.

### Logout

1. Open http://localhost:8083/auth/logout.
2. Submit the **Sign out** confirmation. Opening the GET page alone does not log
   you out. The IDP's own navigation also offers sign-out.
3. Revisit the application's `/private` page. Its live session check denies the
   revoked grant, clears the stale access cookie and redirects the browser to
   sign-in. No manual reload is needed.

Logout revokes the current IDP session and the application grants issued from
it. It does not log out independently established sessions on other devices,
and it does not log out Google's own browser session. The minimal application
has no separate local logout route. Clearing only its cookie is not IDP logout:
the remaining IDP session can sign you straight back in.

### Expiry and interrupted flows

| Item | Lifetime / consequence |
|---|---|
| Access token | Five minutes; the minimal app reauthorizes rather than automatically refreshing |
| IDP and application login transactions | Ten minutes; start a fresh login when expired |
| Authorization code | Two minutes, single use |
| IDP session | 24 hours; requires new authentication after expiry |
| Refresh credential | Up to 24 hours, bounded by the IDP session; rotates on use |
| Password reset link | 15 minutes, single use; a newer request supersedes the old one |

Do not bookmark callback URLs, replay a code or copy a callback into another
browser. State, nonce, PKCE and browser transaction binding must match. Use `/`
or `/private` as your bookmark. Keep one active enrollment/login flow per browser;
starting another can replace the transaction cookie and invalidate the older
form. Restarting the app loses pending in-memory login transactions; restart the
login from `/private`. Stored IDP accounts survive service restarts.

## 9. Password-only accounts and authenticator management

**Skipped enrollment:** registration can create a password-only IDP account if
you uncheck MFA or skip enrollment. This account can use the IDP but cannot enter
this protected application. Log in to http://localhost:8083/settings, enable MFA,
scan the QR and verify a current code. Then return to `/private` and start a fresh
login. An old application cookie is cleared automatically as the browser returns to sign-in.

**Disable MFA:** in Settings, choose Disable and complete the confirmation with
your current password and TOTP code. A Google-only account has no local password
to supply, but still needs its TOTP code. Disabling MFA revokes existing sessions.
Subsequent password-only login cannot access this application until MFA is enabled
again.

**Move to another authenticator:** while the old authenticator still works,
disable MFA with the old credentials, log in again, and enroll the new device
through Settings. This changes the secret and revokes affected sessions. Verify
the new device before discarding your recovery arrangements.

**Lost authenticator:** there are no recovery codes, alternate SMS factor,
WebAuthn factor or self-service MFA bypass. Password reset changes the password;
it does not remove TOTP. Without the authenticator or a valid backup of it, this
implementation provides no self-service way to recover an MFA-enabled account.
An operator recovery procedure would need separate design and identity checks;
editing database flags is not a supported recovery workflow.

## 10. Password recovery, end to end

1. Open http://localhost:8083/auth/forgot-password, or follow the login page's
   reset link.
2. Submit the account's stored email address. The response is deliberately generic
   for existing and missing accounts and for delivery failures.
3. For this local setup, inspect the newest captured message:

   ```bash
   ls -lt "$DEMO_DIR/mail"
   ```

   Open the newest `.eml` file in a local text editor. Check its `To` header and
   copy its reset URL into the browser. Do not share the message or link.
4. Within 15 minutes, enter and confirm a new 8–128-character password.
5. Return to the application and log in with the new password and your TOTP code.

Successful reset revokes existing sessions and grants. The old password stops
working. Reusing the link fails, and requesting another link invalidates the
previous one. An expired/used link can display an error page even when the HTTP
status is 200. Request a new link through the normal form.

No file means no captured delivery: inspect the IDP terminal, exported
`DEMO_DIR`, `SMTP_COMMAND`, filesystem permissions and account email. Do not expect
a reset link in the browser response or server log. With real SMTP, check the
recipient inbox and mail submission logs instead. Remove captured reset mail
when no longer needed.

## 11. Profile changes, password changes and account deletion

| Action in `http://localhost:8083/settings` | Steps and effect |
|---|---|
| Change username/email | Edit and save; both must remain unique. Use the new username for subsequent password login and the new email for reset delivery. No email ownership verification is sent. Existing token claims can remain stale until a new token is issued. |
| Change local password | Supply current password, new password and confirmation. All of this user's existing sessions are revoked; log in again with the new password and TOTP. |
| Delete account | Open the danger-zone deletion form, type the exact username and provide the local password and current TOTP when applicable. Confirm only for an account you intend to remove. The user and associated sessions/grants are deleted. |

A Google-only account's settings omit the local-password change form and do not
require a nonexistent local password for deletion. MFA-enabled accounts still
need their TOTP. Deletion is irreversible through the UI; restoration requires an
operator backup. Re-registering the same available name creates a new identity,
not the original account.

## 12. Optional Google login

This is optional and needs external Google credentials; it is not necessary for
any local password/TOTP flow above.

1. In a Google Cloud project, configure the OAuth consent setup and a **Web
   application** OAuth client. Permit the intended test accounts when using a
   testing configuration.
2. Register this exact authorized redirect URI:
   `http://localhost:8083/auth/federated/google/callback`.
   This is the **IDP's Google callback**, distinct from the application's callback.
3. Set nonempty `OAUTH_GOOGLE_CLIENT_ID` and `OAUTH_GOOGLE_CLIENT_SECRET` in the
   protected `idp.env`. Restart the IDP with that file sourced.
4. Start login from the application and choose Google on the IDP login page.
   Complete Google's login/consent screens.
5. A new federated identity still needs **this IDP's TOTP enrollment** to enter
   the protected application. Visit IDP Settings, enroll and verify TOTP, then
   begin application login again. An already-enrolled Google identity is prompted
   for the IDP's TOTP during login.

The IDP maps Google's stable subject to an account; an email collision with a
local account fails instead of automatically linking identities. There is no
account-linking UI or automatic migration of legacy email-linked identities.
Google's own MFA does not replace the IDP's TOTP requirement. Apple and Meta
login are not implemented.

Google setup and exact redirect matching are described in the official
[web-server OAuth guide](https://developers.google.com/identity/protocols/oauth2/web-server)
and [OpenID Connect guide](https://developers.google.com/identity/openid-connect/openid-connect).
Actual Google login was not included in the local live verification because no
provider credentials were configured.

## 13. Register another application

Each application needs its own client ID, callback, public-key deployment and
application process. Add its callback to the **same** `IDP_CLIENTS` JSON object,
restart the IDP and configure the second client's `OAuthClient` consistently.
For example:

```bash
export IDP_CLIENTS='{"minimal-mfa-app":["http://localhost:8081/auth/callback"],"second-app":["http://127.0.0.1:8082/auth/callback"]}'
```

Persist the change in `idp.env` before restarting. For the second application use
client ID `second-app`, callback `http://127.0.0.1:8082/auth/callback`, listen port
8082 and a distinct WebApp/configuration name. Keep the issuer
`http://localhost:8083`. Open it at `http://127.0.0.1:8082`.

The different application hostname is intentional: browser cookies are scoped by
host, not port, and these clients use the same access-cookie name. Two applications
on `localhost` at different ports can overwrite that cookie. For a larger local
setup, use distinct application hostnames with HTTPS and matching registrations.
The existing IDP session can supply SSO across these separate application hosts.

## 14. Stop, restart, back up and restore

Stop each foreground process with Ctrl-C in its terminal, and verify ports 8081
and 8083 no longer have listeners. If a process remains, identify its exact PID
with `ss -ltnp` before terminating that process. Do not kill unrelated services.
Restart using step 6, preserving the database and keys. Do not repeat key creation.

Back up SQLite consistently, including when WAL mode is in use. For this small
local deployment, stop the IDP first, repeat the path exports, then:

```bash
umask 077
export BACKUP_DIR="$DEMO_DIR/backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"
python3 - <<'PY'
import os
import sqlite3
from pathlib import Path

source_path = Path(os.environ["DEMO_DIR"]) / "data/auth.db"
backup_path = Path(os.environ["BACKUP_DIR"]) / "auth.db"
with sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True) as source:
    with sqlite3.connect(backup_path) as target:
        source.backup(target)
PY
cp -a "$DEMO_DIR/keys" "$BACKUP_DIR/keys"
cp "$DEMO_DIR/idp.env" "$BACKUP_DIR/idp.env"
```

Keep an access-controlled copy outside this machine and record the source
revisions. Backups contain password hashes, encrypted TOTP secrets and the keys
that decrypt them. Copying only the main database file while writers are running
can omit WAL data; copying only the database without the original TOTP key is
not a usable authenticator backup.

To restore, keep the IDP stopped and restore into a fresh runtime directory:
put the snapshot at `data/auth.db`, restore `keys/` and `idp.env`, recreate the
config/mail directories and capture script from steps 3–4, and set `DEMO_DIR` to
that directory. Do not mix the restored database with old `auth.db-wal` or
`auth.db-shm` files. Copy the restored public key into the application's working
directory. Start using step 6 and verify password plus TOTP login. Preserve the
old runtime directory until recovery is verified. Restoring a snapshot also
restores its historical account/session state; later changes are not in it.

## 15. Failure paths and deployment boundaries

| Symptom | What to check or do |
|---|---|
| Connection refused | Start the appropriate process; inspect its terminal and loopback port. |
| Address already in use | Identify the owner with `ss`; use a free port only after updating the app, origins and exact callback registry together. |
| Callback rejected | Match issuer, client ID and callback byte-for-byte; keep hostname consistent; restart login from `/private`. |
| MFA account cannot authenticate | Verify clock synchronization and current code, wait out rate limiting, and use a fresh transaction rather than an old form. |
| Password succeeds but `/private` denies access | Complete IDP TOTP enrollment and a fresh MFA login; password-only sessions intentionally fail. |
| Callback fails after app restart | Pending transactions are in memory; start again. Multi-worker callback routing must reach the process that started the transaction. |
| IDP unavailable while app runs | Protected requests fail closed because live session checks cannot complete; the public homepage can remain available. Restore the IDP, then start login again. |
| Old page fails after logout/password/MFA change | Its session was revoked; begin a fresh login. Revocation is checked on subsequent protected requests. |
| Reset response succeeds but no email | Generic responses conceal account existence and delivery failure; inspect the local capture or configured mail transport. |
| JWT/key/issuer errors | Use the matching trusted public key and exact issuer; inspect time and configuration. Never disable verification to get past an error. |

The example does not expose a protected JSON API, implement automatic refresh,
or define an application-specific logout endpoint. The library's Bearer
middleware and OAuth endpoints are documented in the
[API and endpoint reference](idp-and-client-guide.md#client-api-and-lifetime).
Use the shared client policy for additional protected routes; do not hand-roll
JWT or MFA checks.

For public deployment, use direct SNode.C HTTPS listeners for both origins, register the exact HTTPS callback and deploy matching signing-key trust. The [ten-step package guide](package-deployment.md#banner) covers the interactive script, public ports, certificates, Google and mail. The [container reference](idp-and-client-guide.md#docker-and-operational-lifecycle) uses direct HTTPS on port 8088. This localhost HTTP recipe remains a development configuration; do not expose it publicly unchanged.

There is no invitation/approval system, administrative account-management UI,
email-verification flow, recovery-code flow, provider-linking UI or complete
implementation of every optional OIDC feature. These are feature boundaries,
not hidden steps required to finish this deployment.

## 16. Manual acceptance checklist and automated live tests

Use a disposable account for destructive cases:

- Register with MFA and reach the protected page.
- Sign out, then log in with password and TOTP.
- Verify wrong password/code rejection and password-only denial.
- Verify same-browser SSO and separate-browser session isolation.
- Reset the password through captured mail; verify the old password and reused
  link fail, and TOTP remains required.
- Change profile/password, disable and re-enable MFA, then verify expected
  revocation and new login.
- Delete the disposable account and verify its previous access no longer works.
- Restart services with preserved keys/data and verify a retained account works.
- Stop only the IDP and verify the application denies protected access.

For repeatable browser and native TLS checks, follow
[Explicit local integration tests](idp-and-client-guide.md#explicit-local-integration-tests).
Those commands create separate disposable fixtures; they do not test or modify
the account database created by this walkthrough.

The recorded implementation verification passed **7/7 HTTP browser checks,
7/7 HTTPS browser checks, 8/8 native transport/TLS checks and all 3 offline
CTests**, including local reset-mail capture and backup/restore. External SMTP,
actual Google login and Docker startup were not verified. This document does not
claim that arbitrary newer revisions or an independently configured deployment
have passed those tests; run the checklist against your own deployment.
