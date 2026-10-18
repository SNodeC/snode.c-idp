<!-- snodec:begin page-header -->
<a id="banner"></a><a id="page-overview"></a>
<p><picture><source media="(max-width: 640px)" srcset="media/nav/banner-documentation-compact.svg"><img src="media/nav/banner-documentation.svg" alt="SNode.C IDP — Documentation" width="100%"></picture></p>
<p><a href="README.md#banner" title="Up to Documentation"><picture><source media="(prefers-color-scheme: dark)" srcset="media/nav/up-documentation-dark.svg"><img src="media/nav/up-documentation-light.svg" alt="Up to Documentation" title="Up to Documentation" width="160" height="28"></picture></a><a href="https://github.com/VolkerChristian#banner" title="Volker Christian account"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/account-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/account-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/account-dark.svg"><img align="right" src="media/nav/account-light.svg" alt="Volker Christian account" title="Volker Christian account"></picture></a><a href="https://github.com/SNodeC#banner" title="SNode.C organization"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/organization-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/organization-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/organization-dark.svg"><img align="right" src="media/nav/organization-light.svg" alt="SNode.C organization" title="SNode.C organization"></picture></a><a href="../README.md#banner" title="SNode.C IDP repository"><picture><source media="(max-width: 640px) and (prefers-color-scheme: dark)" srcset="media/nav/repository-icon-dark.svg"><source media="(max-width: 640px)" srcset="media/nav/repository-icon-light.svg"><source media="(prefers-color-scheme: dark)" srcset="media/nav/repository-dark.svg"><img align="right" src="media/nav/repository-light.svg" alt="SNode.C IDP repository" title="SNode.C IDP repository"></picture></a><br clear="all"></p>
<!-- snodec:end page-header -->

# Authentication hardening: implementation boundary

Status: implemented; offline verification completed on 2026-10-17. Based on `ed3b897` on
`docs/idp-client-guide`, inspected 2026-10-17. This continues the existing
IDP/client task in the approved checkout. The initial implementation started no
services; subsequent explicitly authorized local integration is recorded below.

## Governing invariant

Every successful authentication must derive from a browser-bound, expiring,
single-use login transaction and an authoritative live IDP session. The session
records factors actually completed. Client, redirect URI, PKCE challenge, nonce,
and federation identity must remain bound to that transaction. Browser fields,
JWT copies, and migration defaults cannot create authentication authority.

Cryptographic verification and current authorization are distinct: a valid JWT
signature alone cannot establish that the issuing session remains active.

## Existing boundaries and smallest coherent changes

| Issue | Owning implementation | Proposed root correction |
|---|---|---|
| 1. Callback binding and injection | `JwtAuthMiddleware.h`, `OAuth2CallbackHandler.h` | Replace destination-as-state with random, expiring, one-use transaction state bound to a browser cookie. Store the PKCE verifier and local return path on the server. Use an explicitly configured callback URL instead of trusting Host/forwarded headers. Delete the generated callback JavaScript. |
| 2. Browser-readable credentials | Same client boundary | Exchange codes through SNode.C's asynchronous HTTP client. Set the credential cookie on the server with HttpOnly, SameSite, and transport-appropriate Secure attributes. Never send the verifier, token response, or credentials in executable HTML or logs. Keep bearer-token API support. |
| 3. MFA enforcement | `AuthMiddleware`, `JwtAuthMiddleware`, `JwtClaims`/`UserContext` | Give both middleware entry points one shared authorization policy and preserve verified MFA information in the user context. Require MFA by default; any explicitly supported single-factor policy must be configured, never inferred from an absent claim. |
| 4. MFA transaction binding | IDP password, registration, SSO, federation, enrollment, and MFA handlers | Extend the existing authoritative login/session lifecycle so pending authentication cannot access authenticated routes. Carry OAuth context server-side. Complete the same browser-bound transaction after TOTP; consume it atomically. A submitted user ID is never proof of password authentication. |
| 5. Reset-link disclosure | Forgot/reset-password handlers and delivery helper | Delete reset links from responses and logs. Deliver only to the stored account email through configured delivery. Return the same generic response for registered and unregistered addresses; never substitute browser disclosure when delivery is absent or fails. Atomically consume reset tokens and revoke affected sessions. |
| 6. False bootstrap promise | Startup, configuration, documentation | Delete the unused claim-token mechanism and administrator/setup claims. There is no implemented administrator role to protect; do not invent a role-management subsystem as a bug fix. Clearly document existing registration semantics. |
| 7. Client/redirect binding | Authorization, continuation, code issuance/redemption | Replace the broad redirect allowlist and automatic local/private-IP exceptions with one explicit client-to-callback registry. Validate once when creating a login transaction and retain that validated context. Require exact client/redirect/PKCE matching at code redemption. Unsupported redirect destinations never receive an authorization response. |
| 8. OIDC/token correctness | Signer, verifier, JWKS, discovery and token endpoints | Replace hand-written JSON with the existing nlohmann JSON dependency. Centralize key identity in the signing-key owner. Issue distinct access and ID tokens with appropriate claims and nonce propagation. Validate token purpose and typed claims; implement the advertised userinfo behavior and align discovery with actual supported endpoints. |
| 9. Federation | Provider registry and federation handlers | Remove synthetic Apple/Meta identity paths and their unsupported configuration. Keep Google using the shared asynchronous HTTP transport. Bind provider state to the pending browser transaction; verify provider identity and use provider subject as the identity key. Do not implicitly link an existing local account by an email string. Require nonempty credentials and remove raw provider-response logging. |
| 10. Revocation | Existing session table, codes, refresh tokens and both client middleware paths | Make IDP session existence/expiry the authority. Link grants and refresh credentials to that session, and revoke through that authority on logout/account-security changes. Clients check current token/session status through an authenticated IDP endpoint after local cryptographic validation; fail closed on errors. No second revocation cache or independent blacklist. |
| 11. Storage and legacy MFA claims | Encryption helpers and database migration | Remove plaintext fallback; require a usable encryption key and fail closed. Migrate existing plaintext records transactionally only when encryption succeeds. Never promote old sessions to MFA-verified; invalidate unverifiable legacy authentication state. Keep schema/migration ownership in the database layer rather than duplicating it in route setup. |
| 12. Build/version drift | Docker, CMake and health output | Pin the tested SNode.C commit using checkout logic that supports commit hashes. Derive version/revision metadata from the build and use it in health output. Update Compose, environment examples and the guide together. Do not claim this alone makes distribution packages or base-image tags immutable. |

## Reuse and deletion before additions

Reuse SQLite prepared statements, transactions and foreign keys; the existing
session and grant model; SNode.C's HTTP/TLS client; OpenSSL; nlohmann JSON; and
the shared URL encoder. Consolidate browser and API authentication policy.

Delete the browser token-exchange page, duplicate cookie/JSON parsing, synthetic
provider callbacks, raw credential logging, false bootstrap mechanism, broad
redirect exceptions and plaintext fallback. No old/new authentication paths will
operate side by side after the change. Public constructor/configuration changes
must be reflected in the guide's complete client example and package consumers.

## Why reduction alone is insufficient

Deletion can remove disclosures, false claims and permissive fallbacks. It cannot
create the missing transaction ownership, a server-side code exchange, or an
online revocation check while preserving functioning login and federation.
The current client has no HTTP exchange implementation, and current grants lack
a live-session relationship. Adding checks only to the final application would
leave the IDP authority defective.

Initial size estimate: approximately 1,000–1,600 production lines introduced or
replaced, offset by removal/consolidation of approximately 500–900 existing lines;
expected net growth approximately 300–900 production lines. These are planning
estimates, not measured results or a reason to pad/reformat code. Test and guide
changes are accounted separately. Reassess before exceeding 900 net production
lines or introducing another authority. The user-supplied engineering rules
require explicit approval before implementing this growth.

## Contract and migration effects

- Existing clients must adopt the shared hardened client configuration and supply
  registered, exact callback URLs. Old browser-JavaScript exchange is removed.
- Immediate revocation requires an online IDP check for protected requests. It
  adds latency and makes IDP availability part of authorization. Already-running
  third-party offline verifiers cannot be retroactively made revocation-aware;
  deployments must update them. In-flight requests already authorized before
  revocation are outside a next-request revocation guarantee.
- Upgrade requires reauthentication for legacy tokens/sessions that cannot prove
  the new bindings. Account data is preserved. Do not execute a migration against
  a user's database during development; test copies/fixtures only.
- Missing mail delivery disables successful reset delivery; it never exposes a
  reset credential. Missing/broken encryption configuration blocks affected
  operations rather than writing plaintext.
- Unsupported Apple/Meta login and nonexistent administrator bootstrap are
  removed honestly, not replaced by new product features.
- Existing email collisions during Google sign-in must fail safely or require
  explicit authenticated linking; never silently merge accounts.

## Required verification

Tests must exercise production policy/state transitions using temporary SQLite
fixtures and mocked outbound responses, without starting IDP/client listeners.
They must cover success and rejection at the route/client boundary, not merely
inspect source strings or repeat implementation logic.

1. Callback: wrong/missing/expired/replayed state, swapped browsers, overlapping
   logins, malformed/error responses, unsafe return paths, and disconnect during
   an asynchronous exchange. Cookies contain no script-readable credentials.
2. IDP transactions: password-only vs completed-MFA state, direct MFA POST,
   wrong user/browser/transaction, expiry, replay, SSO step-up, registration and
   settings enrollment, and provider completion. Pending sessions cannot enter
   account routes. State-changing cookie-authenticated routes enforce CSRF rules.
3. Client binding: unknown client, callback mismatch, rejected local/private-IP
   bypasses, missing or invalid PKCE, altered continuation fields, code replay,
   refresh replay, atomic consumption and database failure behavior.
4. Reset: uniform response with no token/link, missing/failing mail delivery,
   expired/replayed tokens, session/grant revocation after password reset.
5. Tokens: escaped/Unicode values, malformed JSON/types, invalid signature,
   wrong algorithm/issuer/audience/purpose, expired/not-yet-valid claims, nonce
   mismatch, signer/JWKS key agreement, and userinfo identity consistency.
6. Revocation: logout, password reset/change, MFA changes, account deletion,
   refresh-token reuse, IDP unavailability, and legacy token rejection. Verify
   the next authorization decision denies access through both middleware APIs.
7. Federation: disabled/empty configuration, unsupported provider rejection,
   state/nonce mismatch, invalid provider responses, stable subject identity,
   email collision, transport failure and timeout. Never expose raw credentials.
8. Migration/storage: old schemas, old MFA flags, encrypted/plaintext fixtures,
   missing/wrong keys, migration rollback and foreign-key cascades.
9. Build: full and client-only builds with warnings as errors, installed-package
   consumers, guide example, offline encoding regression checks, formatting,
   dependency pin/configuration checks and measured production/test line counts.

Preserve the earlier no-service constraint. Real browser, TLS/network and Google
integration remain unverified until separately authorized and exercised; report
that limitation explicitly. Do not declare all issues fixed based on compilation.

## Implementation and verification record

All twelve corrections above are implemented in the IDP/client 2.0 change. The
shared client/store boundaries replace the earlier paths; no alternate legacy
login, JavaScript exchange, synthetic provider or plaintext fallback remains.
SSO reuses its live browser session rather than leaving earlier application
sessions behind at logout. Session-based enrollment checks that same authority
before consuming its transaction. Stale forms cannot submit into a new flow.

Verified locally with GCC 16.2.0, OpenSSL 3.6.5 and installed SNode.C
`ba57feee0e62e6780abb778fff54a29f443d5439`:

- Full Debug build and client-only Release build, with `-Werror` and the
  repository's warning flags.
- The guide's exact application/CMake example compiled against separate full
  and client-only development installations, with `-Wall -Wextra -Wconversion
  -Werror`; neither executable was started.
- Three CTest tests passed: authentication, encoding and PNG validation. The
  authentication test has independently reported store, token/client,
  reset/migration and Google-identity groups. It exercises the browser middleware
  and callback with a real Express request and an offline response sink, injected
  HTTP results, real cryptographic signatures and ephemeral SQLite fixtures.
- Positive/negative coverage includes primary/browser/form binding, exact
  callbacks and PKCE, code/callback/refresh replay, SSO logout, account-change
  revocation, enrollment transition/rollback, token purpose/types/signature/
  issuer/audience/times, Google signature/claims, malformed/unavailable exchanges,
  nonce mismatch, cookie origin checks, reset failure/expiry/replay/rollback,
  encryption migration rollback and wrong/missing keys, and legacy-session
  invalidation. Encoding checks retain RFC 6238 and independent PNG validation.
- Shell syntax checked for the entrypoint and documented Bash examples. CMake
  formatting and staged whitespace checks passed; changed source ranges were
  formatted. Shared formatting/analysis settings match the local baseline;
  source discovery includes project tests and excludes vendored sources.
- Compose YAML structure and dependency pin were inspected. Docker is unavailable
  in this environment, so Compose interpolation, image construction and startup
  were not executed.

This is offline boundary verification, not execution of every IDP route through
an HTTP server. Live browser/proxy cookie behavior, TLS handshakes/timeouts,
Google account creation/link-collision flows, mail delivery and backup restoration
remain operator integration checks under the existing no-service constraint.
The client policy adds one online request per protected request (previously zero);
no network latency or throughput benchmark was performed.

Line accounting is recorded in the handover: production is `src/`, regression
code is `tests/`, and build/configuration/documentation are counted separately.
Temporary builds and isolated development installs are retained under
`/tmp/codex/build/snodec-idp/hardening/` for reproducibility; they can be removed
when review is complete. No user database, system installation, remote branch,
PR, running service or deployment was modified.

## Subsequent authorized local integration

The user subsequently authorized online tests on the local machine. The opt-in
`tests/live.py` and `tests/live_tls.py` exercise real loopback IDP/client processes,
Chromium, TLS reverse proxies and the native transport. The guide records commands,
coverage and the four narrow fixes found at runtime. Disposable accounts, keys,
mail capture and databases remain isolated under the permitted temporary build
root. SQLite backup/restore is verified by starting a restored IDP and signing in
with the restored password and encrypted TOTP record. All test services are
stopped afterward. Google, external SMTP and Docker remain unavailable and are
not represented as passing tests. Earlier offline-only limitations above describe
the initial checkpoint; the guide's live-test section is the current evidence.
