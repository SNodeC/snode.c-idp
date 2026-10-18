# Development conventions

## Dependencies and logging

Consume installed SNode.C through `find_package(snodec REQUIRED COMPONENTS
http-server-express-legacy-in http-client net-in-stream-tls)`. The server component loads the transport, Express,
core, utilities, and logger targets transitively. `logger` is not a standalone
public discovery component. The exported `snodec-auth` package must follow the
same discovery contract.

Use the public `Log.h` API and `snode::log::application()` for application
diagnostics. Do not reintroduce Easylogging++ macros or compatibility wrappers.

## Formatting and analysis

The root formatting/analysis configurations and `cmake/` formatting modules
come from the shared canonical baseline. Preserve their style settings.
Module discovery includes `examples/` and `tests/` as well as `src/`, and excludes `src/supplement/`, build directories, and
checkouts from C++ formatting so vendored code is not rewritten.

`cmake --build <build-dir> --target format` explicitly formats project C++ and
CMake files; ordinary compilation never formats sources. For narrow changes,
format only affected ranges with the root `.clang-format`, and use
`cmake-format --check CMakeLists.txt` to check the build definition. Avoid
unrelated whole-file formatting. Enable `CMAKE_EXPORT_COMPILE_COMMANDS` for
clangd/clang-tidy; pass the build directory to these tools. Run clang-tidy only
on owned translation units, not vendored QR sources.

## Workspace layout and validation

Use repository-local `build/codex/<configuration>` for persistent builds and
`checkouts/<task>` for explicitly approved additional checkouts. Both parent
directories are ignored. Temporary builds and compiler scratch files belong
under `/tmp/codex/build/snodec-idp/<task>`.

Validate both the full IDP build and `AUTH_CLIENT_ONLY=ON`. Also compile an
external consumer against the installed client package: the redirect middleware
and callback handler are header-only and are not compiled by the static library
alone. Do not start IDP or client listeners merely to check compilation.

Run the offline encoding checks documented in `docs/idp-and-client-guide.md`
when changing TOTP or QR serialization. They use OpenSSL 3 and Python 3 and
start no services. The vendored Nayuki encoder carries one local byte-cast fix
in its bit-packing loop; preserve it when updating the vendor source.

## Authentication invariants

The hardened schema is owned by `SqliteDatabase::initSchema`; authentication state
transitions are owned by `AuthStore`. Do not add route-local schema changes or
revocation caches. Browser transaction references are not primary authentication.
Both client adapters must use the shared `OAuthClient` policy (MFA plus a live
session check). Never restore the browser JavaScript token exchange or parse JWT
JSON by substring. Use the one outbound HTTP implementation with verified TLS.

Run the offline CTest suite, full/client-only warning-as-error builds and both
installed consumers when modifying authentication. Tests use ephemeral SQLite
fixtures, generated keys and injected HTTP responses; never start listeners as a
side effect. Update the guide, example, environment and Compose configuration in
the same API/configuration change. The plan in `docs/authentication-hardening-plan.md`
records the user's approved scope and growth boundary.

## IDP embedding

`IdpMiddleware` owns all IDP routes and per-instance state. Keep environment
parsing, listener setup and event-loop startup in the standalone host. Pass all
operator configuration through `IdpConfig`; never restore process-global IDP
state or captures of constructor-local references. Mounted handlers and pending
asynchronous callbacks must retain the instance without a router/state cycle.
The standalone host owns VHost selection and `HOST_REDIRECTS`; keep both out of
`IdpMiddleware`. Use the SNode.C VHost implementation and the shared endpoint
validator. Host-routing changes require explicit `tests/live_vhost.py` checks;
Docker and Compose must share the hostname-aware `scripts/healthcheck.sh` probe.
Full installations export `snodec-auth::auth-idp`; client-only installations must
remain independent of it. When changing this boundary, compile the installed
`tests/live_idp.cpp` consumer and explicitly run `tests/live_idp.py` on disposable
loopback fixtures to verify configuration isolation and mounted lifetime.

## Explicit live integration

When the user authorizes runtime tests, build the installed-package consumers in
`tests/live/` and invoke `tests/live.py` (HTTP and `--https`) plus
`tests/live_tls.py` explicitly as documented in the guide. These are never normal
build/CTest side effects. Use fresh disposable work directories under the task's
temporary build root and loopback listeners. Keep real provider/mail credentials
out of fixtures. Report unavailable Google/SMTP/Docker checks separately from
local browser, mail-sink and TLS results, and verify no test listener remains.

## Packaging and deployment

CPack maps the existing install components to server, client-dev, server-dev and optional example packages. Package installation never activates services. `scripts/deploy.py` is the explicit systemd/TLS deployment boundary; configuration is an operator-owned JSON file and generated environment files are not another authority. Run `python3 tests/deployment.py` for disposable configuration/key/rollback checks. Never dispatch package workflows or create release tags merely to validate a packaging change.

The shell bootstrap delegates interactive configuration and provisioning to this same helper. Keep deployment.json as the sole operator input: saved values become editable defaults, secrets stay hidden, and absent JSON supplies no deployment defaults. Certificate tooling follows the chosen TLS owner. Deployment tests must use disposable files and mocked system changes; never contact ACME, Google or real SMTP as a test side effect.

The bootstrap downloads deploy.py by its pinned Git blob ID. Whenever that helper changes, update helper_blob in the shell script with `git hash-object scripts/deploy.py`; deployment tests verify the pin. Users download and execute only the shell script.
