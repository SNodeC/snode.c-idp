#!/bin/sh
# Connect locally while preserving the public origin, TLS verification and VHost.
set -eu
origin="${IDP_BASE_URL:-http://localhost:8083}"
authority="${origin#*://}"
authority="${authority%%/*}"
host="${authority%%:*}"
exec curl --fail --silent --show-error --connect-to "$host::127.0.0.1:${IDP_PORT:-}" "$origin/health"
