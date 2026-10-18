#!/bin/sh
# Probe the private listener using the configured public VHost authority.
set -eu
origin="${IDP_BASE_URL:-http://localhost:8083}"
authority="${origin#*://}"
authority="${authority%%/*}"
exec curl --fail --silent --show-error --header "Host: $authority" \
    "http://127.0.0.1:${IDP_PORT:-8083}/health"
