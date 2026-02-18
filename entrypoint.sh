#!/bin/sh
# TIDE Container Entrypoint
# ---------------------------------------------------------
# 1. Install any CA certificates mounted into the standard
#    Debian location /usr/local/share/ca-certificates/
# 2. Point Python/requests/httpx at the system trust store
# 3. Hand off to the CMD (uvicorn by default)
# ---------------------------------------------------------

SYS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# If any custom CA certs were mounted, install them into the
# system trust store so Python, curl, and everything else trusts them.
if ls /usr/local/share/ca-certificates/*.crt >/dev/null 2>&1; then
    echo "🔒 Installing custom CA certificates..."
    update-ca-certificates --fresh 2>/dev/null
    echo "✅ CA certificates installed"
else
    echo "ℹ️  No custom CA certificates found, using defaults"
fi

# Point Python's requests / httpx / urllib at the system CA bundle.
# This overrides any stale REQUESTS_CA_BUNDLE value (e.g. /app/certs/ca-bundle.crt)
# that may linger in an old .env file.
export REQUESTS_CA_BUNDLE="$SYS_CA_BUNDLE"
export SSL_CERT_FILE="$SYS_CA_BUNDLE"
export CURL_CA_BUNDLE="$SYS_CA_BUNDLE"

# Execute the CMD passed to the container (e.g. uvicorn)
exec "$@"
