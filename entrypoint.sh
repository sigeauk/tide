#!/bin/sh
# TIDE Container Entrypoint
# ---------------------------------------------------------
# 1. Install any CA certificates mounted into the standard
#    Debian location /usr/local/share/ca-certificates/
# 2. Hand off to the CMD (uvicorn by default)
# ---------------------------------------------------------

# If any custom CA certs were mounted, install them into the
# system trust store so Python, curl, and everything else trusts them.
if ls /usr/local/share/ca-certificates/*.crt >/dev/null 2>&1; then
    echo "🔒 Installing custom CA certificates..."
    update-ca-certificates --fresh 2>/dev/null
    echo "✅ CA certificates installed"
else
    echo "ℹ️  No custom CA certificates found, using defaults"
fi

# Execute the CMD passed to the container (e.g. uvicorn)
exec "$@"
