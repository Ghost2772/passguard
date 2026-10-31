#!/bin/sh
set -eu
mkdir -p /vault/tls /vault/data /vault/audit
cp /run/secrets/vault_tls_cert /vault/tls/server.crt
cp /run/secrets/vault_tls_key /vault/tls/server.key
chown -R vault:vault /vault/tls /vault/data /vault/audit
chmod 0700 /vault/tls /vault/data /vault/audit
chmod 0600 /vault/tls/server.key
# The official entrypoint already adds -config=/vault/config. Supplying the
# same file again would load the listener and storage configuration twice.
exec docker-entrypoint.sh server
