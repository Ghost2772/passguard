#!/bin/sh
set -eu
mkdir -p /var/lib/postgresql/tls
mkdir -p /run/postgres-secrets
cp /run/secrets/postgres_tls_cert /var/lib/postgresql/tls/server.crt
cp /run/secrets/postgres_tls_key /var/lib/postgresql/tls/server.key
cp /run/secrets/postgres_bootstrap_password /run/postgres-secrets/bootstrap_password
chown -R postgres:postgres /var/lib/postgresql/tls
chown -R postgres:postgres /run/postgres-secrets
chmod 0700 /var/lib/postgresql/tls
chmod 0700 /run/postgres-secrets
chmod 0600 /var/lib/postgresql/tls/server.key
chmod 0600 /run/postgres-secrets/bootstrap_password
# File-based Compose secrets keep host ownership on Linux. The official
# entrypoint reads this file again after dropping root privileges.
export POSTGRES_PASSWORD_FILE=/run/postgres-secrets/bootstrap_password
exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file=/var/lib/postgresql/tls/server.crt \
  -c ssl_key_file=/var/lib/postgresql/tls/server.key \
  -c hba_file=/etc/postgresql/pg_hba.conf \
  -c password_encryption=scram-sha-256 \
  -c log_statement=none \
  -c log_min_error_statement=panic
