#!/bin/sh
set -eu

: "${REDEEM_POSTGRES_USER:?REDEEM_POSTGRES_USER is required}"
: "${REDEEM_POSTGRES_PASSWORD:?REDEEM_POSTGRES_PASSWORD is required}"
: "${REDEEM_POSTGRES_DB:?REDEEM_POSTGRES_DB is required}"

psql \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  --set=redeem_user="$REDEEM_POSTGRES_USER" \
  --set=redeem_password="$REDEEM_POSTGRES_PASSWORD" \
  --set=redeem_db="$REDEEM_POSTGRES_DB" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'redeem_user', :'redeem_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'redeem_user')
\gexec

SELECT format('CREATE DATABASE %I OWNER %I', :'redeem_db', :'redeem_user')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'redeem_db')
\gexec
SQL
