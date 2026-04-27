#!/bin/sh
# postgres-init.sh — runs once on a fresh postgres data volume.
#
# Mirrors the k8s-deploy templates/database/postgres/entrypoint.sh: ensures
# the cylonix-manager DB and the headscale DB both exist. cylonix-manager
# bundles headscale as a library and uses one or both depending on config.

set -e

ensure_db() {
    db=$1
    # psql with -U $POSTGRES_USER defaults to a DB matching the username,
    # which doesn't exist here (POSTGRES_DB=cylonix_manager creates that one
    # instead). Connect explicitly to the cylonix_manager DB created by the
    # postgres entrypoint.
    psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tc "SELECT 1 FROM pg_database WHERE datname = '$db'" | grep -q 1 \
        || psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "CREATE DATABASE $db"
}

ensure_db cylonix_manager
ensure_db headscale
ensure_db cylonix_supervisor
