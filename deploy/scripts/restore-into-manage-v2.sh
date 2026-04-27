#!/usr/bin/env bash
# restore-into-manage-v2.sh — pour a backup bundle produced by backup.sh
# (or run-backup-in-tools.sh) into the manage-v2 docker compose stack.
#
# Order matters:
#   1. postgres (3 DBs) — uses pg_restore from the postgres image
#   2. redis           — copies dump.rdb into the redis volume (requires
#                        redis to be stopped to avoid the in-memory DB
#                        clobbering the file at next save)
#   3. etcd            — uses etcdctl snapshot restore; the etcd container
#                        must be stopped and the data dir replaced
#
# After this script runs, bring up cylonix-manager:
#   docker compose -f deploy/compose/manage-v2/docker-compose.yaml \
#                  up -d cylonix-manager
#
# The manager binary will run gormigrate on connect; migrations are
# idempotent. The pre_auth_key_acl_tags → pre_auth_keys.tags preservation
# step (migration 202510311550-cylonix-preserve-preauth-acl-tags) runs
# before the legacy table is dropped.
#
# Usage:
#   restore-into-manage-v2.sh <backup-dir>
#
# where <backup-dir> is the directory produced by backup.sh, e.g.
#   /tmp/cylonix-backup-20260425-120000

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <backup-dir>" >&2
    exit 1
fi

BACKUP_DIR="$(cd "$1" && pwd)"
if [ ! -d "$BACKUP_DIR" ]; then
    echo "error: $BACKUP_DIR is not a directory" >&2
    exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/../compose/manage-v2/docker-compose.yaml"
PROJECT_NAME="cylonix-manage-v2"
NETWORK_NAME="${PROJECT_NAME}_default"

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "error: compose file not found at $COMPOSE_FILE" >&2
    exit 1
fi

# Pick up PG_USERNAME from .env.local and PG_PASSWORD from the file pointed
# to by PG_PASSWORD_FILE, so restore matches the running postgres container.
ENV_FILE="$SCRIPT_DIR/../compose/manage-v2/.env.local"
if [ ! -f "$ENV_FILE" ]; then
    echo "error: $ENV_FILE not found. Copy .env.local.example and fill it in." >&2
    exit 1
fi
set -a
. "$ENV_FILE"
set +a
: "${PG_USERNAME:?PG_USERNAME must be set in .env.local}"

# PG_PASSWORD_FILE is a path INSIDE the container (/etc/secrets/...). Map
# it to the host location via SECRETS_HOST_DIR.
SECRETS_HOST_DIR="${SECRETS_HOST_DIR:-/root/secrets}"
if [ -z "${PG_PASSWORD_FILE:-}" ]; then
    echo "error: PG_PASSWORD_FILE must be set in .env.local" >&2
    exit 1
fi
host_pw_file="${PG_PASSWORD_FILE/#\/etc\/secrets/$SECRETS_HOST_DIR}"
if [ ! -r "$host_pw_file" ]; then
    echo "error: cannot read postgres password file $host_pw_file" >&2
    exit 1
fi
PG_PASSWORD="$(cat "$host_pw_file")"
export PG_PASSWORD

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    echo "error: docker network '$NETWORK_NAME' not found." >&2
    echo "  Bring up the data services first:" >&2
    echo "    docker compose -f $COMPOSE_FILE up -d postgres redis etcd" >&2
    exit 1
fi

echo "==> backup source: $BACKUP_DIR"
echo "==> target stack: $PROJECT_NAME"

# ---------- postgres ----------
echo "==> postgres restore"
for db in cylonix_manager headscale cylonix_supervisor; do
    dump=""
    for candidate in \
        "$BACKUP_DIR/postgres/$db.dump" \
        "$BACKUP_DIR/$db.dump" \
        "$BACKUP_DIR/postgres/$db.sql"; do
        if [ -f "$candidate" ]; then dump="$candidate"; break; fi
    done
    if [ -z "$dump" ]; then
        echo "    • $db: no dump found, skipping"
        continue
    fi
    echo "    • $db <- $dump"

    # Drop+recreate the target DB so pg_restore lands on a clean slate.
    docker compose -f "$COMPOSE_FILE" exec -T -e PGPASSWORD="$PG_PASSWORD" postgres \
        psql -U "$PG_USERNAME" -d postgres -v ON_ERROR_STOP=1 <<EOF
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$db' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS $db;
CREATE DATABASE $db OWNER $PG_USERNAME;
EOF

    case "$dump" in
    *.sql)
        docker compose -f "$COMPOSE_FILE" exec -T -e PGPASSWORD="$PG_PASSWORD" postgres \
            psql -U "$PG_USERNAME" -d "$db" -v ON_ERROR_STOP=1 < "$dump"
        ;;
    *.dump)
        # custom-format pg_dump → pg_restore. --no-owner avoids fights with
        # role names that may differ between prod and v2.
        docker run --rm -i \
            --network "$NETWORK_NAME" \
            -e PGPASSWORD="$PG_PASSWORD" \
            postgres:14.1-alpine \
            pg_restore --no-owner --no-acl --clean --if-exists \
                       --host=postgres-service.database \
                       --username="$PG_USERNAME" \
                       --dbname="$db" \
                       < "$dump"
        ;;
    esac
done

# ---------- redis ----------
echo "==> redis restore"
redis_dump=""
for candidate in \
    "$BACKUP_DIR/redis/dump.rdb" \
    "$BACKUP_DIR/dump.rdb"; do
    if [ -f "$candidate" ]; then redis_dump="$candidate"; break; fi
done
if [ -n "$redis_dump" ]; then
    echo "    • redis <- $redis_dump"
    docker compose -f "$COMPOSE_FILE" stop redis
    # Replace the dump file in the redis-data named volume.
    docker run --rm \
        -v "${PROJECT_NAME}_redis-data:/data" \
        -v "$redis_dump:/restore/dump.rdb:ro" \
        alpine:3.20 \
        sh -c "cp /restore/dump.rdb /data/dump.rdb && chmod 644 /data/dump.rdb"
    docker compose -f "$COMPOSE_FILE" start redis
else
    echo "    • no redis dump found, skipping"
fi

# ---------- etcd ----------
echo "==> etcd restore"
etcd_snap=""
for candidate in \
    "$BACKUP_DIR/etcd/snapshot.db" \
    "$BACKUP_DIR/snapshot.db"; do
    if [ -f "$candidate" ]; then etcd_snap="$candidate"; break; fi
done
if [ -n "$etcd_snap" ]; then
    echo "    • etcd <- $etcd_snap"
    docker compose -f "$COMPOSE_FILE" stop etcd
    # Restore into a scratch dir, then swap into the named volume.
    docker run --rm \
        -e ETCDCTL_API=3 \
        -v "${PROJECT_NAME}_etcd-data:/etcd-data" \
        -v "$etcd_snap:/restore/snapshot.db:ro" \
        --entrypoint /usr/local/bin/etcdctl \
        quay.io/coreos/etcd:v3.5.14 \
        snapshot restore /restore/snapshot.db \
            --name=etcd0 \
            --initial-cluster="etcd0=http://etcd-service.database:2380" \
            --initial-advertise-peer-urls="http://etcd-service.database:2380" \
            --data-dir=/etcd-data/restored
    # Replace the live data dir contents with the restored one.
    docker run --rm \
        -v "${PROJECT_NAME}_etcd-data:/etcd-data" \
        alpine:3.20 \
        sh -c "rm -rf /etcd-data/member && mv /etcd-data/restored/member /etcd-data/member && rm -rf /etcd-data/restored"
    docker compose -f "$COMPOSE_FILE" start etcd
else
    echo "    • no etcd snapshot found, skipping"
fi

echo
echo "==> restore complete. Bring up the manager:"
echo "    docker compose -f $COMPOSE_FILE up -d cylonix-manager"
echo "    docker compose -f $COMPOSE_FILE logs -f cylonix-manager"
