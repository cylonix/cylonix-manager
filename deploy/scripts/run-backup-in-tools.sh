#!/usr/bin/env bash
# run-backup-in-tools.sh — convenience wrapper to run backup.sh in --direct
# mode by spinning up tool containers (one per backend) on the same docker
# network as the cylonix-manager test deploy. Useful when your dev machine
# doesn't have pg_dump / etcdctl / redis-cli installed.
#
# Each backup step runs in a one-shot container with the right CLI for that
# backend, writing artifacts into a shared output directory.
#
# Usage:
#   cd deploy/compose && docker compose up -d   # bring up the stack
#   ../scripts/run-backup-in-tools.sh           # back up to deploy/compose/backups/
#
# Output: deploy/compose/backups/cylonix-<timestamp>/

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
COMPOSE_DIR="$(cd "$SCRIPT_DIR/../compose" && pwd)"
NETWORK_NAME="cylonix-manager-test_default"

if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
    echo "error: docker network '$NETWORK_NAME' not found." >&2
    echo "  Bring up the stack first: cd $COMPOSE_DIR && docker compose up -d" >&2
    exit 1
fi

STAMP=$(date +%Y%m%d-%H%M%S)
OUT_DIR_HOST="$COMPOSE_DIR/backups/cylonix-$STAMP"
mkdir -p "$OUT_DIR_HOST/postgres" "$OUT_DIR_HOST/etcd" "$OUT_DIR_HOST/redis"

echo "==> output: $OUT_DIR_HOST"

# postgres — uses pg_dump from the official postgres image.
echo "==> postgres dump"
for db in cylonix_manager headscale cylonix_supervisor; do
    echo "    • $db"
    docker run --rm \
        --network "$NETWORK_NAME" \
        -e PGPASSWORD=cylonix \
        -v "$OUT_DIR_HOST/postgres:/out" \
        postgres:14.1-alpine \
        pg_dump --format=custom --no-owner --no-acl \
                --host=postgres --username=cylonix \
                --file=/out/"$db".dump "$db"
done

# redis — uses redis-cli's --rdb mode for a remote dump.
echo "==> redis dump"
docker run --rm \
    --network "$NETWORK_NAME" \
    -v "$OUT_DIR_HOST/redis:/out" \
    redis:7-alpine \
    redis-cli -h redis --rdb /out/dump.rdb

# etcd — etcdctl is the entrypoint-friendly binary on the etcd image.
# (the image is distroless-ish and has no /bin/sh; invoke etcdctl directly.)
echo "==> etcd snapshot"
docker run --rm \
    --network "$NETWORK_NAME" \
    -e ETCDCTL_API=3 \
    -v "$OUT_DIR_HOST/etcd:/out" \
    --entrypoint /usr/local/bin/etcdctl \
    quay.io/coreos/etcd:v3.5.14 \
    --endpoints=http://etcd:2379 snapshot save /out/snapshot.db

# Generate manifest using whatever shell tools are on the host.
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
    else echo "no-sha256-tool"; fi
}
size_of() {
    stat -f%z "$1" 2>/dev/null || stat -c%s "$1"
}

{
    echo '{'
    echo '  "deployment": "cylonix-manager",'
    echo "  \"started_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo '  "mode": "direct-via-tools-containers",'
    echo "  \"host\": \"$(hostname)\","
    echo '  "artifacts": ['
    first=true
    for f in "$OUT_DIR_HOST"/postgres/*.dump \
             "$OUT_DIR_HOST"/redis/dump.rdb \
             "$OUT_DIR_HOST"/etcd/snapshot.db; do
        [ -f "$f" ] || continue
        $first || echo ','
        first=false
        section=$(basename "$(dirname "$f")")
        printf '    {"section":"%s","artifact":"%s","path":"%s","size_bytes":%s,"sha256":"%s"}' \
            "$section" "$(basename "$f" | sed 's/\.[^.]*$//')" \
            "$section/$(basename "$f")" "$(size_of "$f")" "$(sha256_of "$f")"
    done
    echo
    echo '  ],'
    echo "  \"finished_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\""
    echo '}'
} > "$OUT_DIR_HOST/manifest.json"

echo
echo "==> done. manifest:"
cat "$OUT_DIR_HOST/manifest.json"
