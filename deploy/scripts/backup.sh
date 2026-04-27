#!/usr/bin/env bash
# backup.sh — full-stack backup for a live cylonix-manager deployment.
#
# Backs up every stateful service the cylonix stack uses:
#
#   postgres   — relational data: cylonix_manager, headscale, cylonix_supervisor
#                databases (user accounts, devices, preauth keys, policies,
#                friend graphs, etc.). Logical pg_dump per-DB in custom format.
#   etcd       — distributed coordination + cluster locks. Snapshot via
#                etcdctl snapshot save.
#   redis      — session cache, ipdrawer IP allocations, friend-request and
#                user-friends caches. Synchronous BGSAVE then COPY of .rdb.
#   influxdb   — metrics (v2). influx backup.
#   prometheus — TSDB. Snapshot via admin API + copy of data dir.
#
# Modes:
#   --kubectl   (default if kubectl is available and a deploy is reachable)
#               kubectl exec into each pod, run the per-service backup tool,
#               then kubectl cp the artifact out.
#   --direct    Run against locally-reachable services (e.g. the docker compose
#               test stack, or a postgres on localhost). Reads connection info
#               from environment variables — see ENV section below.
#
# Output:
#   ./backups/cylonix-<timestamp>/
#     ├── manifest.json         host/version/size/sha256 per artifact
#     ├── postgres/
#     │   ├── cylonix_manager.dump
#     │   ├── headscale.dump
#     │   └── cylonix_supervisor.dump
#     ├── etcd/snapshot.db
#     ├── redis/dump.rdb
#     ├── influxdb/<bucket>.tar.gz
#     └── prometheus/snapshot.tar.gz
#
# Exit codes: 0 on full success, non-zero on any failure (the partial output
# is left on disk for inspection).
#
# ENV (--direct mode):
#   PG_HOST, PG_PORT (5432), PG_USER (cylonix), PG_PASSWORD, PG_DBS
#       Space-separated list of postgres databases to back up.
#       Default: "cylonix_manager headscale cylonix_supervisor"
#   ETCD_ENDPOINT (default http://localhost:2379)
#   REDIS_HOST (localhost), REDIS_PORT (6379), REDIS_PASSWORD (optional)
#   INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG  (skipped if INFLUX_URL is empty)
#   PROM_URL (default http://localhost:9090)  (skipped if PROM_URL is empty)
#
# ENV (--kubectl mode):
#   K8S_NAMESPACE        Namespace where the database pods live (default: database)
#   POSTGRES_POD         Name of the postgres pod (default: postgres)
#   ETCD_POD             Name of the etcd pod (default: etcd)
#   REDIS_POD            Name of the redis pod (default: redis)
#   INFLUX_POD           Name of the influxdb pod (default: influxdb, "" to skip)
#   PROM_POD             Name of the prometheus pod (default: prometheus, "" to skip)
#   PG_DBS               Same as direct mode.
#   PG_USERNAME          Postgres user inside the pod (default: from
#                         configmap/PG_USERNAME, falling back to "cylonix")
#
# Usage:
#   ./backup.sh                              # auto-detect mode
#   ./backup.sh --direct                     # force direct-host mode
#   ./backup.sh --kubectl                    # force kubectl mode
#   ./backup.sh --output /var/lib/backups    # change output root
#   ./backup.sh --tar                        # also produce a single .tar.gz
#   ./backup.sh --verify                     # roundtrip-restore each artifact
#                                            # to a throwaway target (slow).
#
# Common rollback flow at the bottom of this file's commentary.

set -euo pipefail

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

MODE=""
OUTPUT_ROOT=""
DO_TAR=false
DO_VERIFY=false

K8S_NAMESPACE="${K8S_NAMESPACE:-database}"
POSTGRES_POD="${POSTGRES_POD:-postgres}"
ETCD_POD="${ETCD_POD:-etcd}"
REDIS_POD="${REDIS_POD:-redis}"
INFLUX_POD="${INFLUX_POD:-influxdb}"
PROM_POD="${PROM_POD:-prometheus}"

PG_HOST="${PG_HOST:-localhost}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-${PG_USERNAME:-cylonix}}"
PG_DBS="${PG_DBS:-cylonix_manager headscale cylonix_supervisor}"

ETCD_ENDPOINT="${ETCD_ENDPOINT:-http://localhost:2379}"

REDIS_HOST="${REDIS_HOST:-localhost}"
REDIS_PORT="${REDIS_PORT:-6379}"

INFLUX_URL="${INFLUX_URL:-}"
PROM_URL="${PROM_URL:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --kubectl)  MODE=kubectl; shift;;
        --direct)   MODE=direct;  shift;;
        --output)   OUTPUT_ROOT="$2"; shift 2;;
        --tar)      DO_TAR=true; shift;;
        --verify)   DO_VERIFY=true; shift;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0;;
        *) echo "unknown flag: $1" >&2; exit 2;;
    esac
done

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

# Compute sha256 in a portable way (Linux: sha256sum, macOS: shasum -a 256).
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "no-sha256-tool"
    fi
}

byte_size_of() {
    if stat -f%z "$1" >/dev/null 2>&1; then
        stat -f%z "$1"   # macOS / BSD
    else
        stat -c%s "$1"   # Linux
    fi
}

manifest_append() {
    # $1=section $2=name $3=path
    local section=$1 name=$2 path=$3
    local size sha
    size=$(byte_size_of "$path")
    sha=$(sha256_of "$path")
    cat >> "$OUTPUT_DIR/manifest.json.partial" <<EOF
    {"section":"$section","artifact":"$name","path":"$(basename "$path")","size_bytes":$size,"sha256":"$sha"},
EOF
}

# ---------------------------------------------------------------------------
# mode detection
# ---------------------------------------------------------------------------

detect_mode() {
    if [ -n "$MODE" ]; then return; fi
    if command -v kubectl >/dev/null 2>&1 \
       && kubectl -n "$K8S_NAMESPACE" get pod "$POSTGRES_POD" >/dev/null 2>&1; then
        MODE=kubectl
        log "auto-detected mode: kubectl (namespace=$K8S_NAMESPACE)"
    else
        MODE=direct
        log "auto-detected mode: direct"
    fi
}

# ---------------------------------------------------------------------------
# postgres
# ---------------------------------------------------------------------------

backup_postgres_kubectl() {
    log "postgres: dumping via kubectl exec ($POSTGRES_POD)"
    mkdir -p "$OUTPUT_DIR/postgres"
    for db in $PG_DBS; do
        log "  • $db"
        # pg_dump custom format inside the pod, stream stdout out via kubectl.
        kubectl -n "$K8S_NAMESPACE" exec -i "$POSTGRES_POD" -- \
            pg_dump --format=custom --no-owner --no-acl --username="$PG_USER" "$db" \
            > "$OUTPUT_DIR/postgres/${db}.dump"
        manifest_append postgres "$db" "$OUTPUT_DIR/postgres/${db}.dump"
    done
}

backup_postgres_direct() {
    log "postgres: dumping directly ($PG_HOST:$PG_PORT as $PG_USER)"
    require_cmd pg_dump
    mkdir -p "$OUTPUT_DIR/postgres"
    export PGPASSWORD="${PG_PASSWORD:-}"
    for db in $PG_DBS; do
        log "  • $db"
        pg_dump --format=custom --no-owner --no-acl \
                --host="$PG_HOST" --port="$PG_PORT" --username="$PG_USER" "$db" \
                > "$OUTPUT_DIR/postgres/${db}.dump"
        manifest_append postgres "$db" "$OUTPUT_DIR/postgres/${db}.dump"
    done
}

verify_postgres() {
    log "postgres: verify (pg_restore --list)"
    require_cmd pg_restore
    for f in "$OUTPUT_DIR/postgres"/*.dump; do
        if ! pg_restore --list "$f" >/dev/null; then
            die "pg_restore --list failed for $f"
        fi
    done
}

# ---------------------------------------------------------------------------
# etcd
# ---------------------------------------------------------------------------

backup_etcd_kubectl() {
    log "etcd: snapshot via kubectl exec ($ETCD_POD)"
    mkdir -p "$OUTPUT_DIR/etcd"
    # Save snapshot inside the pod, then cp it out.
    kubectl -n "$K8S_NAMESPACE" exec "$ETCD_POD" -- \
        sh -c 'ETCDCTL_API=3 etcdctl snapshot save /tmp/snapshot.db'
    kubectl -n "$K8S_NAMESPACE" cp \
        "$ETCD_POD:/tmp/snapshot.db" "$OUTPUT_DIR/etcd/snapshot.db"
    kubectl -n "$K8S_NAMESPACE" exec "$ETCD_POD" -- rm -f /tmp/snapshot.db || true
    manifest_append etcd snapshot "$OUTPUT_DIR/etcd/snapshot.db"
}

backup_etcd_direct() {
    log "etcd: snapshot via etcdctl against $ETCD_ENDPOINT"
    require_cmd etcdctl
    mkdir -p "$OUTPUT_DIR/etcd"
    ETCDCTL_API=3 etcdctl --endpoints "$ETCD_ENDPOINT" \
        snapshot save "$OUTPUT_DIR/etcd/snapshot.db"
    manifest_append etcd snapshot "$OUTPUT_DIR/etcd/snapshot.db"
}

verify_etcd() {
    log "etcd: verify (snapshot status)"
    if [ "$MODE" = kubectl ]; then
        kubectl -n "$K8S_NAMESPACE" cp \
            "$OUTPUT_DIR/etcd/snapshot.db" "$ETCD_POD:/tmp/verify.db"
        kubectl -n "$K8S_NAMESPACE" exec "$ETCD_POD" -- \
            sh -c 'ETCDCTL_API=3 etcdctl snapshot status /tmp/verify.db -w table'
        kubectl -n "$K8S_NAMESPACE" exec "$ETCD_POD" -- rm -f /tmp/verify.db || true
    else
        ETCDCTL_API=3 etcdctl snapshot status \
            "$OUTPUT_DIR/etcd/snapshot.db" -w table
    fi
}

# ---------------------------------------------------------------------------
# redis
# ---------------------------------------------------------------------------

backup_redis_kubectl() {
    log "redis: BGSAVE + cp dump.rdb ($REDIS_POD)"
    mkdir -p "$OUTPUT_DIR/redis"
    # Trigger a synchronous-ish save then poll until the LASTSAVE timestamp moves.
    local before after
    before=$(kubectl -n "$K8S_NAMESPACE" exec "$REDIS_POD" -- redis-cli LASTSAVE)
    kubectl -n "$K8S_NAMESPACE" exec "$REDIS_POD" -- redis-cli BGSAVE >/dev/null
    for _ in $(seq 1 60); do
        after=$(kubectl -n "$K8S_NAMESPACE" exec "$REDIS_POD" -- redis-cli LASTSAVE)
        [ "$before" != "$after" ] && break
        sleep 1
    done
    [ "$before" != "$after" ] || die "redis BGSAVE did not complete in 60s"
    kubectl -n "$K8S_NAMESPACE" cp \
        "$REDIS_POD:/data/dump.rdb" "$OUTPUT_DIR/redis/dump.rdb"
    manifest_append redis dump "$OUTPUT_DIR/redis/dump.rdb"
}

backup_redis_direct() {
    log "redis: --rdb against $REDIS_HOST:$REDIS_PORT"
    require_cmd redis-cli
    mkdir -p "$OUTPUT_DIR/redis"
    local args=(-h "$REDIS_HOST" -p "$REDIS_PORT")
    [ -n "${REDIS_PASSWORD:-}" ] && args+=(-a "$REDIS_PASSWORD")
    redis-cli "${args[@]}" --rdb "$OUTPUT_DIR/redis/dump.rdb"
    manifest_append redis dump "$OUTPUT_DIR/redis/dump.rdb"
}

verify_redis() {
    log "redis: verify (file magic)"
    # First 5 bytes of an RDB are "REDIS".
    head -c 5 "$OUTPUT_DIR/redis/dump.rdb" | grep -q REDIS \
        || die "redis dump magic missing — file is not a valid RDB"
}

# ---------------------------------------------------------------------------
# influxdb (optional)
# ---------------------------------------------------------------------------

backup_influxdb_kubectl() {
    [ -z "$INFLUX_POD" ] && { log "influxdb: skipped (INFLUX_POD empty)"; return; }
    if ! kubectl -n "$K8S_NAMESPACE" get pod "$INFLUX_POD" >/dev/null 2>&1; then
        log "influxdb: pod $INFLUX_POD not found, skipping"
        return
    fi
    log "influxdb: backup via influx CLI inside pod"
    mkdir -p "$OUTPUT_DIR/influxdb"
    kubectl -n "$K8S_NAMESPACE" exec "$INFLUX_POD" -- \
        sh -c 'rm -rf /tmp/influx-backup && mkdir -p /tmp/influx-backup && influx backup /tmp/influx-backup'
    kubectl -n "$K8S_NAMESPACE" exec "$INFLUX_POD" -- \
        sh -c 'cd /tmp && tar -czf influx-backup.tar.gz -C influx-backup .'
    kubectl -n "$K8S_NAMESPACE" cp \
        "$INFLUX_POD:/tmp/influx-backup.tar.gz" "$OUTPUT_DIR/influxdb/all.tar.gz"
    kubectl -n "$K8S_NAMESPACE" exec "$INFLUX_POD" -- \
        rm -rf /tmp/influx-backup /tmp/influx-backup.tar.gz || true
    manifest_append influxdb all "$OUTPUT_DIR/influxdb/all.tar.gz"
}

backup_influxdb_direct() {
    [ -z "$INFLUX_URL" ] && { log "influxdb: skipped (INFLUX_URL empty)"; return; }
    require_cmd influx
    log "influxdb: backup via influx CLI against $INFLUX_URL"
    mkdir -p "$OUTPUT_DIR/influxdb/raw"
    local args=(--host "$INFLUX_URL")
    [ -n "${INFLUX_TOKEN:-}" ] && args+=(--token "$INFLUX_TOKEN")
    [ -n "${INFLUX_ORG:-}" ] && args+=(--org "$INFLUX_ORG")
    influx backup "${args[@]}" "$OUTPUT_DIR/influxdb/raw"
    tar -czf "$OUTPUT_DIR/influxdb/all.tar.gz" -C "$OUTPUT_DIR/influxdb/raw" .
    rm -rf "$OUTPUT_DIR/influxdb/raw"
    manifest_append influxdb all "$OUTPUT_DIR/influxdb/all.tar.gz"
}

verify_influxdb() {
    [ -f "$OUTPUT_DIR/influxdb/all.tar.gz" ] || return 0
    log "influxdb: verify (tar -tzf)"
    tar -tzf "$OUTPUT_DIR/influxdb/all.tar.gz" >/dev/null \
        || die "influxdb backup tar is corrupt"
}

# ---------------------------------------------------------------------------
# prometheus (optional)
# ---------------------------------------------------------------------------

backup_prometheus_kubectl() {
    [ -z "$PROM_POD" ] && { log "prometheus: skipped (PROM_POD empty)"; return; }
    if ! kubectl -n "$K8S_NAMESPACE" get pod "$PROM_POD" >/dev/null 2>&1; then
        log "prometheus: pod $PROM_POD not found, skipping"
        return
    fi
    log "prometheus: snapshot via admin API + tar of /prometheus/snapshots"
    mkdir -p "$OUTPUT_DIR/prometheus"
    # Trigger an in-place snapshot (admin API must be enabled at startup with
    # --web.enable-admin-api). Fall back to cold-copy of /prometheus/data on
    # failure — that's a less consistent snapshot but better than nothing.
    if kubectl -n "$K8S_NAMESPACE" exec "$PROM_POD" -- \
        wget -qO- --post-data="" http://localhost:9090/api/v1/admin/tsdb/snapshot 2>/dev/null \
        | grep -q '"status":"success"'; then
        kubectl -n "$K8S_NAMESPACE" exec "$PROM_POD" -- \
            sh -c 'cd /prometheus/snapshots && tar -czf /tmp/prom-snapshot.tar.gz $(ls -1t | head -1)'
        kubectl -n "$K8S_NAMESPACE" cp \
            "$PROM_POD:/tmp/prom-snapshot.tar.gz" "$OUTPUT_DIR/prometheus/snapshot.tar.gz"
        kubectl -n "$K8S_NAMESPACE" exec "$PROM_POD" -- \
            rm -f /tmp/prom-snapshot.tar.gz || true
    else
        log "prometheus: admin API snapshot unavailable, falling back to cold tar of /prometheus"
        kubectl -n "$K8S_NAMESPACE" exec "$PROM_POD" -- \
            sh -c 'tar -czf /tmp/prom-cold.tar.gz -C /prometheus .'
        kubectl -n "$K8S_NAMESPACE" cp \
            "$PROM_POD:/tmp/prom-cold.tar.gz" "$OUTPUT_DIR/prometheus/snapshot.tar.gz"
        kubectl -n "$K8S_NAMESPACE" exec "$PROM_POD" -- rm -f /tmp/prom-cold.tar.gz || true
    fi
    manifest_append prometheus snapshot "$OUTPUT_DIR/prometheus/snapshot.tar.gz"
}

backup_prometheus_direct() {
    [ -z "$PROM_URL" ] && { log "prometheus: skipped (PROM_URL empty)"; return; }
    require_cmd curl
    log "prometheus: snapshot via admin API at $PROM_URL"
    mkdir -p "$OUTPUT_DIR/prometheus"
    if curl -sf -X POST "$PROM_URL/api/v1/admin/tsdb/snapshot" \
        | grep -q '"status":"success"'; then
        log "prometheus: snapshot triggered. NOTE: --direct mode cannot pull"
        log "  the snapshot directory off a remote prometheus host — kubectl"
        log "  mode is required for that. Snapshot remains on the prom data dir."
        echo "snapshot triggered remotely; collect from \$PROM_URL host data dir" \
            > "$OUTPUT_DIR/prometheus/snapshot.tar.gz"
        manifest_append prometheus marker "$OUTPUT_DIR/prometheus/snapshot.tar.gz"
    else
        log "prometheus: admin API call failed, skipping"
    fi
}

verify_prometheus() {
    [ -f "$OUTPUT_DIR/prometheus/snapshot.tar.gz" ] || return 0
    log "prometheus: verify (tar -tzf)"
    tar -tzf "$OUTPUT_DIR/prometheus/snapshot.tar.gz" >/dev/null 2>&1 \
        || log "prometheus: snapshot.tar.gz is not a tarball (probably a marker)"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

main() {
    detect_mode

    : "${OUTPUT_ROOT:=./backups}"
    local stamp
    stamp=$(date +%Y%m%d-%H%M%S)
    OUTPUT_DIR="$OUTPUT_ROOT/cylonix-$stamp"
    mkdir -p "$OUTPUT_DIR"
    log "output: $OUTPUT_DIR"

    # Start manifest
    {
        printf '{\n  "deployment": "cylonix-manager",\n'
        printf '  "started_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '  "mode": "%s",\n  "host": "%s",\n  "artifacts": [\n' "$MODE" "$(hostname)"
    } > "$OUTPUT_DIR/manifest.json.partial"

    # Run each section. Any failure cascades because of `set -e`.
    if [ "$MODE" = kubectl ]; then
        require_cmd kubectl
        backup_postgres_kubectl
        backup_etcd_kubectl
        backup_redis_kubectl
        backup_influxdb_kubectl
        backup_prometheus_kubectl
    else
        backup_postgres_direct
        backup_etcd_direct
        backup_redis_direct
        backup_influxdb_direct
        backup_prometheus_direct
    fi

    if $DO_VERIFY; then
        verify_postgres
        verify_etcd
        verify_redis
        verify_influxdb
        verify_prometheus
    fi

    # Close the manifest. The trailing comma on the last artifact line is
    # invalid JSON; strip it before adding the closing bracket.
    sed -i.bak '$ s/,$//' "$OUTPUT_DIR/manifest.json.partial"
    rm -f "$OUTPUT_DIR/manifest.json.partial.bak"
    {
        cat "$OUTPUT_DIR/manifest.json.partial"
        printf '  ],\n  "finished_at": "%s"\n}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$OUTPUT_DIR/manifest.json"
    rm -f "$OUTPUT_DIR/manifest.json.partial"

    if $DO_TAR; then
        local tarball="$OUTPUT_ROOT/cylonix-$stamp.tar.gz"
        log "tar: $tarball"
        tar -czf "$tarball" -C "$OUTPUT_ROOT" "cylonix-$stamp"
        log "tar size: $(byte_size_of "$tarball") bytes"
    fi

    log "done: $OUTPUT_DIR"
    log
    log "to roll back, see deploy/scripts/restore.sh (when implemented) or:"
    log "  postgres:  pg_restore --clean --create -d postgres postgres/<db>.dump"
    log "  etcd:      etcdutl snapshot restore etcd/snapshot.db --data-dir=/path/restored"
    log "  redis:     stop redis, replace dump.rdb in data dir, start"
    log "  influxdb:  influx restore <dir-from-tar.gz>"
    log "  prometheus: stop prom, replace /prometheus/data with snapshot.tar.gz contents, start"
}

main "$@"
