# Cylonix-manager test deploy (docker compose)

Minimal docker-based stack for verifying the v0.28 headscale + v1.96.4 tailscale
merge against real devices before touching the manage-v2 cluster. Mirrors what
[k8s-deploy](https://github.com/cylonix/k8s-deploy) provides at production
scale (postgres + redis + etcd + cylonix-manager).

## Prerequisites

- Docker (with buildx) and `docker compose` v2.16+ (for `--build-context`).
- The cylonix tailscale fork checked out at `/Volumes/2TB-1/src/cylonix/tailscale`
  on the `cylonix-v1.96.4` branch (or set `CYLONIX_TAILSCALE_DIR` to wherever
  you have it).

## Quick start

```sh
# 1. Build the image (uses local tailscale fork via docker buildx context)
./build.sh

# 2. Start the stack
docker compose up -d

# 3. Tail manager logs
docker compose logs -f cylonix-manager

# 4. Tear down (data preserved in named volumes)
docker compose down

# 5. Tear down + wipe data (start fresh)
docker compose down -v
```

Exposed ports (loopback only by default):
- `8000` — headscale vpn (gRPC + noise)
- `8080` — cylonix-manager API
- `8070` — websocket
- `5432` — postgres (test convenience)
- `6379` — redis (test convenience)
- `2379` — etcd (test convenience)

## Real-device test plan

The L2 relay rig (per CLAUDE.md memory):

| Device | Role | Address | Access |
|---|---|---|---|
| HP printer | Discovery target | 10.0.0.33 | — |
| Linux relay | Relay node | 10.0.0.27 | `ssh randy@10.0.0.27` |
| Android relay | Relay node | 192.168.8.180 | adb (USB) |
| Android device | Client | 192.168.8.219 | adb (USB) |

Point each device's headscale `server_url` at this stack's `8000`. Note the
container's `HEADSCALE_BASE_DOMAIN=local.cylonix.io` — the test devices will
either need DNS for that name pointing at this host, or you'll need to override
`server_url` on the client side directly.

## DB backup / rollback

The migration delta against the cylonix pre-merge schema is:
- `users` ← +5 columns (display_name, email, provider_identifier, provider, profile_pic_url) + 3 indexes
- `pre_auth_keys` ← +3 columns (prefix, hash, tags) + 1 index. The
  `pre_auth_key_acl_tags` table data is **migrated into `pre_auth_keys.tags`
  JSON** by migration `202510311550-cylonix-preserve-preauth-acl-tags`, then
  the legacy table is dropped.
- `nodes` ← +1 column (approved_routes), `forced_tags` renamed to `tags`
  (data preserved by gormigrate), `nodes_network_domain_given_name` index
  becomes partial (`WHERE given_name != ''`).
- `routes` table → renamed to `routes_archive` (cylonix shadow-keep).
- New tables (`capabilities`, `node_capabilities_relation`,
  `node_would_share_to_users_relation`, `node_accepted_share_to_users_relation`)
  already exist in cylonix pre-merge — no change.

### Pre-migration backup (production)

```sh
# Logical backup, custom format (compresses + supports parallel restore).
pg_dump --format=custom --file=cylonix-prod-pre-v028.dump \
        --host=PROD_HOST --user=cylonix cylonix_manager

# Verify it's restorable on a throwaway target before doing anything else.
createdb cylonix-restore-test
pg_restore --dbname=cylonix-restore-test cylonix-prod-pre-v028.dump
psql cylonix-restore-test -c "SELECT count(*) FROM users; SELECT count(*) FROM nodes; SELECT count(*) FROM pre_auth_keys;"
dropdb cylonix-restore-test

# Stash somewhere durable.
aws s3 cp cylonix-prod-pre-v028.dump s3://cylonix-backups/migration-$(date +%Y%m%d)/
```

### Test the migration on a clone first

```sh
# Clone production to a v2 database and let the new manager migrate it.
createdb cylonix-v2 --template=cylonix_manager   # only works if no clients connected
# Or: pg_dump cylonix_manager | psql cylonix-v2

# Point manage-v2.cylonix.io's POSTGRES_URL at cylonix-v2.
# Production cylonix-manager keeps running against cylonix_manager untouched.

# Real-device test against manage-v2.
# Verify legacy preauth keys (no `hskey-auth-` prefix) still register nodes —
# this confirms the bcrypt-fallback path didn't regress.
# Verify nodes show all their pre-merge tags after registration —
# this confirms the pre_auth_key_acl_tags → pre_auth_keys.tags migration worked.
```

### Cutover

```sh
# After v2 is verified:
# 1. Stop production cylonix-manager.
# 2. Start the new cylonix-manager pointed at cylonix_manager (the production
#    DB). Migrations are idempotent — gormigrate's `migrations` table
#    tracks which ones have run. The forced_tags→tags rename is safe; the
#    pre_auth_key_acl_tags preservation runs before the drop.
# 3. Cut DNS for manage.cylonix.io to the new manager.
# 4. cylonix-v2 (the clone) can be dropped at this point.
```

### Rollback (if something goes wrong post-cutover)

```sh
# Stop new manager first.
docker compose down  # or kubectl scale deployment cylonix-manager --replicas=0

# Restore from the pg_dump.
pg_restore --clean --create --dbname=postgres cylonix-prod-pre-v028.dump

# Bring up the old manager binary (pre-merge image).
# Any data written between cutover and rollback is LOST. The shadow-kept
# `routes_archive` table can be cross-checked against post-rollback state to
# detect divergence.
```

## Inspecting the stack

```sh
# Connect to postgres
docker compose exec postgres psql -U cylonix cylonix_manager

# Show migrations that have run
docker compose exec postgres psql -U cylonix cylonix_manager \
    -c "SELECT * FROM migrations ORDER BY id;"

# Snapshot the live DB (test convenience, not for prod)
docker compose exec -T postgres pg_dump -U cylonix cylonix_manager > snapshot.sql

# Restore a snapshot (will fail if data exists; clean first)
docker compose exec -T postgres psql -U cylonix cylonix_manager < snapshot.sql

# Watch route table fate (should remain `routes_archive` after migration)
docker compose exec postgres psql -U cylonix cylonix_manager \
    -c "SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE 'route%';"
```
