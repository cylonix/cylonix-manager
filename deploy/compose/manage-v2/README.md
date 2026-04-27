# manage-v2.cylonix.io — docker compose deploy

Single-host docker compose deploy that mirrors the k8s-deploy ConfigMap +
secrets layout, intended for testing the v0.28 headscale + v1.96.4 tailscale
merge against a clone of production data before cutting the real cluster.

## How this differs from `../docker-compose.yaml`

| | test stack (`../`) | manage-v2 (this dir) |
|---|---|---|
| Project name | `cylonix-manager-test` | `cylonix-manage-v2` |
| Service hostnames | bare (`postgres`, `redis`, `etcd`) | `<svc>-service.database` (matches k8s) |
| Postgres host port | 5432 | 5433 |
| Redis host port | 6379 | 6380 |
| Etcd host port | 2379 | 2380 |
| Manager API port | 8080 | 8081 |
| Headscale gRPC | 8000 | 8001 |
| Websocket | 8070 | 8071 |
| Config rendered from | inline env block | `.env.local` file |
| Postgres init | shared `postgres-init.sh` | shared `postgres-init.sh` |
| Initial data | empty | restored from `backup.sh` bundle |
| Secrets | none | bind-mounted from `${SECRETS_HOST_DIR:-/root/secrets}` |

Both stacks can run side-by-side on the same host since all ports differ.

## Env mapping (k8s → compose)

The k8s ConfigMap at `k8s-deploy/templates/k8s/manager/config.yml` and the
sysadmin/OAuth/email values are passed through as env vars in this compose
stack. The container's `/opt/entrypoint.sh` runs envsubst over
`/opt/templates/{config,headscale_config}.yaml`, so the rendered files at
`/etc/cylonix/*.yaml` come out identical to the k8s deploy.

The trick that makes `${POSTGRES_SERVICE_NAME}.${DATABASE_NAMESPACE}` (e.g.
`postgres-service.database`) resolve under compose: each backing service has
a network alias of that exact form. So:

- in k8s: `postgres-service.database` resolves via kube-dns → service in the
  `database` namespace
- here: `postgres-service.database` resolves via docker's embedded DNS →
  the `postgres` compose service (alias)

This means you can use the same prod env values without rewriting the
template.

## Setup

Secrets live as files under `${SECRETS_HOST_DIR:-/root/secrets}` on the
host. The expected layout is:

```
/root/secrets/
├── admin/
│   └── password               # CYLONIX_ADMIN_PASSWORD
├── apple/
│   └── private-key.p8         # Apple Sign In key (path goes into config as-is)
├── database/
│   └── pg-password            # PG_PASSWORD (POSTGRES_PASSWORD)
└── google/
    ├── client-secret          # GOOGLE_LOGIN_CLIENT_SECRET
    └── service-account.json   # SEND_EMAIL_SERVICE_ACCOUNT_FILE (path)
```

All files should be `mode 400` and owned by `root` (or whatever uid runs
docker on the host). The compose stack bind-mounts this directory to
`/etc/secrets:ro` inside the postgres + manager containers.

```sh
cd deploy/compose/manage-v2

# 1. Copy and fill in the local env file (no secrets in here anymore — only
#    paths to secret files inside the container).
cp .env.local.example .env.local
$EDITOR .env.local

# 2. Build the manager image LOCALLY for linux/amd64 and save it to a tar.
#    (Build on the dev box; servers don't have the source tree.)
../build.sh --platform=linux/amd64 --save=$HOME/src-ext/sase.tar

# 3. Ship the image to the server and load it.
scp $HOME/src-ext/sase.tar root@manage-v2.cylonix.io:/tmp/
ssh root@manage-v2.cylonix.io 'docker load -i /tmp/sase.tar && rm /tmp/sase.tar'

# 4. On the server, in this directory: bring up the data services and let
#    postgres init the 3 DBs.
#    --env-file is required because compose's default is .env, not .env.local.
docker compose --env-file .env.local up -d postgres redis etcd

# 5. Restore production data into the stack
../../scripts/restore-into-manage-v2.sh /path/to/backups/cylonix-<timestamp>

# 6. Bring up the manager.
docker compose --env-file .env.local up -d cylonix-manager
docker compose --env-file .env.local logs -f cylonix-manager
```

The container entrypoint loads each `*_FILE` env var: it reads the file at
that path and exports the same name without the suffix (e.g.
`PG_PASSWORD_FILE=/etc/secrets/database/pg-password` → `PG_PASSWORD=<contents>`)
before envsubst runs over the config templates. This is the standard
Docker-secrets pattern — same as `POSTGRES_PASSWORD_FILE` in the postgres
image.

## Verify the restore landed

```sh
# Should match production's row counts
docker compose exec postgres \
    psql -U cylonix cylonix_manager -c "
        SELECT 'users' AS t, count(*) FROM users
        UNION ALL SELECT 'nodes', count(*) FROM nodes
        UNION ALL SELECT 'pre_auth_keys', count(*) FROM pre_auth_keys;"

# Confirm migrations ran (all rows should have run_on set)
docker compose exec postgres \
    psql -U cylonix cylonix_manager -c "
        SELECT id FROM migrations ORDER BY id DESC LIMIT 10;"

# Confirm the legacy table was migrated to the new tags column.
# After migrations, pre_auth_key_acl_tags should be GONE and the
# pre_auth_keys.tags JSON column should contain the data.
docker compose exec postgres \
    psql -U cylonix cylonix_manager -c "
        SELECT count(*) FILTER (WHERE tags IS NOT NULL AND tags <> '[]')
        FROM pre_auth_keys;"
```

## Public TLS (manage-v2.cylonix.io)

The host has nginx in front of the docker stack with a Let's Encrypt cert.
Vhost lives at `/etc/nginx/sites-available/manage-v2.cylonix.io` (template
checked in at `nginx-manage-v2.conf` next to the compose file). Routing:

| Path prefix | Backend | Container port |
|---|---|---|
| `/manager/v2/...` | cylonix-manager API | 8080 |
| `/ws/...`         | websocket logs       | 8070 |
| everything else (`/ts2021`, `/key`, `/machine/*`, `/derp*`, `/register/*`, `/oidc/callback`, `/health`, `/version`, ...) | headscale | 8000 |

To re-issue or renew the cert:

```sh
ssh root@manage-v2.cylonix.io \
    'certbot --nginx -d manage-v2.cylonix.io --redirect'
```

Sanity-check the public stack:

```sh
curl https://manage-v2.cylonix.io/health      # → {"status":"pass"}
curl https://manage-v2.cylonix.io/version     # → cylonix-manager build info
curl 'https://manage-v2.cylonix.io/key?v=88'  # → headscale noise pubkey
```

## Real-device test plan (against this stack)

Per `~/.claude/CLAUDE.md`'s L2 relay rig:

| Device | Address |
|---|---|
| HP printer (discovery target) | 10.0.0.33 |
| Linux relay | 10.0.0.27 |
| Android relay | 192.168.8.180 |
| Android client | 192.168.8.219 |

Point each device's `server_url` at this host's port `8001` (or set up a
LAN DNS record for `manage-v2.cylonix.io`). For Apple Sign-In to work over
the LAN, you'll need either a publicly trusted cert or a custom client that
accepts your dev CA — easiest is to terminate TLS at a fronting traefik with
Let's Encrypt and proxy `8081`/`8001`/`8071` upstream.

### What to check post-restore

1. Existing pre-auth keys (no `hskey-auth-` prefix) still register nodes →
   confirms bcrypt-fallback didn't regress.
2. Existing nodes show all their pre-merge tags after registration →
   confirms `pre_auth_key_acl_tags` → `pre_auth_keys.tags` migration worked.
3. `routes_archive` table exists (cylonix shadow-keep) and contains the
   pre-merge `routes` rows.
4. The HP printer is discoverable from the Android client over the L2
   relay (this is the "live regression test" for the merged tailscale fork).

## Tear down

```sh
docker compose down        # keeps volumes (data preserved)
docker compose down -v     # wipes volumes (start fresh on next up)
```
