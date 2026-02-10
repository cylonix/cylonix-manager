# Log collection server for cylonix manager

This server accepts log content and appends it to per-collection files with a simple two-file rotation to keep each log ID at or below 10 MB.

## Endpoint

- **Path:** `POST /log/c/{collection}/{logUUID}?copyTo=<uuid>`
- **Body:** raw log content
- **Headers:** `Content-Encoding: zstd` (optional)

Behavior:

- Logs are stored under `DATA_DIR/<collection>/<logUUID>`.
- When the active file reaches 10 MB, it rotates to `<logUUID>.1` and a new file starts.
- If `copyTo` is set, the same payload is appended to `DATA_DIR/<collection>/<copyTo>` with its own rotation.

## Configuration

Environment variables:

- `PORT` (default `8080`)
- `DATA_DIR` (default `./data`)

## Docker

The Dockerfile and compose file live in `log/`.

Build image:

```bash
docker build -f log/Dockerfile -t cylonix-log-collector:local .
```

Run with compose:

```bash
cd log
docker compose up --build
```

## Traefik rate limiting (overall + per-IP)

Below are example Traefik dynamic config entries that apply **both** a global rate limit and a per-source-IP rate limit. Adjust `average` and `burst` to match your desired throughput.

### File provider example

```yaml
http:
 middlewares:
  log-collector-global-rate:
   rateLimit:
    average: 200
    burst: 100

  log-collector-per-ip-rate:
   rateLimit:
    average: 20
    burst: 40
    sourceCriterion:
     ipStrategy:
      depth: 1

 routers:
  log-collector:
   rule: PathPrefix(`/log`)
   service: log-collector
   middlewares:
    - log-collector-global-rate
    - log-collector-per-ip-rate
```

### Docker labels example

```yaml
services:
 log-collector:
  labels:
   - "traefik.http.routers.log-collector.rule=PathPrefix(`/log`)"
   - "traefik.http.routers.log-collector.middlewares=log-collector-global-rate,log-collector-per-ip-rate"
   - "traefik.http.middlewares.log-collector-global-rate.rateLimit.average=200"
   - "traefik.http.middlewares.log-collector-global-rate.rateLimit.burst=100"
   - "traefik.http.middlewares.log-collector-per-ip-rate.rateLimit.average=20"
   - "traefik.http.middlewares.log-collector-per-ip-rate.rateLimit.burst=40"
   - "traefik.http.middlewares.log-collector-per-ip-rate.rateLimit.sourcecriterion.ipstrategy.depth=1"
```
