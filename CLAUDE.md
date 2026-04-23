# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cylonix Manager is the control plane for the Cylonix SASE platform. It orchestrates network policy, user/device management, and mesh network coordination. It does not handle user data traffic. The Go module is `cylonix/sase`.

Key integrations: Tailscale coordination (forked headscale), multi-tenant VPN mesh, firewall policy, WireGuard agents.

## Build Commands

```bash
make init          # Initialize git submodules (utils, openapi, headscale)
make generate      # Generate ALL API code (requires oapi-codegen + Docker for client generation)
make build         # Build cylonix-manager binary from manager/main.go
make test          # Run unit tests with coverage (go test ./... -cover -count=1)
make docker        # Build Alpine Docker image (linux/amd64)
make log-collector # Build log collector Docker image
make clean         # Remove built binary
```

Individual API generation targets: `manager-api`, `wg-api`, `supervisor-api`, `ipdrawer-api`, `fw-api`.

**Prerequisites:** Go 1.25.6, `oapi-codegen` (Cylonix fork), Docker (for client code generation via `cylonix/openapi-generator-cli:v7.8.5`).

## Architecture

- **Entry point:** `manager/main.go` -> `manager/cmd/root.go` (Cobra CLI)
- **API layer:** Chi router, OpenAPI 3.0 spec at `submodules/openapi/manager/openapi-3.0.yaml`, generated server code in `api/v2/`
- **Core logic:** `daemon/` - main service with sub-packages for access keys, auth, device mgmt, login (multi-provider OAuth), policy, tenant management, VPN/Tailscale integration, analytics
- **Shared libraries:** `pkg/` - cleanup, defaults, firewall config, distributed locking, logging, metrics, utilities
- **Shared utilities submodule:** `utils/` - token, OAuth, postgres, etcd, redis helpers
- **Generated clients:** `clients/` - auto-generated Go clients for fw, wg, supervisor, ipdrawer APIs
- **Headscale fork:** `submodules/headscale/` - Tailscale coordination server with multi-tenant extensions
- **Background tasks:** `cmd/task/` - task runner with service definitions
- **Log collector:** `cmd/log-collector/` + `log/` - standalone log aggregation service

## Code Generation

`api/v2/` and `clients/*/` are auto-generated -- do not edit these directly. Regenerate with `make generate` after OpenAPI spec changes in `submodules/openapi/`.

The manager API uses `oapi-codegen` (Cylonix fork). Client APIs use `openapi-generator-cli` via Docker (script: `submodules/openapi/scripts/client.sh`).

## Key Infrastructure

- **Database:** PostgreSQL via GORM (`daemon/db/`)
- **Cache:** Redis
- **Coordination:** etcd v3
- **Auth:** OAuth2 (Google, Apple, GitHub, Microsoft, WeChat) + Keycloak (gocloak)
- **Monitoring:** Prometheus metrics + Elasticsearch analytics
- **IPC:** Unix socket at `/run/sase/sase-manager.sock`

## Git Submodules

Three submodules (initialize with `make init`):
- `utils/` - shared Go utilities (cylonix/utils)
- `submodules/openapi/` - OpenAPI specs for all services
- `submodules/headscale/` - forked Tailscale coordination server

## Testing

`make test` runs all tests. Test framework: `testify`. Some tests create temporary `test.db` files (cleaned up by make target). Run a single test with:

```bash
go test ./daemon/... -run TestName -count=1
```
