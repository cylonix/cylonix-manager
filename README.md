# Cylonix Manager

Cylonix Manager is the centralized management and intelligence hub of the Cylonix system. While it does not handle user data traffic, it serves as the critical orchestration, policy, and monitoring center.

## Core Components

### Headscale Service

A forked version of the open-source Tailscale coordination server, enhanced to support:

- Multi-tenant environments
- Multiple mesh networks within a tenant
- Node registration and management
- Public key exchange between peers
- Network map generation for all agents

### User & Device & Access Management

Manages core security components including:

- Identity management (users, groups, service accounts)
- Device registration and management
- Access control policies
- Integration with Headscale for policy enforcement

## Getting Started

### Prerequisites

- Go 1.19 or later
- Git
- Docker (for container builds)
- oapi-codegen (for server API generation)

    ```bash
    go install github.com/cylonix/oapi-codegen/v2/cmd/oapi-codegen@latest
    oapi-codegen --version
    ```

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/cylonix/cylonix-manager.git
    cd cylonix-manager
    ```

2. Initialize submodules and generate API code:

    ```bash
    make init
    make generate
    ```

3. Build the project:

    ```bash
    make build
    ```

## Development Commands

### Building

- `make build` - Build the manager binary
- `make clean` - Remove built artifacts

### API Generation

- `make generate` - Generate all API code
- `make manager-api` - Generate manager API server code
- `make wg-api` - Generate Wireguard agent API client
- `make supervisor-api` - Generate supervisor API client
- `make ipdrawer-api` - Generate IP drawer API client
- `make fw-api` - Generate firewall API client

### Testing

```bash
make test
```

Runs unit tests with coverage for all packages

### Docker Build

```bash
make docker
```

Builds Alpine-based Docker images with tags:

- `cylonix/cylonix-manager:alpine-{VERSION}`
- `cylonix/cylonix-manager:alpine-{RELEASE}`
- `cylonix/cylonix-manager:alpine-latest`

## Version Information

The build system automatically includes:

- Git commit hash
- Version tag (if available)
- Release version (defaults to v1.0)

## License

[BSD 3-Clause License](./LICENSE)

Copyright (c) 2025 EZBLOCK INC. & AUTHORS.
