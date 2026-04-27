#!/usr/bin/env bash
# build.sh — wrapper around the parent compose dir's build.sh, retagged for
# manage-v2. We share the same Dockerfile and image; this just makes intent
# explicit when invoked from this subdirectory.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
exec "$SCRIPT_DIR/../build.sh" "$@"
