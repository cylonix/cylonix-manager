#!/usr/bin/env bash
# Build the cylonix-manager test image with the locally-checked-out cylonix
# tailscale fork bundled in via a docker buildx additional context.
#
# Why not use the standard docker/Dockerfile.alpine?
# Because that one assumes tailscale.com resolves to a public version
# (github.com/cylonix/tailscale@<tag>). During the v0.28 merge the cylonix
# tailscale fork is still local — branch cylonix-v1.96.4, not pushed yet —
# so we wire it in via a build context instead.
#
# Usage:
#   build.sh                       # build for the host platform, --load
#   build.sh --platform=linux/amd64
#                                  # cross-build for amd64 (Mac → Linux)
#   build.sh --save=/path/to/image.tar
#                                  # additionally docker save the image
#                                  # to that tar file (for scp-and-load)
#   build.sh --platform=linux/amd64 --save=$HOME/cylonix-manager.tar
#                                  # both: cross-build + save

set -euo pipefail

PLATFORM=""
SAVE_PATH=""
for arg in "$@"; do
    case "$arg" in
        --platform=*) PLATFORM="${arg#--platform=}" ;;
        --save=*)     SAVE_PATH="${arg#--save=}" ;;
        *) echo "unknown arg: $arg" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
MANAGER_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TAILSCALE_DIR="${CYLONIX_TAILSCALE_DIR:-/Volumes/2TB-1/src/cylonix/tailscale}"

if [ ! -d "$TAILSCALE_DIR" ]; then
    echo "error: cylonix tailscale source not found at $TAILSCALE_DIR" >&2
    echo "       set CYLONIX_TAILSCALE_DIR=/path/to/cylonix/tailscale and re-run" >&2
    exit 1
fi

VERSION_LONG=$(git -C "$MANAGER_DIR" describe --always --tags --dirty 2>/dev/null || echo dev)
VERSION_SHORT=$(git -C "$MANAGER_DIR" describe --always --tags 2>/dev/null || echo dev)
VERSION_GIT_HASH=$(git -C "$MANAGER_DIR" rev-parse HEAD 2>/dev/null || echo dev)

IMAGE_TAG="cylonix/cylonix-manager:test-merge-v0.28"
echo "==> Building $IMAGE_TAG"
echo "    manager-src:   $MANAGER_DIR"
echo "    tailscale-src: $TAILSCALE_DIR"
echo "    version:       $VERSION_LONG"
echo "    platform:      ${PLATFORM:-host}"
echo

build_args=(
    --tag "$IMAGE_TAG"
    --build-arg VERSION_LONG="$VERSION_LONG"
    --build-arg VERSION_SHORT="$VERSION_SHORT"
    --build-arg VERSION_GIT_HASH="$VERSION_GIT_HASH"
    --build-context tailscale-src="$TAILSCALE_DIR"
    --file "$SCRIPT_DIR/Dockerfile"
    --load
)
if [ -n "$PLATFORM" ]; then
    build_args+=(--platform="$PLATFORM")
fi

docker buildx build "${build_args[@]}" "$MANAGER_DIR"

if [ -n "$SAVE_PATH" ]; then
    echo
    echo "==> Saving image to $SAVE_PATH"
    docker save "$IMAGE_TAG" -o "$SAVE_PATH"
    ls -lh "$SAVE_PATH"
fi

echo
echo "==> Done. Bring up the stack with:"
echo "    cd $SCRIPT_DIR && docker compose up -d"
