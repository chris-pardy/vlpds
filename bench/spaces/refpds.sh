#!/usr/bin/env bash
# The reference implementation, pinned: clones bluesky-social/atproto at the
# Spaces alpha pin into .scratch/atproto (blobless, so small) and builds the
# reference PDS image from it natively, with the pin's own root Dockerfile
# (target pds; the published pds-spaces-alpha image is b27a037c7, the pin
# merged with main, built from the same Dockerfile). Skips what already exists.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
PIN=d4def6e9f521896ed8222f576d54923d00b5fbeb
IMAGE="vlpds-spaces-refpds:${PIN:0:8}"
src="$here/.scratch/atproto"
mkdir -p "$here/.scratch"
if [ ! -d "$src/.git" ]; then
  git clone -q --filter=blob:none --no-checkout https://github.com/bluesky-social/atproto.git "$src"
fi
if [ "$(git -C "$src" rev-parse HEAD 2>/dev/null)" != "$PIN" ]; then
  git -C "$src" fetch -q origin "$PIN"
  git -C "$src" -c advice.detachedHead=false checkout -q "$PIN"
fi
if [ -n "${REF_PDS_IMAGE:-}" ] || docker image inspect "$IMAGE" >/dev/null 2>&1; then
  exit 0
fi
echo "building $IMAGE (atproto $PIN; ~10 min the first time)" >&2
docker build -q --target pds -t "$IMAGE" -f "$src/Dockerfile" "$src" >&2
