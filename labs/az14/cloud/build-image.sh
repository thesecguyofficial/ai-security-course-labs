#!/usr/bin/env bash
# build-image.sh: build a container image and push it to YOUR Azure Container Registry WITHOUT Docker and WITHOUT
# ACR Tasks (`az acr build`).
#
# Why this exists: on free-credit and trial subscriptions Azure refuses `az acr build` with
#   (TasksOperationsNotAllowed) ACR Tasks requests for the registry ... are not permitted.
# (we hit this on 9 Nov 2026). This script does the same job from Azure Cloud Shell or any Linux/macOS shell with
# Python 3.12 and the Azure CLI:
#   1. installs the Python packages from <dir>/requirements.txt for linux/amd64 + Python 3.12 into a folder,
#   2. puts them and your code in ONE extra layer on top of the official python:3.12-slim image,
#   3. pushes the result to <registry>.azurecr.io/<name>:<tag> with `crane` (Google's go-containerregistry tool),
#      signed in with a short-lived Entra token from `az acr login --expose-token` (no admin user, no password).
# The image runs the same as the Dockerfile next to your code: WORKDIR /app, CMD python <entry file>.
#
# Usage: ./build-image.sh <registry name> <name:tag> <source dir> <entry file> [--pre]
#   e.g. ./build-image.sh craz14ab12 helpdesk-mcp:1 mcp server.py
#        ./build-image.sh craz14ab12 helpdesk-agent:1 agent main.py --pre
set -euo pipefail

REG="${1:?registry name, e.g. craz14ab12}"
IMG="${2:?image name:tag, e.g. helpdesk-mcp:1}"
SRC="${3:?source folder with requirements.txt and your .py files}"
ENTRY="${4:?entry file, e.g. server.py}"
PRE="${5:-}"
CRANE_VERSION="v0.20.2"
BASE="python:3.12-slim"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1. crane, pinned and checked against the release's own checksums file
TOOLS="$HERE/.state/tools"
mkdir -p "$TOOLS"
if [ ! -x "$TOOLS/crane" ]; then
  echo "== getting crane $CRANE_VERSION (github.com/google/go-containerregistry)"
  url="https://github.com/google/go-containerregistry/releases/download/$CRANE_VERSION"
  file="go-containerregistry_Linux_x86_64.tar.gz"
  [ "$(uname -s)" = "Darwin" ] && file="go-containerregistry_Darwin_$(uname -m).tar.gz"
  curl -fsSL "$url/$file" -o "$WORK/$file"
  curl -fsSL "$url/checksums.txt" -o "$WORK/checksums.txt"
  (cd "$WORK" && grep " $file\$" checksums.txt | sha256sum -c -)
  tar -xzf "$WORK/$file" -C "$TOOLS" crane
fi
CRANE="$TOOLS/crane"

# 2. the layer: /app/<your code> and /app/deps/<packages built for linux/amd64, CPython 3.12>
echo "== installing $SRC/requirements.txt for linux/amd64, Python 3.12"
mkdir -p "$WORK/layer/app/deps"
python3 -m pip install -q --no-cache-dir --target "$WORK/layer/app/deps" -r "$SRC/requirements.txt" $PRE \
  --python-version 3.12 --implementation cp --only-binary=:all: \
  --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux_2_28_x86_64
cp "$SRC"/*.py "$WORK/layer/app/"
tar -C "$WORK/layer" -cf "$WORK/layer.tar" app

# 3. sign in to the registry with a short-lived Entra token (never printed), append the layer, set how it starts
echo "== pushing $REG.azurecr.io/$IMG"
TOKEN="$(az acr login -n "$REG" --expose-token --query accessToken -o tsv 2>/dev/null)"
"$CRANE" auth login "$REG.azurecr.io" -u 00000000-0000-0000-0000-000000000000 --password-stdin <<<"$TOKEN" >/dev/null
unset TOKEN
"$CRANE" append --platform linux/amd64 -b "$BASE" -f "$WORK/layer.tar" -t "$REG.azurecr.io/$IMG.tmp" >/dev/null
"$CRANE" mutate "$REG.azurecr.io/$IMG.tmp" -t "$REG.azurecr.io/$IMG" --workdir /app \
  --env PYTHONPATH=/app/deps --env PYTHONUNBUFFERED=1 --entrypoint python --cmd "$ENTRY" >/dev/null
"$CRANE" delete "$REG.azurecr.io/$IMG.tmp" >/dev/null 2>&1 || true
echo "== done: $REG.azurecr.io/$IMG@$("$CRANE" digest "$REG.azurecr.io/$IMG")"
"$CRANE" auth logout "$REG.azurecr.io" >/dev/null 2>&1 || true
