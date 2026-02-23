#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  DOCKER_ARCH="amd64" ;;
    aarch64) DOCKER_ARCH="arm64" ;;
    *) echo "Unsupported: $ARCH" >&2; exit 1 ;;
esac

mkdir -p "docker-ctx/$DOCKER_ARCH"
cp target/release/hermitshell-agent "docker-ctx/$DOCKER_ARCH/"
cp target/release/hermitshell-dhcp "docker-ctx/$DOCKER_ARCH/"
cp target/release/hermitshell "docker-ctx/$DOCKER_ARCH/"
cp target/release/blocky "docker-ctx/$DOCKER_ARCH/"

docker build -t hermitshell:latest .

rm -rf docker-ctx
echo "Built: hermitshell:latest"
