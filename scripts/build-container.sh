#!/bin/bash
set -e
cd "$(dirname "$0")/.."

# Copy pre-built musl binary to Docker context
cp target/release/hermitshell hermitshell/hermitshell

docker build -t hermitshell:latest hermitshell/

rm -f hermitshell/hermitshell

echo "Container built: hermitshell:latest"
