#!/bin/bash
set -e
cd "$(dirname "$0")/.."

docker build -t hermitshell:latest -f hermitshell/Dockerfile .

echo "Container built: hermitshell:latest"
