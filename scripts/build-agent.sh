#!/bin/bash
set -e

# Build with musl for static linking (portable across Linux distros)
cargo build --release -p hermitshell-agent --target x86_64-unknown-linux-musl

# Copy to release dir for convenience
mkdir -p target/release
cp target/x86_64-unknown-linux-musl/release/hermitshell-agent target/release/

echo "Agent built: target/release/hermitshell-agent (statically linked)"

# Build container if docker is available
if command -v docker &> /dev/null; then
    ./scripts/build-container.sh
    docker save hermitshell:latest -o target/release/hermitshell-container.tar
    echo "Container saved: target/release/hermitshell-container.tar"
fi
