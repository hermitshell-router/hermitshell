#!/bin/bash
set -e

# Build with musl for static linking (portable across Linux distros)
cargo build --release -p hermitshell-agent --target x86_64-unknown-linux-musl

# Copy to release dir for convenience
mkdir -p target/release
cp target/x86_64-unknown-linux-musl/release/hermitshell-agent target/release/

echo "Agent built: target/release/hermitshell-agent (statically linked)"

# Download blocky binary (cached)
BLOCKY_VERSION="v0.24"
BLOCKY_BIN="target/release/blocky"
if [ ! -f "$BLOCKY_BIN" ]; then
    echo "Downloading blocky ${BLOCKY_VERSION}..."
    curl -sSL "https://github.com/0xERR0R/blocky/releases/download/${BLOCKY_VERSION}/blocky_${BLOCKY_VERSION}_Linux_x86_64.tar.gz" \
        | tar -xz -C target/release/ blocky
    chmod +x "$BLOCKY_BIN"
    echo "Downloaded: $BLOCKY_BIN"
else
    echo "Blocky already cached: $BLOCKY_BIN"
fi

# Build container if docker is available
if command -v docker &> /dev/null; then
    ./scripts/build-container.sh
    docker save hermitshell:latest -o target/release/hermitshell-container.tar
    echo "Container saved: target/release/hermitshell-container.tar"
fi
