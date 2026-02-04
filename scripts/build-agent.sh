#!/bin/bash
set -e
cargo build --release -p hermitshell-agent
echo "Agent built: target/release/hermitshell-agent"
