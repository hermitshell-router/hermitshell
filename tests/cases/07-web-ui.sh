#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Check if container is running
assert_success "Web UI container running" \
    vm_exec router "docker ps | grep -q hermitshell"

# Check web UI responds
response=$(vm_exec router "curl -s http://localhost:3000/")
assert_match "$response" "HermitShell" "Web UI responds with content"
