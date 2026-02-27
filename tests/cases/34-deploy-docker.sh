#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

if [ "${HERMIT_MODE:-direct}" != "docker" ]; then
    echo "SKIP: docker-only test (mode=$HERMIT_MODE)"
    exit 0
fi

require_agent

# Container is running
running=$(vm_exec router "docker inspect -f '{{.State.Running}}' hermitshell-aio" 2>/dev/null)
assert_match "$running" "true" "All-in-one container running"

# s6-overlay is PID 1
pid1=$(vm_exec router "docker exec hermitshell-aio cat /proc/1/cmdline 2>/dev/null" | tr '\0' ' ')
assert_contains "$pid1" "s6" "PID 1 is s6-overlay"

# Agent process running inside container
agent_pid=$(vm_exec router "docker exec hermitshell-aio pgrep -f hermitshell-agent" 2>/dev/null || echo "")
assert_match "$agent_pid" "^[0-9]+" "Agent running in container"

# DHCP process running inside container
dhcp_pid=$(vm_exec router "docker exec hermitshell-aio pgrep -f hermitshell-dhcp" 2>/dev/null || echo "")
assert_match "$dhcp_pid" "^[0-9]+" "DHCP running in container"

# Blocky running inside container
blocky_pid=$(vm_exec router "docker exec hermitshell-aio pgrep blocky" 2>/dev/null || echo "")
assert_match "$blocky_pid" "^[0-9]+" "Blocky running in container"

# Web UI running inside container
ui_pid=$(vm_exec router "docker exec hermitshell-aio pgrep -f '/usr/local/bin/hermitshell$'" 2>/dev/null || echo "")
assert_match "$ui_pid" "^[0-9]+" "Web UI running in container"

# Container can access nftables
nft_ok=$(vm_exec router "docker exec hermitshell-aio nft list tables 2>&1")
assert_contains "$nft_ok" "inet filter" "Container can access nftables"

# Data volume is mounted and DB exists
db_check=$(vm_exec router "docker exec hermitshell-aio ls /var/lib/hermitshell/" 2>/dev/null)
assert_contains "$db_check" "hermitshell" "Data volume mounted with DB"

# Socket accessible from host via bind mount
assert_success "Socket accessible from host" \
    vm_exec router "test -S /run/hermitshell/agent.sock"
