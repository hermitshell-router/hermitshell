#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- check_update returns version info ---
result=$(vm_exec router "echo '{\"method\":\"check_update\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "check_update succeeds"
assert_match "$result" '"current_version"' "response has current_version"

# --- Set update_latest_version to current version, verify apply_update says already up to date ---
current=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['update_info']['current_version'])")
vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"update_latest_version\",\"value\":\"v${current}\"}' | socat - $SOCK" > /dev/null

result=$(vm_exec router "echo '{\"method\":\"apply_update\"}' | socat - $SOCK")
assert_match "$result" '"error"' "apply_update returns error when already current"
assert_match "$result" 'already running' "apply_update says already running"

# --- auto_update_enabled config key ---
vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"auto_update_enabled\",\"value\":\"true\"}' | socat - $SOCK" > /dev/null
result=$(vm_exec router "echo '{\"method\":\"check_update\"}' | socat - $SOCK")
assert_match "$result" '"auto_update_enabled":true' "auto_update_enabled reflected in check_update"

# Clean up
vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"auto_update_enabled\",\"value\":\"false\"}' | socat - $SOCK" > /dev/null
