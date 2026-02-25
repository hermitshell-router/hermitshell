#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- check_update returns ok with current_version ---
result=$(vm_exec router "echo '{\"method\":\"check_update\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "check_update succeeds"
assert_match "$result" '"current_version"' "response has current_version"
assert_match "$result" '"update_info"' "response has update_info"

# --- current_version is a semver-like string ---
assert_match "$result" '"current_version":"[0-9]' "current_version starts with digit"

# --- latest_version and last_check fields present (may be null before first check) ---
assert_match "$result" '"latest_version"' "response has latest_version field"
assert_match "$result" '"last_check"' "response has last_check field"

# --- enabled field present and defaults to false ---
assert_match "$result" '"enabled":false' "update check disabled by default"
