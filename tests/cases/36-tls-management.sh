#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- get_tls_status returns mode and cert info ---
result=$(vm_exec router "echo '{\"method\":\"get_tls_status\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "get_tls_status succeeds"
assert_match "$result" '"tls_mode":"self_signed"' "default tls_mode is self_signed"
assert_match "$result" '"issuer"' "get_tls_status returns issuer"
assert_match "$result" '"expires_at"' "get_tls_status returns expiry"
assert_match "$result" '"sans"' "get_tls_status returns SANs"
