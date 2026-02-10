#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Agent socket should exist
assert_success "Agent socket exists" \
    vm_exec router "test -S /run/hermitshell/agent.sock"

# Agent should respond to get_status
status=$(vm_exec router 'echo "{\"method\":\"get_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$status" '"ok":true' "Agent responds to get_status"
