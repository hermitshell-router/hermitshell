#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Agent socket should exist
socket_type=$(vm_exec router "stat -c '%F' /run/hermitshell/agent.sock 2>/dev/null")
assert_match "$socket_type" "socket" "Agent socket exists"

# Agent should respond to get_status (with retry — socket may exist before agent accepts)
require_agent
status=$(vm_exec router 'echo "{\"method\":\"get_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$status" '"ok":true' "Agent responds to get_status"

# Agent should log the configured interfaces
agent_log=$(deploy_get_agent_log)
assert_match "$agent_log" "network interfaces" "Agent logs interface configuration"
