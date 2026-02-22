#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip

lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")
assert_match "$lan_mac" "^[0-9a-f]" "Got LAN MAC address"

# Test hostname sanitization at DHCP layer
# Send a hostname with HTML/shell injection characters via the DHCP socket
# The DHCP server should sanitize before forwarding to the agent
args=$(_vm_ssh_args router)
result=$(ssh $SSH_COMMON $args "sudo bash -s" 2>/dev/null <<EOTEST
DSOCK=/run/hermitshell/dhcp.sock
ASOCK=/run/hermitshell/agent.sock
MAC="$lan_mac"

# Send hostname with injection characters — DHCP server should strip them
echo "{\"method\":\"dhcp_discover\",\"mac\":\"\$MAC\",\"hostname\":\"<script>alert(1)</script>\"}" | socat - UNIX-CONNECT:\$DSOCK

# Query to see what was stored
echo "{\"method\":\"get_device\",\"mac\":\"\$MAC\"}" | socat - UNIX-CONNECT:\$ASOCK
EOTEST
)

assert_match "$result" '"ok":true' "dhcp_discover with malicious hostname succeeds"
# After sanitization: <script>alert(1)</script> -> scriptalert1script
assert_contains "$result" '"hostname":"scriptalert1script"' "Malicious hostname sanitized at DHCP layer"

# Test with a very long hostname (200+ chars)
long_host=$(printf 'a%.0s' {1..200})
result=$(ssh $SSH_COMMON $args "sudo bash -s" 2>/dev/null <<EOTEST
DSOCK=/run/hermitshell/dhcp.sock
ASOCK=/run/hermitshell/agent.sock
MAC="$lan_mac"

echo "{\"method\":\"dhcp_discover\",\"mac\":\"\$MAC\",\"hostname\":\"$long_host\"}" | socat - UNIX-CONNECT:\$DSOCK
echo "{\"method\":\"get_device\",\"mac\":\"\$MAC\"}" | socat - UNIX-CONNECT:\$ASOCK
EOTEST
)

assert_match "$result" '"ok":true' "dhcp_discover with long hostname succeeds"
# Hostname should be truncated to 63 chars
truncated=$(printf 'a%.0s' {1..63})
assert_contains "$result" "\"hostname\":\"$truncated\"" "Long hostname truncated to 63 chars"

# Test with all-invalid hostname (only special chars)
result=$(ssh $SSH_COMMON $args "sudo bash -s" 2>/dev/null <<EOTEST
DSOCK=/run/hermitshell/dhcp.sock
ASOCK=/run/hermitshell/agent.sock
MAC="$lan_mac"

# First set a known hostname so we can verify it doesn't change
echo "{\"method\":\"dhcp_discover\",\"mac\":\"\$MAC\",\"hostname\":\"keepme\"}" | socat - UNIX-CONNECT:\$DSOCK

# Send all-invalid hostname — should be dropped (empty after sanitize)
echo "{\"method\":\"dhcp_discover\",\"mac\":\"\$MAC\",\"hostname\":\"<>!@#\"}" | socat - UNIX-CONNECT:\$DSOCK

echo "{\"method\":\"get_device\",\"mac\":\"\$MAC\"}" | socat - UNIX-CONNECT:\$ASOCK
EOTEST
)

assert_contains "$result" '"hostname":"keepme"' "All-invalid hostname preserves previous hostname"

# Restore original hostname
ssh $SSH_COMMON $args "sudo bash -s" 2>/dev/null <<EOTEST
echo "{\"method\":\"dhcp_discover\",\"mac\":\"$lan_mac\",\"hostname\":\"lan\"}" | socat - UNIX-CONNECT:/run/hermitshell/dhcp.sock
EOTEST
