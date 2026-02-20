#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip
require_nftables

# Get LAN device IP
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$device_ip" "10\." "LAN device has 10.x IP"

# Add a port forward
result=$(vm_exec router "echo '{\"method\":\"add_port_forward\",\"protocol\":\"tcp\",\"external_port_start\":8080,\"external_port_end\":8080,\"internal_ip\":\"$device_ip\",\"internal_port\":80,\"description\":\"test\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "add_port_forward succeeds"

# List port forwards
result=$(vm_exec router 'echo "{\"method\":\"list_port_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_port_forwards succeeds"
assert_match "$result" '8080' "port forward shows port 8080"

# Verify nftables has the DNAT rule
rules=$(vm_exec router "sudo nft list chain ip nat prerouting" 2>/dev/null || echo "")
assert_match "$rules" "dport 8080" "nftables has DNAT rule for 8080"

# Remove port forward
result=$(vm_exec router 'echo "{\"method\":\"remove_port_forward\",\"id\":1}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "remove_port_forward succeeds"
