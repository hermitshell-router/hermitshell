#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_nftables

echo "=== Test 42: mDNS proxy ==="

# Verify nftables allows mDNS traffic on LAN
rules=$(vm_nft "list chain inet filter input")
assert_match "$rules" "udp dport 5353 accept" "nftables allows mDNS port 5353"

# Get LAN device MAC
LAN_MAC=$(vm_exec lan 'cat /sys/class/net/eth1/address')

# Query mDNS services for a device (should return empty initially)
RESULT=$(vm_exec router "echo '{\"method\":\"list_mdns_services\",\"mac\":\"$LAN_MAC\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$RESULT" '"ok":true' "list_mdns_services returns ok"
assert_match "$RESULT" '"mdns_services":\[\]' "no mDNS services initially"

# Query for nonexistent device returns error
RESULT=$(vm_exec router "echo '{\"method\":\"list_mdns_services\",\"mac\":\"00:00:00:00:00:00\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$RESULT" '"ok":false' "list_mdns_services rejects unknown MAC"

# Test auto_classify_devices config key
RESULT=$(vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"auto_classify_devices\",\"value\":\"true\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$RESULT" '"ok":true' "set auto_classify_devices"

RESULT=$(vm_exec router "echo '{\"method\":\"get_config\",\"key\":\"auto_classify_devices\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$RESULT" '"config_value":"true"' "auto_classify_devices persisted"

# Reset
vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"auto_classify_devices\",\"value\":\"false\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null

echo "=== Test 42 complete ==="
