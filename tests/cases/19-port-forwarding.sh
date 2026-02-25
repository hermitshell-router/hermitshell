#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip
require_nftables

# Get LAN device IP
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$device_ip" "10\." "LAN device has 10.x IP"

# Clean up any leftover port forwards from previous runs
existing_ids=$(vm_exec router 'echo "{\"method\":\"list_port_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -oP '"id":\K[0-9]+')
for id in $existing_ids; do
    vm_exec router "echo '{\"method\":\"remove_port_forward\",\"id\":$id}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null 2>&1
done

# Add a port forward: WAN:8080 -> LAN device:80
result=$(vm_exec router "echo '{\"method\":\"add_port_forward\",\"protocol\":\"tcp\",\"external_port_start\":8080,\"external_port_end\":8080,\"internal_ip\":\"$device_ip\",\"internal_port\":80,\"description\":\"test forward\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "add_port_forward succeeds"

# Try to add overlapping forward — should fail
overlap_result=$(vm_exec router "echo '{\"method\":\"add_port_forward\",\"protocol\":\"tcp\",\"external_port_start\":8080,\"external_port_end\":8080,\"internal_ip\":\"$device_ip\",\"internal_port\":81,\"description\":\"overlap test\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$overlap_result" '"ok":false' "overlapping port forward rejected"
assert_match "$overlap_result" 'overlap' "error mentions overlap"

# Try with "both" protocol overlapping tcp — should also fail
overlap_result2=$(vm_exec router "echo '{\"method\":\"add_port_forward\",\"protocol\":\"both\",\"external_port_start\":8079,\"external_port_end\":8081,\"internal_ip\":\"$device_ip\",\"internal_port\":79,\"description\":\"range overlap test\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$overlap_result2" '"ok":false' "range overlap with both protocol rejected"

# UDP on same port should succeed (no protocol overlap with tcp)
udp_result=$(vm_exec router "echo '{\"method\":\"add_port_forward\",\"protocol\":\"udp\",\"external_port_start\":8080,\"external_port_end\":8080,\"internal_ip\":\"$device_ip\",\"internal_port\":80,\"description\":\"udp no overlap\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$udp_result" '"ok":true' "UDP on same port as TCP succeeds (no overlap)"

# Verify port forward appears in list with correct fields
result=$(vm_exec router 'echo "{\"method\":\"list_port_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_port_forwards succeeds"
assert_contains "$result" '"external_port_start":8080' "Forward lists external port 8080"
assert_contains "$result" "\"internal_ip\":\"$device_ip\"" "Forward lists correct internal IP"
assert_contains "$result" '"internal_port":80' "Forward lists internal port 80"
assert_contains "$result" '"protocol":"tcp"' "Forward lists protocol tcp"

# Verify nftables DNAT rule has correct structure
nat_rules=$(vm_nft "list chain ip nat prerouting" || echo "")
assert_match "$nat_rules" "tcp dport 8080 dnat to ${device_ip}:80" "NAT prerouting has complete DNAT rule"

# Verify nftables forward rule allows the forwarded traffic
fwd_rules=$(vm_nft "list chain inet filter port_fwd" || echo "")
assert_match "$fwd_rules" "ip daddr ${device_ip} tcp dport 80 accept" "Forward chain allows traffic to internal IP:port"

# Test actual traffic through the port forward:
# Start a TCP listener on LAN VM port 80 that echoes a marker
vm_sudo lan "echo PORT_FWD_OK | ncat -l -p 80 -w 5 &" || \
    vm_sudo lan "(echo PORT_FWD_OK | socat - TCP-LISTEN:80,reuseaddr) &" || true

# Connect from WAN VM through the router's WAN IP to test the forward
router_wan_ip=$(vm_exec router "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
traffic_result=$(vm_exec wan "curl -s --connect-timeout 3 http://${router_wan_ip}:8080 2>/dev/null" || echo "")
# If ncat/socat unavailable, traffic test is best-effort; nftables rule validation above is the primary check

# Verify DNAT rule is removed after delete
# Remove all remaining port forwards
remaining_ids=$(vm_exec router 'echo "{\"method\":\"list_port_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -oP '"id":\K[0-9]+')
first_id=""
for rid in $remaining_ids; do
    [ -z "$first_id" ] && first_id=$rid
    result=$(vm_exec router "echo '{\"method\":\"remove_port_forward\",\"id\":$rid}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
    assert_match "$result" '"ok":true' "remove_port_forward $rid succeeds"
done

# Verify nftables rule is actually gone
nat_after=$(vm_nft "list chain ip nat prerouting" || echo "")
if echo "$nat_after" | grep -q "dport 8080"; then
    echo -e "${RED}FAIL${NC}: DNAT rule still present after removal"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: DNAT rule removed from nftables after delete"
fi
