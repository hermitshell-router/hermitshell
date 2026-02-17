#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Enable WireGuard
result=$(vm_exec router 'echo "{\"method\":\"set_wireguard_enabled\",\"enabled\":true}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "Enable WireGuard"

# Verify wg0 interface exists
wg_iface=$(vagrant ssh router -c "sudo ip link show wg0" 2>/dev/null || echo "")
assert_match "$wg_iface" "wg0" "wg0 interface exists"

# Get WireGuard status
status=$(vm_exec router 'echo "{\"method\":\"get_wireguard\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$status" '"enabled":true' "WireGuard shows enabled"
assert_match "$status" '"public_key"' "WireGuard has public key"
assert_match "$status" '"listen_port":51820' "WireGuard listen port is 51820"

# Generate a peer keypair on lan-vm
peer_privkey=$(vagrant ssh lan -c "wg genkey" 2>/dev/null | tr -d '\r\n')
peer_pubkey=$(vagrant ssh lan -c "echo '$peer_privkey' | wg pubkey" 2>/dev/null | tr -d '\r\n')
assert_match "$peer_pubkey" "^[A-Za-z0-9+/]" "Generated peer public key"

# Add peer
result=$(vm_exec router "echo '{\"method\":\"add_wg_peer\",\"name\":\"test-laptop\",\"public_key\":\"$peer_pubkey\",\"group\":\"trusted\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "Add WireGuard peer"
assert_match "$result" '"device_ip":"10\.' "Peer got IP address"

# Extract peer IP from response
peer_ip=$(echo "$result" | grep -oP '"device_ip":"[^"]+' | cut -d'"' -f4)
assert_match "$peer_ip" "^10\." "Parsed peer IP"

# Verify peer appears in status
status=$(vm_exec router 'echo "{\"method\":\"get_wireguard\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$status" '"name":"test-laptop"' "Peer appears in status"
assert_match "$status" '"device_group":"trusted"' "Peer group is trusted"

# Verify peer is in wg show (use fixed-string match; pubkey has regex metacharacters)
wg_show=$(vagrant ssh router -c "sudo wg show wg0" 2>/dev/null)
if echo "$wg_show" | grep -qF "$peer_pubkey"; then
    echo -e "${GREEN}PASS${NC}: Peer in wg show output"
else
    echo -e "${RED}FAIL${NC}: Peer in wg show output"
    echo "  Expected (fixed string): $peer_pubkey"
    echo "  Actual: $wg_show"
fi

# Verify nftables has the peer in verdict map
nft_map=$(vagrant ssh router -c "sudo nft list map inet filter device_groups" 2>/dev/null)
assert_match "$nft_map" "$peer_ip" "Peer IP in verdict map"

# Remove peer
result=$(vm_exec router "echo '{\"method\":\"remove_wg_peer\",\"public_key\":\"$peer_pubkey\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "Remove WireGuard peer"

# Verify wg0 still exists after peer removal
wg_show=$(vagrant ssh router -c "sudo wg show wg0" 2>/dev/null)
assert_match "$wg_show" "wg0" "wg0 still exists after peer removal"

# Disable WireGuard
result=$(vm_exec router 'echo "{\"method\":\"set_wireguard_enabled\",\"enabled\":false}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "Disable WireGuard"

# Verify wg0 is gone
wg_gone=$(vagrant ssh router -c "sudo ip link show wg0 2>&1" 2>/dev/null || echo "not found")
assert_match "$wg_gone" "does not exist|not found" "wg0 interface removed"
