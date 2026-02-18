#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Enable WireGuard on router
result=$(vm_exec router 'echo "{\"method\":\"set_wireguard_enabled\",\"enabled\":true}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "Enable WireGuard for traffic test"

# Get router's server public key
status=$(vm_exec router 'echo "{\"method\":\"get_wireguard\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
server_pubkey=$(echo "$status" | grep -oP '"public_key":"[^"]+' | cut -d'"' -f4)
assert_match "$server_pubkey" "^[A-Za-z0-9+/]" "Got server public key"

# Generate peer keypair on lan-vm
peer_privkey=$(vagrant ssh lan -c "wg genkey" 2>/dev/null | tr -d '\r\n')
peer_pubkey=$(vagrant ssh lan -c "echo '$peer_privkey' | wg pubkey" 2>/dev/null | tr -d '\r\n')

# Add peer as trusted (full access)
result=$(vm_exec router "echo '{\"method\":\"add_wg_peer\",\"name\":\"tunnel-test\",\"public_key\":\"$peer_pubkey\",\"group\":\"trusted\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "Add tunnel test peer"
peer_ip=$(echo "$result" | grep -oP '"device_ipv4":"[^"]+' | cut -d'"' -f4)

# Get the router's LAN IP for WireGuard endpoint
# In test env, lan-vm connects to router via LAN network
router_lan_ip="10.0.0.1"

# Configure WireGuard on lan-vm
vagrant ssh lan -c "sudo bash -c '
    ip link add wg-test type wireguard 2>/dev/null || true
    umask 077
    echo \"$peer_privkey\" > /tmp/wg-privkey
    wg set wg-test private-key /tmp/wg-privkey peer \"$server_pubkey\" allowed-ips 10.0.0.1/32,192.168.100.0/24 endpoint $router_lan_ip:51820
    rm -f /tmp/wg-privkey
    ip addr add $peer_ip/32 dev wg-test 2>/dev/null || true
    ip link set wg-test up
    ip route add 192.168.100.0/24 dev wg-test 2>/dev/null || true
'" 2>/dev/null || true

# Wait for tunnel to establish (poll for handshake)
tunnel_up() {
    vm_exec lan "wg show wg-test latest-handshakes" | grep -q '[1-9]'
}
wait_for 10 "WireGuard tunnel established" tunnel_up

# Test: ping router through tunnel
assert_success "Ping router via WireGuard tunnel" \
    vm_exec lan "ping -c1 -W3 -I wg-test 10.0.0.1"

# Test: reach WAN through tunnel (trusted group = full access)
assert_success "Reach WAN through WireGuard tunnel" \
    vm_exec lan "ping -c1 -W3 -I wg-test 192.168.100.2"

# Clean up: tear down WireGuard on lan-vm
vagrant ssh lan -c "sudo ip link del wg-test 2>/dev/null" 2>/dev/null || true

# Clean up: remove peer and disable WireGuard
vm_exec router "echo '{\"method\":\"remove_wg_peer\",\"public_key\":\"$peer_pubkey\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" > /dev/null
vm_exec router 'echo "{\"method\":\"set_wireguard_enabled\",\"enabled\":false}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' > /dev/null
