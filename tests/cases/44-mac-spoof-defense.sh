#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_nftables
require_lan_ip

# --- Phase 1: Static ARP binding ---

# Get LAN device MAC and IP
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")

# Wait for agent startup to finish restoring MAC-IP rules
_mac_ip_ready() {
    vm_nft "list chain inet filter mac_ip_validate" 2>/dev/null | grep -q "$device_ip"
}
wait_for 10 "MAC-IP rules restored" _mac_ip_ready

# Verify router has a permanent neighbor entry for the LAN device
neigh=$(vm_sudo router "ip neigh show $device_ip dev eth2")
assert_match "$neigh" "PERMANENT" "Device has permanent ARP entry on router"
assert_contains "$neigh" "$lan_mac" "ARP entry maps to correct MAC"

# --- Phase 2: nftables MAC-IP validation ---

# Verify the mac_ip_validate chain exists
chain=$(vm_nft "list chain inet filter mac_ip_validate" || echo "")
assert_match "$chain" "mac_ip_validate" "mac_ip_validate chain exists"

# Verify there's a rule binding our device's IP to its MAC
# Rule format: ip saddr <ip> ether saddr != <mac> counter drop
assert_contains "$chain" "$device_ip" "mac_ip_validate has rule for device IP"
assert_contains "$chain" "$lan_mac" "mac_ip_validate binds to correct MAC"

# --- Phase 3: DHCP fingerprint recording ---

# Get device info and check for dhcp_fingerprint field
device_info=$(vm_exec router "echo '{\"method\":\"list_devices\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$device_info" '"dhcp_fingerprint"' "Device has dhcp_fingerprint field"
# The LAN VM (Ubuntu) should have a non-empty fingerprint after DHCP
# Option 55 produces a comma-separated list of option codes
assert_match "$device_info" '"dhcp_fingerprint":"[0-9]' "Device has non-empty DHCP fingerprint"

# --- Phase 3b: DHCP fingerprint change detection ---

# Store a fake old fingerprint to create a mismatch
vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"dhcp_fp_$lan_mac\",\"value\":\"99,98,97\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null

# Trigger analysis cycle
vm_exec router "echo '{\"method\":\"run_analysis\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null

# Check alerts for dhcp_fingerprint_change
alerts=$(vm_exec router "echo '{\"method\":\"list_alerts\",\"rule\":\"dhcp_fingerprint_change\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$alerts" "dhcp_fingerprint_change" "Fingerprint change alert fired"
