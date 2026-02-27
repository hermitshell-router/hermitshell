#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_nftables
require_lan_ip

# --- Phase 1: Static ARP binding ---

# Get LAN device MAC and IP
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")

# Verify router has a permanent neighbor entry for the LAN device
neigh=$(vm_sudo router "ip neigh show $device_ip dev eth2")
assert_match "$neigh" "PERMANENT" "Device has permanent ARP entry on router"
assert_contains "$neigh" "$lan_mac" "ARP entry maps to correct MAC"
