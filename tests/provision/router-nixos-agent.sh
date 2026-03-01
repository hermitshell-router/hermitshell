#!/usr/bin/env bash
# Provision a NixOS router VM — Phase 2: post-reboot setup.
# Called after reboot (interfaces are now eth0, eth1, eth2).
# Does NOT start the agent — run.sh handles that via deploy_start.
set -e

# Ensure NixOS binaries are on PATH for this script
export PATH="/run/current-system/sw/bin:$PATH"

# eth1 = WAN, eth2 = LAN
ip link set eth1 up 2>/dev/null || true
ip link set eth2 up 2>/dev/null || true

# Fix default route to go through WAN (eth1) instead of Vagrant management (eth0)
ip route del default via 192.168.121.1 dev eth0 2>/dev/null || true
ip route add default via 192.168.100.2 dev eth1 2>/dev/null || true

echo "NixOS router ready (eth0=mgmt, eth1=WAN, eth2=LAN)"
