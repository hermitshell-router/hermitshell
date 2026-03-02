#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../lib/helpers.sh"

echo "=== Test 53: Rogue DHCP server blocking ==="

# Verify nftables forward chain contains the rogue DHCP drop rule
RULES=$(vm_sudo router 'nft list chain inet filter forward')
assert_match "$RULES" "udp sport 67.*drop" "forward chain blocks rogue DHCP (sport 67)"

# Verify nftables input chain also blocks rogue DHCP
RULES_INPUT=$(vm_sudo router 'nft list chain inet filter input')
assert_match "$RULES_INPUT" "udp sport 67.*drop" "input chain blocks rogue DHCP (sport 67)"

echo "=== Test 53 complete ==="
