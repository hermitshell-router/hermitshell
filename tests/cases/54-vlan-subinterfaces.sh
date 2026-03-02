#!/bin/bash
set -euo pipefail
source "$(dirname "$0")/../lib/helpers.sh"

echo "=== Test 54: VLAN subinterface creation and teardown ==="

# --- Step 1: Enable VLAN mode via agent socket ---
ENABLE=$(vm_sudo router 'echo "{\"method\":\"vlan_enable\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$ENABLE" '"ok":true' "vlan_enable succeeds"

# --- Step 2: Verify subinterfaces exist ---
IFACES=$(vm_sudo router 'ip -o link show')
assert_match "$IFACES" "eth2\.10" "subinterface eth2.10 exists"
assert_match "$IFACES" "eth2\.20" "subinterface eth2.20 exists"
assert_match "$IFACES" "eth2\.30" "subinterface eth2.30 exists"
assert_match "$IFACES" "eth2\.40" "subinterface eth2.40 exists"
assert_match "$IFACES" "eth2\.50" "subinterface eth2.50 exists"

# --- Step 3: Verify gateway IPs assigned on each subinterface ---
ADDRS=$(vm_sudo router 'ip -o addr show')
assert_match "$ADDRS" "eth2\.10.*10\.0\.10\.1/24" "eth2.10 has gateway 10.0.10.1/24"
assert_match "$ADDRS" "eth2\.20.*10\.0\.20\.1/24" "eth2.20 has gateway 10.0.20.1/24"
assert_match "$ADDRS" "eth2\.30.*10\.0\.30\.1/24" "eth2.30 has gateway 10.0.30.1/24"
assert_match "$ADDRS" "eth2\.40.*10\.0\.40\.1/24" "eth2.40 has gateway 10.0.40.1/24"
assert_match "$ADDRS" "eth2\.50.*10\.0\.50\.1/24" "eth2.50 has gateway 10.0.50.1/24"

# --- Step 4: Verify nftables rules reference VLAN subinterfaces ---
NFT_INPUT=$(vm_sudo router 'nft list chain inet filter input')
assert_match "$NFT_INPUT" "eth2\.10" "nftables input references eth2.10"
assert_match "$NFT_INPUT" "eth2\.50" "nftables input references eth2.50"

NFT_FORWARD=$(vm_sudo router 'nft list chain inet filter forward')
assert_match "$NFT_FORWARD" "eth2\.10.*udp sport 67.*drop" "nftables forward blocks rogue DHCP on eth2.10"

# --- Step 5: Check VLAN status via socket API ---
STATUS=$(vm_sudo router 'echo "{\"method\":\"vlan_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$STATUS" '"ok":true' "vlan_status succeeds"
# config_value is a JSON string (double-encoded), so inner keys appear with escaped quotes
assert_match "$STATUS" 'config_value' "vlan_status returns config_value"
assert_match "$STATUS" 'enabled.*true' "vlan_status reports enabled"
assert_match "$STATUS" 'vlan_id.*10' "vlan_status includes vlan_id 10"
assert_match "$STATUS" 'trusted' "vlan_status includes trusted group"
assert_match "$STATUS" '10\.0\.10\.1' "vlan_status includes trusted gateway"

# --- Step 6: Disable VLAN mode ---
DISABLE=$(vm_sudo router 'echo "{\"method\":\"vlan_disable\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$DISABLE" '"ok":true' "vlan_disable succeeds"

# --- Step 7: Verify subinterfaces are removed ---
IFACES_AFTER=$(vm_sudo router 'ip -o link show')
if echo "$IFACES_AFTER" | grep -q "eth2\\.10"; then
    echo -e "${RED}FAIL${NC}: eth2.10 still exists after disable"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: eth2.10 removed after disable"
fi

if echo "$IFACES_AFTER" | grep -q "eth2\\.50"; then
    echo -e "${RED}FAIL${NC}: eth2.50 still exists after disable"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: eth2.50 removed after disable"
fi

# --- Step 8: Verify nftables back to flat mode (no VLAN subinterface refs) ---
NFT_INPUT_AFTER=$(vm_sudo router 'nft list chain inet filter input')
if echo "$NFT_INPUT_AFTER" | grep -q "eth2\\.10"; then
    echo -e "${RED}FAIL${NC}: nftables input still references eth2.10 after disable"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: nftables input no longer references VLAN subinterfaces"
fi

NFT_FWD_AFTER=$(vm_sudo router 'nft list chain inet filter forward')
if echo "$NFT_FWD_AFTER" | grep -q "eth2\\.10"; then
    echo -e "${RED}FAIL${NC}: nftables forward still references eth2.10 after disable"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: nftables forward no longer references VLAN subinterfaces"
fi

# Verify flat-mode rules are restored (eth2 referenced directly, not as VLAN sub)
assert_match "$NFT_INPUT_AFTER" "eth2" "nftables input references eth2 in flat mode"
assert_match "$NFT_FWD_AFTER" "udp sport 67.*drop" "nftables forward has rogue DHCP rule in flat mode"

echo "=== Test 54 complete ==="
