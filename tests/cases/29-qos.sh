#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- 1. QoS defaults: disabled ---
result=$(vm_exec router "echo '{\"method\":\"get_qos_config\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "get_qos_config succeeds"
assert_contains "$result" '"enabled":false' "QoS disabled by default"

# --- 2. Enable QoS ---
result=$(vm_exec router "echo '{\"method\":\"set_qos_config\",\"enabled\":true,\"upload_mbps\":50,\"download_mbps\":200}' | socat - $SOCK")
assert_match "$result" '"ok":true' "set_qos_config enable succeeds"

# --- 3. Verify CAKE on eth1 ---
tc_eth1=$(vm_exec router "sudo tc qdisc show dev eth1")
assert_contains "$tc_eth1" 'cake' "CAKE qdisc present on eth1"

# --- 4. Verify IFB device exists ---
ifb=$(vm_exec router "sudo ip link show ifb0 2>&1")
assert_contains "$ifb" 'ifb0' "ifb0 device exists"

# --- 5. Verify CAKE on ifb0 ---
tc_ifb=$(vm_exec router "sudo tc qdisc show dev ifb0")
assert_contains "$tc_ifb" 'cake' "CAKE qdisc present on ifb0"

# --- 6. Verify DSCP nftables table ---
nft_qos=$(vm_exec router "sudo nft list table inet qos 2>&1")
assert_contains "$nft_qos" 'table inet qos' "nft table inet qos exists"
assert_contains "$nft_qos" 'mark_forward' "nft chain mark_forward exists"

# --- 7. Disable QoS ---
result=$(vm_exec router "echo '{\"method\":\"set_qos_config\",\"enabled\":false}' | socat - $SOCK")
assert_match "$result" '"ok":true' "set_qos_config disable succeeds"

# --- 8. Verify cleanup ---
tc_eth1=$(vm_exec router "sudo tc qdisc show dev eth1 2>&1")
if echo "$tc_eth1" | grep -qF 'cake'; then
    echo -e "${RED}FAIL${NC}: CAKE still on eth1 after disable"
else
    echo -e "${GREEN}PASS${NC}: CAKE removed from eth1 after disable"
fi

ifb=$(vm_exec router "sudo ip link show ifb0 2>&1")
if echo "$ifb" | grep -qF 'ifb0:'; then
    echo -e "${RED}FAIL${NC}: ifb0 still exists after disable"
else
    echo -e "${GREEN}PASS${NC}: ifb0 removed after disable"
fi

nft_qos=$(vm_exec router "sudo nft list table inet qos 2>&1")
if echo "$nft_qos" | grep -qF 'chain mark_forward'; then
    echo -e "${RED}FAIL${NC}: nft table inet qos still exists after disable"
else
    echo -e "${GREEN}PASS${NC}: nft table inet qos removed after disable"
fi

# --- 9. Re-enable for restart test ---
result=$(vm_exec router "echo '{\"method\":\"set_qos_config\",\"enabled\":true,\"upload_mbps\":100,\"download_mbps\":500}' | socat - $SOCK")
assert_match "$result" '"ok":true' "re-enable QoS for restart test"

tc_eth1=$(vm_exec router "sudo tc qdisc show dev eth1")
assert_contains "$tc_eth1" 'cake' "CAKE on eth1 before restart"

# --- 10. Restart agent ---
vagrant ssh router -c "sudo systemctl stop hermitshell-agent 2>/dev/null; sudo killall hermitshell-age hermitshell-dhc 2>/dev/null; true" 2>/dev/null || true

agent_dead() {
    ! vm_exec router "pgrep -x hermitshell-age" | grep -q '[0-9]'
}
wait_for 5 "Agent stopped" agent_dead

vagrant ssh router -c "sudo rm -f /run/hermitshell/*.sock && sudo systemctl restart hermitshell-agent" 2>/dev/null || true

socket_ready() {
    vagrant ssh router -c "sudo chmod 666 /run/hermitshell/agent.sock" 2>/dev/null
    vm_exec router "echo '{\"method\":\"get_status\"}' | socat - $SOCK" | grep -q '"ok":true'
}
wait_for 15 "Agent socket ready after restart" socket_ready

# --- 11. Verify QoS restored after restart ---
tc_eth1=$(vm_exec router "sudo tc qdisc show dev eth1")
assert_contains "$tc_eth1" 'cake' "CAKE restored on eth1 after restart"

tc_ifb=$(vm_exec router "sudo tc qdisc show dev ifb0")
assert_contains "$tc_ifb" 'cake' "CAKE restored on ifb0 after restart"

# --- 12. Export includes QoS ---
result=$(vm_exec router "echo '{\"method\":\"export_config\"}' | socat - $SOCK")
assert_contains "$result" '"ok":true' "export_config succeeds"
assert_contains "$result" 'qos_enabled' "export includes qos_enabled"
assert_contains "$result" 'qos_upload_mbps' "export includes qos_upload_mbps"
assert_contains "$result" 'qos_download_mbps' "export includes qos_download_mbps"

# --- 13. Device group change updates DSCP ---
lan_mac=$(vm_exec lan "ip link show eth1 | grep -oP 'link/ether \K[0-9a-f:]+'" || echo "")
if [ -n "$lan_mac" ]; then
    # Set device to iot group (should be added to bulk_v4 set)
    result=$(vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"iot\"}' | socat - $SOCK")
    assert_match "$result" '"ok":true' "set_device_group to iot succeeds"

    nft_qos=$(vm_exec router "sudo nft list table inet qos 2>&1")
    assert_contains "$nft_qos" 'bulk_v4' "bulk_v4 set exists after iot assignment"
    # The set should have at least one element (the iot device IP)
    assert_contains "$nft_qos" 'elements' "bulk_v4 has elements for iot device"

    # Restore device to trusted group
    result=$(vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$lan_mac\",\"group\":\"trusted\"}' | socat - $SOCK")
    assert_match "$result" '"ok":true' "restored device to trusted"
else
    echo -e "${GREEN}SKIP${NC}: no LAN device MAC found, skipping DSCP device test"
fi

# --- 14. Validation: reject invalid bandwidth ---
result=$(vm_exec router "echo '{\"method\":\"set_qos_config\",\"enabled\":true,\"upload_mbps\":0,\"download_mbps\":200}' | socat - $SOCK")
assert_match "$result" '"ok":false' "rejects upload_mbps=0"

result=$(vm_exec router "echo '{\"method\":\"set_qos_config\",\"enabled\":true,\"upload_mbps\":50,\"download_mbps\":2000000}' | socat - $SOCK")
assert_match "$result" '"ok":false' "rejects download_mbps=2000000"

# --- Cleanup: disable QoS for subsequent tests ---
vm_exec router "echo '{\"method\":\"set_qos_config\",\"enabled\":false}' | socat - $SOCK" >/dev/null
