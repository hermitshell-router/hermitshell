#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip

# Get LAN device MAC and current IP
lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")
assert_match "$lan_mac" "^[0-9a-f]" "LAN MAC is valid"

# Remove any existing reservation (idempotency)
vm_exec router "echo '{\"method\":\"remove_dhcp_reservation\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null 2>&1

original_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$original_ip" "^10\." "LAN has current IP"

# Get current subnet_id from device record
device_info=$(vm_exec router "echo '{\"method\":\"get_device\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_contains "$device_info" '"subnet_id":' "Device has a subnet_id"

# Set reservation for current subnet
result=$(vm_exec router "echo '{\"method\":\"set_dhcp_reservation\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "set_dhcp_reservation succeeds"

# Verify reservation appears in list with correct MAC and subnet
result=$(vm_exec router 'echo "{\"method\":\"list_dhcp_reservations\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_dhcp_reservations succeeds"
assert_contains "$result" "$lan_mac" "reservation contains LAN MAC"
assert_contains "$result" '"subnet_id":' "reservation includes subnet_id"

# Force DHCP renewal and verify same IP is assigned (reservation works)
vm_exec lan "sudo pkill -f 'dhclient.*eth1' 2>/dev/null; sudo ip addr flush dev eth1 2>/dev/null; sudo dhclient eth1 2>/dev/null" || true

dhcp_done() {
    vm_exec lan "ip -4 addr show eth1" | grep -q '10\.0\.'
}
wait_for 30 "DHCP lease reacquired" dhcp_done

renewed_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
assert_match "$renewed_ip" "^10\." "Got IP after renewal"
assert_match "$renewed_ip" "$original_ip" "Reserved IP matches original after DHCP renewal"

# Verify reservation appears in export_config
# Note: export_config embeds config as a JSON string, so inner keys are backslash-escaped
export=$(vm_exec router 'echo "{\"method\":\"export_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$export" 'dhcp_reservations' "export includes dhcp_reservations"
assert_contains "$export" "$lan_mac" "export reservation has correct MAC"

# Remove reservation
result=$(vm_exec router "echo '{\"method\":\"remove_dhcp_reservation\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$result" '"ok":true' "remove_dhcp_reservation succeeds"

# Verify reservation is gone from list
result=$(vm_exec router 'echo "{\"method\":\"list_dhcp_reservations\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
if echo "$result" | grep -qF "$lan_mac"; then
    echo -e "${RED}FAIL${NC}: Reservation still present after removal"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: Reservation removed from list"
fi
