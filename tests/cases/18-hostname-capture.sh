#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip

lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")
assert_match "$lan_mac" "^[0-9a-f]" "Got LAN MAC address"

# Verify device exists
device=$(vm_exec router "echo '{\"method\":\"get_device\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_match "$device" '"ok":true' "get_device succeeds for LAN device"

# Test hostname capture end-to-end on router VM
# DHCP socket needs sudo, agent socket is world-readable (chmod 666 in run.sh)
# Run as heredoc on router to avoid shell quoting issues
args=$(_vm_ssh_args router)
result=$(ssh $SSH_COMMON $args "sudo bash -s" 2>/dev/null <<EOTEST
DSOCK=/run/hermitshell/dhcp.sock
ASOCK=/run/hermitshell/agent.sock
MAC="$lan_mac"

# Send dhcp_discover with hostname "testhost"
echo "{\"method\":\"dhcp_discover\",\"mac\":\"\$MAC\",\"hostname\":\"testhost\"}" | socat - UNIX-CONNECT:\$DSOCK

# Query device to verify hostname was captured
echo "{\"method\":\"get_device\",\"mac\":\"\$MAC\"}" | socat - UNIX-CONNECT:\$ASOCK

# Test sanitization: send hostname with HTML injection
echo "{\"method\":\"dhcp_discover\",\"mac\":\"\$MAC\",\"hostname\":\"test<script>host\"}" | socat - UNIX-CONNECT:\$DSOCK

# Query device to check sanitized hostname
echo "SANITIZED:"
echo "{\"method\":\"get_device\",\"mac\":\"\$MAC\"}" | socat - UNIX-CONNECT:\$ASOCK

# Restore original hostname
echo "{\"method\":\"dhcp_discover\",\"mac\":\"\$MAC\",\"hostname\":\"lan\"}" | socat - UNIX-CONNECT:\$DSOCK
EOTEST
)

assert_match "$result" '"ok":true' "dhcp_discover with hostname succeeds"
assert_contains "$result" '"hostname":"testhost"' "Hostname 'testhost' captured from DHCP discover"

# Check sanitization result (after the SANITIZED: marker)
sanitized_part=$(echo "$result" | sed -n '/SANITIZED:/,$p')
if echo "$sanitized_part" | grep -qF '<script>'; then
    echo -e "${RED}FAIL${NC}: Hostname contains unsanitized HTML"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: Hostname sanitized (no HTML injection)"
fi

# Verify hostname is back to "lan" after restore
device=$(vm_exec router "echo '{\"method\":\"get_device\",\"mac\":\"$lan_mac\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_contains "$device" '"hostname":"lan"' "Hostname restored to original value"
