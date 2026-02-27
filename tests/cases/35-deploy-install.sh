#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

if [ "${HERMIT_MODE:-direct}" != "install" ]; then
    echo "SKIP: install-only test (mode=$HERMIT_MODE)"
    exit 0
fi

require_agent

# hermitshell-agent systemd service is active
agent_status=$(vm_sudo router "systemctl is-active hermitshell-agent" 2>/dev/null)
assert_match "$agent_status" "active" "hermitshell-agent service active"

# hermitshell-ui systemd service is active
ui_status=$(vm_sudo router "systemctl is-active hermitshell-ui" 2>/dev/null)
assert_match "$ui_status" "active" "hermitshell-ui service active"

# WAN/LAN env vars in agent service
unit_env=$(vm_sudo router "systemctl show hermitshell-agent --property=Environment" 2>/dev/null)
assert_contains "$unit_env" "WAN_IFACE=eth1" "Agent service has WAN_IFACE=eth1"
assert_contains "$unit_env" "LAN_IFACE=eth2" "Agent service has LAN_IFACE=eth2"

# hermitshell user exists (created by install.sh)
user_check=$(vm_exec router "id hermitshell 2>&1")
assert_contains "$user_check" "hermitshell" "hermitshell user exists"

# Binaries at expected path
assert_success "Agent binary at /opt/hermitshell/" \
    vm_exec router "test -x /opt/hermitshell/hermitshell-agent"
assert_success "DHCP binary at /opt/hermitshell/" \
    vm_exec router "test -x /opt/hermitshell/hermitshell-dhcp"
assert_success "Web UI binary at /opt/hermitshell/" \
    vm_exec router "test -x /opt/hermitshell/hermitshell"
assert_success "Blocky binary at /opt/hermitshell/" \
    vm_exec router "test -x /opt/hermitshell/blocky"

# Data directories exist
assert_success "Data directory exists" \
    vm_exec router "test -d /var/lib/hermitshell"
assert_success "Blocky data directory exists" \
    vm_exec router "test -d /var/lib/hermitshell/blocky"

# Web UI responds (running as native systemd service, not Docker)
# Use port 8443 directly — nftables 443->8443 redirect only applies to LAN-sourced traffic
response=$(vm_exec router "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/" 2>/dev/null)
assert_match "$response" "200|30[0-9]" "Web UI responds via native service"
