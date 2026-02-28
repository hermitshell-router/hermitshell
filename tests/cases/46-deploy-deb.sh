#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

if [ "${HERMIT_MODE:-direct}" != "deb" ]; then
    echo "SKIP: deb-only test (mode=$HERMIT_MODE)"
    exit 0
fi

require_agent

# hermitshell package is installed
pkg_status=$(vm_exec router "dpkg-query -W -f='\${Status}' hermitshell 2>/dev/null" || echo "not-installed")
assert_contains "$pkg_status" "install ok installed" "hermitshell deb package installed"

# hermitshell-agent systemd service is active
agent_status=$(vm_sudo router "systemctl is-active hermitshell-agent" 2>/dev/null)
assert_match "$agent_status" "active" "hermitshell-agent service active"

# hermitshell-ui systemd service is active
ui_status=$(vm_sudo router "systemctl is-active hermitshell-ui" 2>/dev/null)
assert_match "$ui_status" "active" "hermitshell-ui service active"

# Agent reads interfaces from /etc/default/hermitshell (EnvironmentFile)
env_file=$(vm_exec router "cat /etc/default/hermitshell" 2>/dev/null)
assert_contains "$env_file" "WAN_IFACE=eth1" "WAN_IFACE configured in /etc/default/hermitshell"
assert_contains "$env_file" "LAN_IFACE=eth2" "LAN_IFACE configured in /etc/default/hermitshell"

# Binaries at expected path
assert_success "Agent binary at /opt/hermitshell/" \
    vm_exec router "test -x /opt/hermitshell/hermitshell-agent"
assert_success "DHCP binary at /opt/hermitshell/" \
    vm_exec router "test -x /opt/hermitshell/hermitshell-dhcp"
assert_success "Web UI binary at /opt/hermitshell/" \
    vm_exec router "test -x /opt/hermitshell/hermitshell"
assert_success "Unbound config at /opt/hermitshell/" \
    vm_exec router "test -d /opt/hermitshell/unbound"

# Systemd units installed to correct location
assert_success "Agent service unit in /lib/systemd/system/" \
    vm_exec router "test -f /lib/systemd/system/hermitshell-agent.service"
assert_success "UI service unit in /lib/systemd/system/" \
    vm_exec router "test -f /lib/systemd/system/hermitshell-ui.service"

# Agent service uses EnvironmentFile (not hardcoded env vars)
unit_content=$(vm_exec router "cat /lib/systemd/system/hermitshell-agent.service" 2>/dev/null)
assert_contains "$unit_content" "EnvironmentFile=/etc/default/hermitshell" "Agent uses EnvironmentFile"

# /etc/default/hermitshell is a conffile (preserved across upgrades)
conffiles=$(vm_exec router "dpkg-query -W -f='\${Conffiles}' hermitshell 2>/dev/null" || echo "")
assert_contains "$conffiles" "/etc/default/hermitshell" "/etc/default/hermitshell is a conffile"

# Data directories exist
assert_success "Data directory exists" \
    vm_exec router "test -d /var/lib/hermitshell"
assert_success "Unbound data directory exists" \
    vm_exec router "test -d /var/lib/hermitshell/unbound"

# hermitshell user exists
user_check=$(vm_exec router "id hermitshell 2>&1")
assert_contains "$user_check" "hermitshell" "hermitshell user exists"

# Web UI responds
response=$(vm_exec router "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/" 2>/dev/null)
assert_match "$response" "200|30[0-9]" "Web UI responds via native service"
