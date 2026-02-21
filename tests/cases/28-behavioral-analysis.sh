#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_wan
require_lan_ip
require_blocky

# Verify analyzer status defaults
result=$(vm_exec router 'echo "{\"method\":\"get_analyzer_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "get_analyzer_status succeeds"
assert_match "$result" '"enabled":"true"' "analyzer enabled by default"

# Get LAN device IP and MAC
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")
device_mac=$(vm_exec lan "ip link show eth1 | grep ether | awk '{print \$2}'")

# Clear any existing alerts
vm_exec router 'echo "{\"method\":\"acknowledge_all_alerts\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' > /dev/null

# Generate suspicious port connections (port 23 = telnet, a suspicious port)
# Must target non-router IP (10.0.0.1 is filtered from conntrack logs)
vm_exec lan "curl -s --connect-timeout 2 telnet://192.168.100.2:23 2>/dev/null" || true

# Wait for conntrack to log the port 23 connection
port23_logged() {
    vm_exec router "echo '{\"method\":\"list_connection_logs\",\"internal_ip\":\"$device_ip\",\"limit\":50}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" | grep -q '"dest_port":23'
}
wait_for 15 "Port 23 connection logged" port23_logged

result=$(vm_exec router "echo '{\"method\":\"list_connection_logs\",\"internal_ip\":\"$device_ip\",\"limit\":50}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_contains "$result" '"dest_port":23' "Port 23 connection logged in database"

# Trigger immediate analysis instead of waiting for 60s cycle
vm_exec router 'echo "{\"method\":\"run_analysis\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' > /dev/null
alert_fired() {
    vm_exec router 'echo "{\"method\":\"list_alerts\",\"limit\":50}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -q '"suspicious_ports"'
}
wait_for 10 "Suspicious ports alert fired" alert_fired

# Verify the alert has correct fields
alerts=$(vm_exec router 'echo "{\"method\":\"list_alerts\",\"limit\":50}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$alerts" '"ok":true' "list_alerts succeeds"
assert_contains "$alerts" '"rule":"suspicious_ports"' "Alert has correct rule name"
assert_contains "$alerts" '"severity":"medium"' "Alert has correct severity"
assert_contains "$alerts" '"device_mac"' "Alert has device_mac field"
assert_contains "$alerts" '"message"' "Alert has message field"

# Verify alert details contain port 23 (details is JSON-in-JSON, so quotes may be escaped)
assert_match "$alerts" 'port.*:.*23' "Alert details reference port 23"

# Test acknowledge_all_alerts
result=$(vm_exec router 'echo "{\"method\":\"acknowledge_all_alerts\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "acknowledge_all_alerts succeeds"

# Verify alerts are acknowledged
alerts_after=$(vm_exec router 'echo "{\"method\":\"list_alerts\",\"limit\":50}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$alerts_after" '"acknowledged":true' "Alerts marked as acknowledged"

# Test disabling a rule
result=$(vm_exec router 'echo "{\"method\":\"set_config\",\"key\":\"alert_rule_dns_beaconing\",\"value\":\"disabled\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "disable rule succeeds"

# Verify rule disabled in status
result=$(vm_exec router 'echo "{\"method\":\"get_analyzer_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"dns_beaconing":"disabled"' "rule shows as disabled"

# Re-enable the rule
result=$(vm_exec router 'echo "{\"method\":\"set_config\",\"key\":\"alert_rule_dns_beaconing\",\"value\":\"enabled\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "re-enable rule succeeds"

# Test disabling analyzer entirely
result=$(vm_exec router 'echo "{\"method\":\"set_config\",\"key\":\"analyzer_enabled\",\"value\":\"false\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "disable analyzer succeeds"

result=$(vm_exec router 'echo "{\"method\":\"get_analyzer_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"enabled":"false"' "analyzer shows as disabled"

# Re-enable
result=$(vm_exec router 'echo "{\"method\":\"set_config\",\"key\":\"analyzer_enabled\",\"value\":\"true\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "re-enable analyzer succeeds"
