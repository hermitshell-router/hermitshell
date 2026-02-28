#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Record current device state
before=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$before" '"ok":true' "list_devices before restart"

# Stop the agent
deploy_stop_agent

# Verify it's dead
wait_for 5 "Agent process stopped" deploy_agent_dead

# Restart agent
deploy_start_agent

# Wait for socket to come back
socket_ready() {
    vm_sudo router "chmod 666 /run/hermitshell/agent.sock"
    vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -q '"ok":true'
}
wait_for 15 "Agent socket ready after restart" socket_ready

# Verify device state is preserved
after=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$after" '"ok":true' "list_devices after restart"
assert_match "$after" '10\.0\.' "Device IP preserved after restart"

# Verify LAN client can still reach WAN (nftables rules restored)
assert_success "LAN can reach WAN after restart" vm_exec lan "ping -c1 -W3 192.168.100.2"

# Verify DNS is running again
wait_for 10 "DNS restarted" deploy_check_dns_running

dns_ok() {
    deploy_check_dns_running
}
assert_success "DNS process running after restart" dns_ok

# Verify DHCP process is running
wait_for 10 "DHCP process running after restart" deploy_check_dhcp_running

# Verify DNS resolution works through unbound
dns_works() {
    vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 example.com" | grep -q '[0-9]'
}
wait_for 10 "DNS resolution works after restart" dns_works

dns=$(vm_exec router "dig +short @10.0.0.1 example.com" || echo "")
assert_match "$dns" "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "Unbound resolves DNS after restart"
