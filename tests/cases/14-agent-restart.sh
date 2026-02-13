#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Record current device state
before=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$before" '"ok":true' "list_devices before restart"

# Kill the agent
vm_exec router "pkill hermitshell-agent" || true
sleep 1

# Verify it's dead
agent_dead() {
    ! vm_exec router "pgrep hermitshell-agent" | grep -q '[0-9]'
}
wait_for 5 "Agent process stopped" agent_dead

# Restart agent
vm_exec router "nohup /opt/hermitshell/hermitshell-agent > /var/log/hermitshell-agent.log 2>&1 &"

# Wait for socket to come back
socket_ready() {
    vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -q '"ok":true'
}
wait_for 15 "Agent socket ready after restart" socket_ready

# Verify device state is preserved
after=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$after" '"ok":true' "list_devices after restart"
assert_match "$after" '10\.0\.' "Device IP preserved after restart"

# Verify LAN client can still reach WAN (nftables rules restored)
assert_success "LAN can reach WAN after restart" vm_exec lan "ping -c1 -W3 192.168.100.1"

# Verify blocky is running again
blocky_running() {
    vm_exec router "pgrep blocky" | grep -q '[0-9]'
}
wait_for 10 "Blocky restarted" blocky_running

blocky_pid=$(vm_exec router "pgrep blocky" || echo "")
assert_match "$blocky_pid" "^[0-9]+" "Blocky process running after restart"

# Verify DNS resolution works through blocky
dns_works() {
    vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 example.com" | grep -q '[0-9]'
}
wait_for 10 "DNS resolution works after restart" dns_works

dns=$(vm_exec router "dig +short @10.0.0.1 example.com" || echo "")
assert_match "$dns" "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "Blocky resolves DNS after restart"
