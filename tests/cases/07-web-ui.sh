#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_docker

# Check if container is running
assert_success "Web UI container running" \
    vm_exec router "docker ps | grep -q hermitshell"

# HTTPS should respond (may redirect to /setup or /login since no password set yet)
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' https://localhost/")
assert_match "$response" "200|30[0-9]" "HTTPS responds"

# HTTP should redirect to HTTPS
response=$(vm_exec router "curl -s -o /dev/null -w '%{http_code}' http://localhost/" 2>/dev/null || echo "000")
assert_match "$response" "30[0-9]|000" "HTTP redirects or refused"

# Setup: set password first
vm_exec router "curl -s -k -X POST -d 'password=testpass123&confirm=testpass123' https://localhost/api/setup" >/dev/null 2>&1

# Login to get session cookie
vm_exec router "curl -s -k -c /tmp/cookies -X POST -d 'password=testpass123' https://localhost/api/login" >/dev/null 2>&1

# Check pages with session cookie
response=$(vm_exec router "curl -s -k -b /tmp/cookies https://localhost/")
assert_match "$response" "HermitShell" "Dashboard responds with content"
assert_match "$response" "Dashboard" "Dashboard page renders"

response=$(vm_exec router "curl -s -k -b /tmp/cookies https://localhost/devices")
assert_match "$response" "Devices" "Devices page responds"

response=$(vm_exec router "curl -s -k -b /tmp/cookies https://localhost/groups")
assert_match "$response" "Groups" "Groups page responds"

response=$(vm_exec router "curl -s -k -b /tmp/cookies https://localhost/traffic")
assert_match "$response" "Traffic" "Traffic page responds"

response=$(vm_exec router "curl -s -k -b /tmp/cookies https://localhost/dns")
assert_match "$response" "Ad Blocking" "DNS page responds"

response=$(vm_exec router "curl -s -k -b /tmp/cookies https://localhost/settings")
assert_match "$response" "Settings" "Settings page responds"

response=$(vm_exec router "curl -s -k -b /tmp/cookies https://localhost/wireguard")
assert_match "$response" "WireGuard" "WireGuard page responds"

response=$(vm_exec router "curl -s -k -b /tmp/cookies https://localhost/port-forwarding")
assert_match "$response" "Port Forwarding" "Port Forwarding page responds"

# Check CSS is served (exempt from auth)
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' https://localhost/style.css")
assert_match "$response" "200" "CSS file served"
